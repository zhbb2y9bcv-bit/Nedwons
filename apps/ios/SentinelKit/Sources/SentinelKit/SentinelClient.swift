import Foundation

/// HTTP client for the Sentinel auth API (contracts/API.md). This is the exact flow the iOS
/// app performs: it builds and signs the canonical transcripts with a `DeviceSigner` (the
/// Secure Enclave on device) and never sends the private key anywhere. Binary fields are hex,
/// matching the wire contract.
///
/// Networking uses `URLSession` async/await so it runs headlessly (the `SentinelSmoke`
/// executable drives it against a live server) and unchanged inside the app.
public struct SentinelClient {
    public enum ClientError: Error {
        case http(status: Int, body: String)
        case decoding
        case transport(String)
    }

    public struct Session: Sendable, Equatable {
        public let accountID: String
        public let deviceID: String
        public let accessToken: String
        public let accessExpiresAt: UInt64
        public let refreshToken: String
        public let refreshExpiresAt: UInt64
    }

    private let baseURL: URL
    private let session: URLSession

    public init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
    }

    // MARK: Public flows

    /// Enroll this device and create the account.
    public func register(
        username: String,
        password: String,
        signer: DeviceSigner
    ) async throws -> Session {
        let challenge: ChallengeResponse = try await post("/v1/register/begin", body: EmptyBody())
        let transcript = ClientTranscripts.register(
            accountID: try hex(challenge.account_id),
            deviceID: try hex(challenge.device_id),
            publicKey: signer.publicKeyX963,
            challengeNonce: try hex(challenge.nonce),
            expiresAt: challenge.expires_at,
            txnID: try hex(challenge.txn_id)
        )
        let signature = try signer.sign(transcript)
        let body = RegisterFinishBody(
            username: username,
            password: password,
            device_public_key: Hex.encode(signer.publicKeyX963),
            txn_id: challenge.txn_id,
            signature: Hex.encode(signature)
        )
        let session: SessionResponse = try await post("/v1/register/finish", body: body)
        return session.model
    }

    /// Log in from the enrolled device (two-stage, device-bound).
    public func login(
        username: String,
        password: String,
        signer: DeviceSigner
    ) async throws -> Session {
        let challenge: ChallengeResponse = try await post(
            "/v1/login/begin",
            body: LoginBeginBody(username: username, password: password)
        )
        let transcript = ClientTranscripts.login(
            accountID: try hex(challenge.account_id),
            deviceID: try hex(challenge.device_id),
            publicKey: signer.publicKeyX963,
            challengeNonce: try hex(challenge.nonce),
            expiresAt: challenge.expires_at,
            txnID: try hex(challenge.txn_id)
        )
        let signature = try signer.sign(transcript)
        let session: SessionResponse = try await post(
            "/v1/login/finish",
            body: LoginFinishBody(txn_id: challenge.txn_id, signature: Hex.encode(signature))
        )
        return session.model
    }

    /// Validate the current access token and return the bound identity.
    public func whoami(accessToken: String) async throws -> (accountID: String, deviceID: String) {
        let who: WhoamiResponse = try await get("/v1/session/whoami", bearer: accessToken)
        return (who.account_id, who.device_id)
    }

    // MARK: Transport

    private func post<B: Encodable, R: Decodable>(_ path: String, body: B) async throws -> R {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)
        return try await send(request)
    }

    private func get<R: Decodable>(_ path: String, bearer: String) async throws -> R {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "GET"
        request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")
        return try await send(request)
    }

    private func send<R: Decodable>(_ request: URLRequest) async throws -> R {
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw ClientError.transport(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else { throw ClientError.decoding }
        guard (200 ..< 300).contains(http.statusCode) else {
            throw ClientError.http(status: http.statusCode, body: String(decoding: data, as: UTF8.self))
        }
        do {
            return try JSONDecoder().decode(R.self, from: data)
        } catch {
            throw ClientError.decoding
        }
    }

    private func hex(_ string: String) throws -> Data {
        guard let data = Hex.decode(string) else { throw ClientError.decoding }
        return data
    }
}

// MARK: - Wire DTOs (match contracts/API.md)

private struct EmptyBody: Encodable {}

private struct ChallengeResponse: Decodable {
    let account_id: String
    let device_id: String
    let txn_id: String
    let nonce: String
    let expires_at: UInt64
}

private struct RegisterFinishBody: Encodable {
    let username: String
    let password: String
    let device_public_key: String
    let txn_id: String
    let signature: String
}

private struct LoginBeginBody: Encodable {
    let username: String
    let password: String
}

private struct LoginFinishBody: Encodable {
    let txn_id: String
    let signature: String
}

private struct WhoamiResponse: Decodable {
    let account_id: String
    let device_id: String
}

private struct SessionResponse: Decodable {
    let account_id: String
    let device_id: String
    let access_token: String
    let access_expires_at: UInt64
    let refresh_token: String
    let refresh_expires_at: UInt64

    var model: SentinelClient.Session {
        SentinelClient.Session(
            accountID: account_id,
            deviceID: device_id,
            accessToken: access_token,
            accessExpiresAt: access_expires_at,
            refreshToken: refresh_token,
            refreshExpiresAt: refresh_expires_at
        )
    }
}
