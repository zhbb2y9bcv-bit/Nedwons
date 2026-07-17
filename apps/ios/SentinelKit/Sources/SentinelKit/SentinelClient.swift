import Foundation

/// HTTP client for the Sentinel auth API (contracts/API.md). This is the exact flow the iOS
/// app performs: it builds and signs the canonical transcripts with a `DeviceSigner` (the
/// Secure Enclave on device) and never sends the private key anywhere. Binary fields are hex,
/// matching the wire contract.
///
/// Networking uses `URLSession` async/await so it runs headlessly (the `SentinelSmoke`
/// executable drives it against a live server) and unchanged inside the app.
public struct SentinelClient: Sendable {
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

    // MARK: Authenticated transport (used by the social/messaging API)

    fileprivate func perform(_ request: URLRequest) async throws -> Data {
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
        return data
    }

    fileprivate func decode<R: Decodable>(_ data: Data) throws -> R {
        do {
            return try JSONDecoder().decode(R.self, from: data)
        } catch {
            throw ClientError.decoding
        }
    }

    fileprivate func authed(_ method: String, _ path: String, accessToken: String) -> URLRequest {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = method
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        return request
    }

    fileprivate func queryURL(_ path: String, _ items: [URLQueryItem]) -> URL {
        var components = URLComponents(
            url: baseURL.appendingPathComponent(path),
            resolvingAgainstBaseURL: false
        )!
        components.queryItems = items
        return components.url!
    }
}

// MARK: - Profiles, friends, groups, and messaging (contracts/API.md)

public struct Profile: Decodable, Sendable {
    public let accountID: String
    public let username: String
    public let displayName: String
    public let bio: String
    enum CodingKeys: String, CodingKey {
        case accountID = "account_id", username, displayName = "display_name", bio
    }
}

public struct ProfileSummary: Decodable, Sendable, Identifiable, Hashable {
    public let accountID: String
    public let username: String
    public let displayName: String
    public var id: String { accountID }
    enum CodingKeys: String, CodingKey {
        case accountID = "account_id", username, displayName = "display_name"
    }
}

/// Result of presenting an invite token: joined outright, or a pending join request
/// (approval-gated groups).
public struct AcceptedInvite: Decodable, Sendable {
    public let conversationID: String
    public let status: String
    enum CodingKeys: String, CodingKey {
        case conversationID = "conversation_id", status
    }
}

public struct GroupCreated: Decodable, Sendable {
    public let conversationID: String
    public let memberAccountIDs: [String]
    enum CodingKeys: String, CodingKey {
        case conversationID = "conversation_id", memberAccountIDs = "member_account_ids"
    }
}

public struct Conversation: Decodable, Sendable, Identifiable {
    public let conversationID: String
    public let memberAccountIDs: [String]
    public var id: String { conversationID }
    enum CodingKeys: String, CodingKey {
        case conversationID = "conversation_id", memberAccountIDs = "member_account_ids"
    }
}

public struct InboxEnvelope: Decodable, Sendable, Identifiable {
    public let id: Int
    public let conversationID: String
    public let senderDevice: String
    public let ciphertext: String
    enum CodingKeys: String, CodingKey {
        case id, conversationID = "conversation_id", senderDevice = "sender_device", ciphertext
    }
}

public extension SentinelClient {
    // ----- profiles -----

    func myProfile(accessToken: String) async throws -> Profile {
        try decode(await perform(authed("GET", "/v1/profile", accessToken: accessToken)))
    }

    func profile(accessToken: String, accountID: String) async throws -> Profile {
        try decode(await perform(authed("GET", "/v1/profile/\(accountID)", accessToken: accessToken)))
    }

    func updateProfile(accessToken: String, displayName: String, bio: String) async throws {
        struct Body: Encodable { let display_name: String; let bio: String }
        var request = authed("PUT", "/v1/profile", accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(Body(display_name: displayName, bio: bio))
        _ = try await perform(request)
    }

    func searchProfiles(accessToken: String, query: String) async throws -> [ProfileSummary] {
        var request = URLRequest(url: queryURL("/v1/profiles/search", [URLQueryItem(name: "q", value: query)]))
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        return try decode(await perform(request))
    }

    // ----- friends -----

    func listFriends(accessToken: String) async throws -> [ProfileSummary] {
        try decode(await perform(authed("GET", "/v1/friends", accessToken: accessToken)))
    }

    func friendRequests(accessToken: String) async throws -> [ProfileSummary] {
        try decode(await perform(authed("GET", "/v1/friends/requests", accessToken: accessToken)))
    }

    /// Returns the resulting status: "requested", "friended", or "already_friends".
    @discardableResult
    func sendFriendRequest(accessToken: String, accountID: String) async throws -> String {
        struct Res: Decodable { let status: String }
        let res: Res = try await postAccountRef("/v1/friends/request", accessToken, accountID)
        return res.status
    }

    func acceptFriend(accessToken: String, accountID: String) async throws {
        try await postAccountRefVoid("/v1/friends/accept", accessToken, accountID)
    }

    func declineFriend(accessToken: String, accountID: String) async throws {
        try await postAccountRefVoid("/v1/friends/decline", accessToken, accountID)
    }

    func removeFriend(accessToken: String, accountID: String) async throws {
        try await postAccountRefVoid("/v1/friends/remove", accessToken, accountID)
    }

    // ----- blocking & reporting -----

    /// Block an account: severs any friendship and refuses future requests (server enforces).
    func blockUser(accessToken: String, accountID: String) async throws {
        try await postAccountRefVoid("/v1/blocks", accessToken, accountID)
    }

    /// Remove a block (does not restore prior friendship).
    func unblock(accessToken: String, accountID: String) async throws {
        try await postAccountRefVoid("/v1/blocks/remove", accessToken, accountID)
    }

    /// Accounts this user has blocked.
    func listBlocked(accessToken: String) async throws -> [ProfileSummary] {
        try decode(await perform(authed("GET", "/v1/blocks", accessToken: accessToken)))
    }

    /// File an abuse report. `evidence` is only what the user chooses to include — the server
    /// cannot read E2EE content. Returns the server-assigned report id.
    @discardableResult
    func reportUser(
        accessToken: String,
        accountID: String,
        reason: String,
        evidence: String? = nil
    ) async throws -> Int {
        struct Body: Encodable {
            let account_id: String
            let reason: String
            let evidence: String?
        }
        struct Res: Decodable { let report_id: Int }
        var request = authed("POST", "/v1/reports", accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(
            Body(account_id: accountID, reason: reason, evidence: evidence)
        )
        let res: Res = try decode(await perform(request))
        return res.report_id
    }

    // ----- groups & messaging -----

    /// The conversations this device belongs to (for the Chats list).
    func listConversations(accessToken: String) async throws -> [Conversation] {
        try decode(await perform(authed("GET", "/v1/conversations", accessToken: accessToken)))
    }

    /// Create a group; the server rejects with 403 unless all members are mutual friends.
    func createGroup(accessToken: String, memberAccountIDs: [String]) async throws -> GroupCreated {
        struct Body: Encodable { let member_account_ids: [String] }
        var request = authed("POST", "/v1/groups", accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(Body(member_account_ids: memberAccountIDs))
        return try decode(await perform(request))
    }

    /// Leave a conversation (consent withdrawal, ADR-0009). Removes all of this account's devices
    /// from routing and purges queued undelivered envelopes for it. Idempotent on the server.
    func leaveConversation(accessToken: String, conversationID: String) async throws {
        let request = authed(
            "POST", "/v1/conversations/\(conversationID)/leave", accessToken: accessToken
        )
        _ = try await perform(request)
    }

    /// Mint an invite-link token for a conversation (admin only). Strangers join with the token —
    /// their own consent — instead of being force-added. Returns the token (hex).
    func createInvite(
        accessToken: String,
        conversationID: String,
        maxUses: Int? = nil,
        expiresInSecs: Int? = nil
    ) async throws -> String {
        struct Body: Encodable {
            let max_uses: Int?
            let expires_in_secs: Int?
        }
        struct Res: Decodable { let invite_token: String }
        var request = authed(
            "POST", "/v1/conversations/\(conversationID)/invites", accessToken: accessToken
        )
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(
            Body(max_uses: maxUses, expires_in_secs: expiresInSecs)
        )
        let res: Res = try decode(await perform(request))
        return res.invite_token
    }

    /// Join (or request to join, for approval-gated groups) a conversation with an invite token.
    func acceptInvite(accessToken: String, inviteToken: String) async throws -> AcceptedInvite {
        struct Body: Encodable { let invite_token: String }
        var request = authed("POST", "/v1/invites/accept", accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(Body(invite_token: inviteToken))
        return try decode(await perform(request))
    }

    /// Send one MLS application ciphertext; the server fans it out to every other member.
    /// Returns the number of recipient devices it was delivered to.
    @discardableResult
    func sendMessage(
        accessToken: String,
        conversationID: String,
        ciphertext: Data,
        idempotencyKey: Data
    ) async throws -> Int {
        struct Body: Encodable { let ciphertext: String; let idempotency_key: String }
        struct Receipt: Decodable { let delivered: Int }
        var request = authed("POST", "/v1/conversations/\(conversationID)/messages", accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(
            Body(ciphertext: Hex.encode(ciphertext), idempotency_key: Hex.encode(idempotencyKey))
        )
        let receipt: Receipt = try decode(await perform(request))
        return receipt.delivered
    }

    /// Peek the inbox (optionally long-polling for up to `waitSeconds`). Non-destructive;
    /// call `ackInbox` after persisting.
    func fetchInbox(accessToken: String, waitSeconds: Int = 0) async throws -> [InboxEnvelope] {
        let items = waitSeconds > 0 ? [URLQueryItem(name: "wait", value: String(waitSeconds))] : []
        var request = URLRequest(url: queryURL("/v1/inbox", items))
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        return try decode(await perform(request))
    }

    func ackInbox(accessToken: String, ids: [Int]) async throws {
        struct Body: Encodable { let ids: [Int] }
        var request = authed("POST", "/v1/inbox/ack", accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(Body(ids: ids))
        _ = try await perform(request)
    }

    // ----- internals -----

    private func postAccountRef<R: Decodable>(
        _ path: String,
        _ accessToken: String,
        _ accountID: String
    ) async throws -> R {
        var request = authed("POST", path, accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(AccountRefBody(account_id: accountID))
        return try decode(await perform(request))
    }

    private func postAccountRefVoid(
        _ path: String,
        _ accessToken: String,
        _ accountID: String
    ) async throws {
        var request = authed("POST", path, accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(AccountRefBody(account_id: accountID))
        _ = try await perform(request)
    }
}

private struct AccountRefBody: Encodable {
    let account_id: String
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
