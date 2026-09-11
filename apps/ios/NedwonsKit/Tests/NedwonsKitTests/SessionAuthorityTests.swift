import CryptoKit
import XCTest

@testable import NedwonsKit

/// A scriptable `URLProtocol`: a handler decides each response, and every request is recorded, so a
/// test can assert both what the client SENT (proof header, rotated bearer) and how many times it
/// talked to a given endpoint — which is the only way to prove single-flight refresh.
final class ScriptedURLProtocol: URLProtocol {
    struct Recorded: Sendable {
        let method: String
        let path: String
        let authorization: String?
        let proof: String?
    }

    private static let lock = NSLock()
    nonisolated(unsafe) private static var _log: [Recorded] = []
    nonisolated(unsafe) private static var _handler: (@Sendable (String, String) -> (Int, Data))?

    static func configure(_ handler: @escaping @Sendable (_ method: String, _ path: String) -> (Int, Data)) {
        lock.lock()
        _log = []
        _handler = handler
        lock.unlock()
    }

    static var log: [Recorded] {
        lock.lock()
        defer { lock.unlock() }
        return _log
    }

    static func requests(to path: String) -> [Recorded] {
        log.filter { $0.path == path }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let method = request.httpMethod ?? "GET"
        let path = request.url?.path ?? ""
        Self.lock.lock()
        Self._log.append(
            Recorded(
                method: method,
                path: path,
                authorization: request.value(forHTTPHeaderField: "Authorization"),
                proof: request.value(forHTTPHeaderField: "X-Nedwons-Proof")))
        let handler = Self._handler
        Self.lock.unlock()

        let (status, body) = handler?(method, path) ?? (200, Data("{}".utf8))
        let response = HTTPURLResponse(
            url: request.url!, statusCode: status, httpVersion: nil,
            headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    static func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [ScriptedURLProtocol.self]
        return URLSession(configuration: config)
    }
}

/// A parsed `X-Nedwons-Proof` header, so a test can verify the signature the device actually sent
/// rather than trusting that a header merely exists.
struct ParsedProofHeader {
    let timestamp: UInt64
    let nonce: Data
    let signature: Data

    init?(_ value: String) {
        var ts: UInt64?
        var nonce: Data?
        var sig: Data?
        for field in value.split(separator: ";") {
            if field == "v1" { continue }
            let parts = field.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { return nil }
            switch parts[0] {
            case "ts": ts = UInt64(parts[1])
            case "nonce": nonce = Hex.decode(String(parts[1]))
            case "sig": sig = Hex.decode(String(parts[1]))
            default: return nil
            }
        }
        guard let ts, let nonce, let sig else { return nil }
        self.timestamp = ts
        self.nonce = nonce
        self.signature = sig
    }
}

private func sessionJSON(access: String, refresh: String) -> Data {
    Data(
        """
        {"account_id":"\(String(repeating: "aa", count: 16))",
         "device_id":"\(String(repeating: "bb", count: 16))",
         "access_token":"\(access)","access_expires_at":9999999999,
         "refresh_token":"\(refresh)","refresh_expires_at":9999999999}
        """.utf8)
}

private let tokenA = String(repeating: "11", count: 32)
private let tokenB = String(repeating: "22", count: 32)
private let refreshA = String(repeating: "33", count: 32)
private let refreshB = String(repeating: "44", count: 32)

private func makeAuthority(
    signer: any DeviceSigner,
    urlSession: URLSession,
    access: String = tokenA,
    refresh: String = refreshA
) -> SessionAuthority {
    SessionAuthority(
        session: NedwonsClient.Session(
            accountID: String(repeating: "aa", count: 16),
            deviceID: String(repeating: "bb", count: 16),
            accessToken: access,
            accessExpiresAt: 9_999_999_999,
            refreshToken: refresh,
            refreshExpiresAt: 9_999_999_999),
        store: SessionStore(store: InMemorySecretStore()),
        signer: signer,
        baseURL: URL(string: "https://relay.example")!,
        urlSession: urlSession)
}

/// A `SecretStore` that keeps blobs in memory, so session persistence is exercised without a real
/// Keychain (which is unavailable to SwiftPM tests).
final class InMemorySecretStore: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]
    private(set) var saveCount = 0

    func save(_ data: Data, account: String, accessible: CFString) throws {
        lock.lock()
        defer { lock.unlock() }
        items[account] = data
        saveCount += 1
    }

    func load(account: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return items[account]
    }

    func delete(account: String) throws {
        lock.lock()
        defer { lock.unlock() }
        items[account] = nil
    }
}

// MARK: - Item 1: proof on every authenticated request

final class RequestProofEnforcementTests: XCTestCase {
    /// The header is not merely present — it VERIFIES, under the enrolled key, over exactly the
    /// method, path and token the request carried. A test that only asserted presence would pass
    /// against a header full of zeroes.
    func testAuthenticatedRequestCarriesAProofThatVerifies() async throws {
        let signer = SoftwareDeviceSigner()
        ScriptedURLProtocol.configure { _, _ in (200, Data("[]".utf8)) }
        let urlSession = ScriptedURLProtocol.session()
        let authority = makeAuthority(signer: signer, urlSession: urlSession)
        let client = NedwonsClient(
            baseURL: URL(string: "https://relay.example")!, session: urlSession,
            authority: authority)

        _ = try await client.listFriends(accessToken: tokenA)

        let recorded = try XCTUnwrap(ScriptedURLProtocol.requests(to: "/v1/friends").first)
        let header = try XCTUnwrap(recorded.proof, "an authenticated request must carry a proof")
        let parsed = try XCTUnwrap(ParsedProofHeader(header))

        let expected = RequestProof(
            method: "GET",
            path: "/v1/friends",
            accessTokenHash: Data(SHA256.hash(data: try XCTUnwrap(Hex.decode(tokenA)))),
            timestamp: parsed.timestamp,
            nonce: parsed.nonce)
        let key = try P256.Signing.PublicKey(x963Representation: signer.publicKeyX963)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: parsed.signature)
        XCTAssertTrue(
            key.isValidSignature(signature, for: expected.canonicalBytes()),
            "the proof must verify over the canonical bytes for THIS method, path and token")
    }

    /// Proof binds the path, so two different endpoints must not produce interchangeable proofs.
    func testProofIsBoundToTheRequestPath() async throws {
        let signer = SoftwareDeviceSigner()
        ScriptedURLProtocol.configure { _, _ in (200, Data("[]".utf8)) }
        let urlSession = ScriptedURLProtocol.session()
        let client = NedwonsClient(
            baseURL: URL(string: "https://relay.example")!, session: urlSession,
            authority: makeAuthority(signer: signer, urlSession: urlSession))

        _ = try await client.listFriends(accessToken: tokenA)
        let header = try XCTUnwrap(ScriptedURLProtocol.requests(to: "/v1/friends").first?.proof)
        let parsed = try XCTUnwrap(ParsedProofHeader(header))

        // The same signature checked against a DIFFERENT path must fail.
        let wrongPath = RequestProof(
            method: "GET",
            path: "/v1/blocks",
            accessTokenHash: Data(SHA256.hash(data: try XCTUnwrap(Hex.decode(tokenA)))),
            timestamp: parsed.timestamp,
            nonce: parsed.nonce)
        let key = try P256.Signing.PublicKey(x963Representation: signer.publicKeyX963)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: parsed.signature)
        XCTAssertFalse(
            key.isValidSignature(signature, for: wrongPath.canonicalBytes()),
            "a proof must not verify for a path the device did not sign")
    }

    /// Nonces are single-use server-side, so two requests must never reuse one.
    func testEachRequestGetsAFreshNonce() async throws {
        let signer = SoftwareDeviceSigner()
        ScriptedURLProtocol.configure { _, _ in (200, Data("[]".utf8)) }
        let urlSession = ScriptedURLProtocol.session()
        let client = NedwonsClient(
            baseURL: URL(string: "https://relay.example")!, session: urlSession,
            authority: makeAuthority(signer: signer, urlSession: urlSession))

        _ = try await client.listFriends(accessToken: tokenA)
        _ = try await client.listFriends(accessToken: tokenA)

        let nonces = ScriptedURLProtocol.requests(to: "/v1/friends")
            .compactMap { $0.proof.flatMap(ParsedProofHeader.init)?.nonce }
        XCTAssertEqual(nonces.count, 2)
        XCTAssertNotEqual(nonces[0], nonces[1], "a replayed nonce is refused by the server")
    }

    /// An unauthenticated call must not carry a proof — there is no token to bind it to.
    func testUnauthenticatedRequestCarriesNoProof() async throws {
        ScriptedURLProtocol.configure { _, _ in
            (200, sessionJSON(access: tokenA, refresh: refreshA))
        }
        let urlSession = ScriptedURLProtocol.session()
        let client = NedwonsClient(
            baseURL: URL(string: "https://relay.example")!, session: urlSession)
        _ = try? await client.login(
            username: "someone", password: "battery staple orbit lantern",
            signer: SoftwareDeviceSigner())

        for recorded in ScriptedURLProtocol.log where recorded.authorization == nil {
            XCTAssertNil(recorded.proof, "\(recorded.path) has no token to bind a proof to")
        }
    }

    /// Without an authority the client must send no proof at all, rather than an unsigned one.
    func testNoAuthorityMeansNoProofHeader() async throws {
        ScriptedURLProtocol.configure { _, _ in (200, Data("[]".utf8)) }
        let urlSession = ScriptedURLProtocol.session()
        let client = NedwonsClient(
            baseURL: URL(string: "https://relay.example")!, session: urlSession)
        _ = try await client.listFriends(accessToken: tokenA)
        XCTAssertNil(ScriptedURLProtocol.requests(to: "/v1/friends").first?.proof)
    }
}

// MARK: - Item 2: single-flight refresh

final class SessionRefreshTests: XCTestCase {
    /// The ordinary expiry path: one 401, one refresh, one replay under the rotated token.
    func testExpiredAccessTokenIsRefreshedAndTheRequestReplayed() async throws {
        let signer = SoftwareDeviceSigner()
        // The first /v1/friends call is refused, the replay succeeds.
        let attempts = Counter()
        ScriptedURLProtocol.configure { _, path in
            if path == "/v1/session/refresh" {
                return (200, sessionJSON(access: tokenB, refresh: refreshB))
            }
            return attempts.next() == 1 ? (401, Data(#"{"error":"denied"}"#.utf8)) : (200, Data("[]".utf8))
        }
        let urlSession = ScriptedURLProtocol.session()
        let authority = makeAuthority(signer: signer, urlSession: urlSession)
        let client = NedwonsClient(
            baseURL: URL(string: "https://relay.example")!, session: urlSession,
            authority: authority)

        _ = try await client.listFriends(accessToken: tokenA)

        XCTAssertEqual(ScriptedURLProtocol.requests(to: "/v1/session/refresh").count, 1)
        let friendCalls = ScriptedURLProtocol.requests(to: "/v1/friends")
        XCTAssertEqual(friendCalls.count, 2, "original + exactly one replay")
        XCTAssertEqual(friendCalls[0].authorization, "Bearer \(tokenA)")
        XCTAssertEqual(friendCalls[1].authorization, "Bearer \(tokenB)", "replay uses the rotation")
        XCTAssertNotEqual(
            friendCalls[0].proof, friendCalls[1].proof,
            "the replay must carry a NEW proof — the old one commits to the old token's hash")
        let adopted = await authority.currentAccessToken()
        XCTAssertEqual(adopted, tokenB)
    }

    /// The property that protects the refresh family: many concurrent 401s must produce exactly ONE
    /// refresh. A second concurrent refresh would present a token the first had already retired,
    /// which the server treats as reuse and answers by revoking every session on the account.
    func testConcurrentRefreshesCollapseToASingleRotation() async throws {
        let signer = SoftwareDeviceSigner()
        let refreshHits = Counter()
        ScriptedURLProtocol.configure { _, path in
            if path == "/v1/session/refresh" {
                _ = refreshHits.next()
                return (200, sessionJSON(access: tokenB, refresh: refreshB))
            }
            // Anything presenting the stale token is refused; the rotated one is accepted.
            return (401, Data(#"{"error":"denied"}"#.utf8))
        }
        let urlSession = ScriptedURLProtocol.session()
        let authority = makeAuthority(signer: signer, urlSession: urlSession)
        let client = NedwonsClient(
            baseURL: URL(string: "https://relay.example")!, session: urlSession,
            authority: authority)

        await withTaskGroup(of: Void.self) { group in
            for _ in 0 ..< 12 {
                group.addTask { _ = try? await client.listFriends(accessToken: tokenA) }
            }
            await group.waitForAll()
        }

        XCTAssertEqual(
            ScriptedURLProtocol.requests(to: "/v1/session/refresh").count, 1,
            "12 concurrent expiries must rotate the refresh token exactly once")
    }

    /// Bounded retry: a request that is still refused after a successful refresh fails rather than
    /// looping, so a genuinely dead session cannot spend refresh tokens indefinitely.
    func testRetryHappensAtMostOnce() async throws {
        let signer = SoftwareDeviceSigner()
        ScriptedURLProtocol.configure { _, path in
            if path == "/v1/session/refresh" {
                return (200, sessionJSON(access: tokenB, refresh: refreshB))
            }
            return (401, Data(#"{"error":"denied"}"#.utf8))
        }
        let urlSession = ScriptedURLProtocol.session()
        let client = NedwonsClient(
            baseURL: URL(string: "https://relay.example")!, session: urlSession,
            authority: makeAuthority(signer: signer, urlSession: urlSession))

        do {
            _ = try await client.listFriends(accessToken: tokenA)
            XCTFail("expected the second refusal to surface")
        } catch NedwonsClient.ClientError.http(let status, _) {
            XCTAssertEqual(status, 401)
        }
        XCTAssertEqual(ScriptedURLProtocol.requests(to: "/v1/friends").count, 2)
        XCTAssertEqual(ScriptedURLProtocol.requests(to: "/v1/session/refresh").count, 1)
    }

    /// A refused refresh is terminal: the stored session is cleared so the next launch asks for a
    /// sign-in instead of replaying a token the server has already retired.
    func testRejectedRefreshClearsTheSession() async throws {
        let signer = SoftwareDeviceSigner()
        ScriptedURLProtocol.configure { _, path in
            path == "/v1/session/refresh"
                ? (401, Data(#"{"error":"denied"}"#.utf8))
                : (401, Data(#"{"error":"denied"}"#.utf8))
        }
        let urlSession = ScriptedURLProtocol.session()
        let authority = makeAuthority(signer: signer, urlSession: urlSession)
        let client = NedwonsClient(
            baseURL: URL(string: "https://relay.example")!, session: urlSession,
            authority: authority)

        _ = try? await client.listFriends(accessToken: tokenA)

        let remaining = await authority.currentSession()
        XCTAssertNil(remaining, "a refused rotation must not leave a session behind")
    }

    /// The rotated session is durable BEFORE it is published, so a relaunch never presents the
    /// retired token.
    func testRotatedSessionIsPersisted() async throws {
        let signer = SoftwareDeviceSigner()
        let backing = InMemorySecretStore()
        ScriptedURLProtocol.configure { _, path in
            path == "/v1/session/refresh"
                ? (200, sessionJSON(access: tokenB, refresh: refreshB))
                : (401, Data(#"{"error":"denied"}"#.utf8))
        }
        let urlSession = ScriptedURLProtocol.session()
        let store = SessionStore(store: backing)
        let authority = SessionAuthority(
            session: NedwonsClient.Session(
                accountID: String(repeating: "aa", count: 16),
                deviceID: String(repeating: "bb", count: 16),
                accessToken: tokenA, accessExpiresAt: 9_999_999_999,
                refreshToken: refreshA, refreshExpiresAt: 9_999_999_999),
            store: store, signer: signer,
            baseURL: URL(string: "https://relay.example")!, urlSession: urlSession)
        let client = NedwonsClient(
            baseURL: URL(string: "https://relay.example")!, session: urlSession,
            authority: authority)

        _ = try? await client.listFriends(accessToken: tokenA)

        let reloaded = try XCTUnwrap(store.load(), "the rotation must be on disk")
        XCTAssertEqual(reloaded.accessToken, tokenB)
        XCTAssertEqual(reloaded.refreshToken, refreshB)
    }
}

/// A tiny thread-safe counter — the scripted handler runs on URLSession's queues.
final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func next() -> Int {
        lock.lock()
        defer { lock.unlock() }
        value += 1
        return value
    }
}
