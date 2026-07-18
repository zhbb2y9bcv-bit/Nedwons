import CryptoKit
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
        /// A cryptographic check failed (e.g. a transparency STH signature, a pinned log-key
        /// mismatch, or an inclusion proof) — fail closed, never treat as "nothing found".
        case verificationFailed
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

/// A signed tree head from the transparency log (R-201).
public struct SignedTreeHead: Decodable, Sendable {
    public let treeSize: UInt64
    public let rootHash: String
    public let timestamp: UInt64
    public let signature: String
    public let logPublicKey: String
    enum CodingKeys: String, CodingKey {
        case treeSize = "tree_size", rootHash = "root_hash", timestamp
        case signature, logPublicKey = "log_public_key"
    }
}

/// One logged transparency leaf with its inclusion proof. Usually an account→device-key **binding**;
/// since ADR-0013 it may instead be a **revocation** of `deviceID` (`revokedAt != nil`), so the full
/// device lifecycle — additions and removals — is auditable under the signed root.
public struct TransparencyBinding: Decodable, Sendable {
    public let leafIndex: UInt64
    public let deviceID: String
    public let publicKey: String
    public let entry: String
    public let proof: [String]
    /// Unix seconds if this leaf is a **revocation** of `deviceID`; `nil` for a binding (ADR-0013).
    public let revokedAt: UInt64?
    enum CodingKeys: String, CodingKey {
        case leafIndex = "leaf_index", deviceID = "device_id"
        case publicKey = "public_key", entry, proof
        case revokedAt = "revoked_at"
    }
}

/// A verified device revocation found in the transparency log (ADR-0013).
public struct LoggedRevocation: Sendable, Equatable {
    public let deviceID: String
    public let revokedAt: UInt64
    public let leafIndex: UInt64
}

public struct TransparencyAccountView: Decodable, Sendable {
    public let treeSize: UInt64
    public let bindings: [TransparencyBinding]
    enum CodingKeys: String, CodingKey {
        case treeSize = "tree_size", bindings
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

    // ----- key transparency (R-201) -----

    /// The log's current signed tree head.
    func transparencySignedTreeHead(accessToken: String) async throws -> SignedTreeHead {
        try decode(await perform(authed("GET", "/v1/transparency/sth", accessToken: accessToken)))
    }

    /// This account's logged bindings + inclusion proofs, pinned to `treeSize` so they verify
    /// against the signed root at that size.
    func transparencyAccount(
        accessToken: String,
        accountID: String,
        treeSize: UInt64
    ) async throws -> TransparencyAccountView {
        var request = URLRequest(
            url: queryURL(
                "/v1/transparency/account/\(accountID)",
                [URLQueryItem(name: "tree_size", value: String(treeSize))]
            )
        )
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        return try decode(await perform(request))
    }

    /// Self-monitor key transparency: verify the STH signature under the **pinned** log public key,
    /// that this device's enrolled key is the one logged (no substitution), and that it is included
    /// under the signed root. The client trusts nothing the server says here — it checks.
    func selfMonitorKeyTransparency(
        accessToken: String,
        accountID: String,
        deviceID: String,
        expectedPublicKeyX963: Data,
        pinnedLogPublicKeyX963: Data
    ) async throws -> SelfMonitorResult {
        let sth = try await transparencySignedTreeHead(accessToken: accessToken)
        guard let root = Hex.decode(sth.rootHash),
            let sig = Hex.decode(sth.signature),
            let advertised = Hex.decode(sth.logPublicKey)
        else { return .badSignature }

        // The log must not silently change its key from the pinned one.
        if advertised != pinnedLogPublicKeyX963 { return .logKeyChanged }
        guard Transparency.verifySTHSignature(
            treeSize: sth.treeSize, root: root, timestamp: sth.timestamp,
            signature: sig, logPublicKeyX963: pinnedLogPublicKeyX963
        ) else { return .badSignature }

        let view = try await transparencyAccount(
            accessToken: accessToken, accountID: accountID, treeSize: sth.treeSize
        )
        guard let mine = view.bindings.first(where: { $0.deviceID == deviceID }) else {
            return .notIncluded
        }
        guard Hex.decode(mine.publicKey) == expectedPublicKeyX963 else { return .keyMismatch }
        guard let entry = Hex.decode(mine.entry) else { return .badProof }
        let proof = mine.proof.compactMap { Hex.decode($0) }
        guard proof.count == mine.proof.count else { return .badProof }
        let included = Transparency.verifyInclusion(
            leaf: Transparency.hashLeaf(entry),
            index: Int(mine.leafIndex),
            treeSize: Int(sth.treeSize),
            proof: proof,
            root: root
        )
        return included ? .ok : .badProof
    }

    /// Extract the revocation leaves from an account view (pure — no proof verification). The
    /// verified counterpart is `monitorDeviceRevocations`.
    static func revocationLeaves(in view: TransparencyAccountView) -> [LoggedRevocation] {
        view.bindings.compactMap { b in
            b.revokedAt.map {
                LoggedRevocation(deviceID: b.deviceID, revokedAt: $0, leafIndex: b.leafIndex)
            }
        }
    }

    /// Monitor the account's transparency log for device **revocations**, each proven included under
    /// the STH signed by the PINNED log key (ADR-0013 Slice 3, R-201). The app compares the returned
    /// list against revocations it initiated; anything extra is a device removed **without the
    /// user's action** — raise the same identity-change alarm as a substituted key. (A *revoked*
    /// device's own token is dead, so this runs from another live device of the account.) Throws
    /// `badSignature` on a swapped log key, bad STH signature, or an unverifiable inclusion proof —
    /// fail closed, never silently report "no revocations."
    public func monitorDeviceRevocations(
        accessToken: String,
        accountID: String,
        pinnedLogPublicKeyX963: Data
    ) async throws -> [LoggedRevocation] {
        let sth = try await transparencySignedTreeHead(accessToken: accessToken)
        guard let root = Hex.decode(sth.rootHash), let sig = Hex.decode(sth.signature),
            let advertised = Hex.decode(sth.logPublicKey)
        else { throw ClientError.decoding }
        guard advertised == pinnedLogPublicKeyX963 else { throw ClientError.verificationFailed }
        guard Transparency.verifySTHSignature(
            treeSize: sth.treeSize, root: root, timestamp: sth.timestamp,
            signature: sig, logPublicKeyX963: pinnedLogPublicKeyX963)
        else { throw ClientError.verificationFailed }

        let view = try await transparencyAccount(
            accessToken: accessToken, accountID: accountID, treeSize: sth.treeSize)
        var verified: [LoggedRevocation] = []
        for b in view.bindings {
            guard let revokedAt = b.revokedAt else { continue }
            guard let entry = Hex.decode(b.entry) else { throw ClientError.decoding }
            let proof = b.proof.compactMap { Hex.decode($0) }
            guard proof.count == b.proof.count,
                Transparency.verifyInclusion(
                    leaf: Transparency.hashLeaf(entry), index: Int(b.leafIndex),
                    treeSize: Int(sth.treeSize), proof: proof, root: root)
            else { throw ClientError.verificationFailed }
            verified.append(
                LoggedRevocation(deviceID: b.deviceID, revokedAt: revokedAt, leafIndex: b.leafIndex))
        }
        return verified
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

// MARK: - MLS-commit-authoritative membership (ADR-0010, R-506)

/// A membership change to commit: the opaque MLS commit (from `mls-ffi` stage_add/stage_remove),
/// the delta it encodes, the epoch it was built against, and the welcomes for added devices.
public struct MembershipChange: Sendable {
    public let control: MembershipControl
    public let prevEpoch: UInt64
    /// (account, device) 16-byte ids, sorted + duplicate-free; empty unless `.add`.
    public let added: [(account: Data, device: Data)]
    /// device 16-byte ids, sorted + duplicate-free; empty unless `.remove`/`.leave`.
    public let removed: [Data]
    public let commit: Data
    public let welcomes: [Data]

    public init(
        control: MembershipControl,
        prevEpoch: UInt64,
        added: [(account: Data, device: Data)],
        removed: [Data],
        commit: Data,
        welcomes: [Data]
    ) {
        self.control = control
        self.prevEpoch = prevEpoch
        self.added = added
        self.removed = removed
        self.commit = commit
        self.welcomes = welcomes
    }
}

/// The interpreted outcome of a `/commit` POST, so the caller knows whether to merge or discard its
/// staged MLS commit.
public enum MembershipCommitOutcome: Sendable, Equatable {
    /// The server's epoch CAS won — the caller must now `mergeStaged()` its local commit.
    case applied(nextEpoch: UInt64)
    /// An idempotent retry of an already-applied commit (also merge / treat as success).
    case alreadyApplied(nextEpoch: UInt64)
    /// A concurrent commit won (`409 stale_epoch`) — the caller must `clearStaged()`, refetch the
    /// epoch, and rebuild.
    case staleEpoch
    /// The idempotency key was reused with a different manifest (`409`).
    case idempotencyConflict
    /// Governance/authz refused the change (`403`).
    case forbidden
}

/// A stored membership event fetched for a recipient's correspondence check.
public struct MembershipEventMember: Decodable, Sendable {
    public let accountID: String
    public let deviceID: String
    enum CodingKeys: String, CodingKey {
        case accountID = "account_id"
        case deviceID = "device_id"
    }
}

public struct MembershipEvent: Decodable, Sendable {
    public let controlType: UInt8
    public let prevEpoch: UInt64
    public let nextEpoch: UInt64
    public let commitHash: String
    public let actorDevice: String
    /// The actor's account — where its device key is logged in the transparency log.
    public let actorAccount: String
    public let added: [MembershipEventMember]
    public let removed: [String]
    public let idempotencyKey: String
    public let expiresAt: UInt64
    /// Canonical manifest bytes (hex) + the actor's device signature (hex).
    public let manifest: String
    public let signature: String

    enum CodingKeys: String, CodingKey {
        case controlType = "control_type"
        case prevEpoch = "prev_epoch"
        case nextEpoch = "next_epoch"
        case commitHash = "commit_hash"
        case actorDevice = "actor_device"
        case actorAccount = "actor_account"
        case added, removed
        case idempotencyKey = "idempotency_key"
        case expiresAt = "expires_at"
        case manifest, signature
    }

    /// The added devices' credential identities — exactly what `MlsClient.processCommit(added:)`
    /// compares the staged commit against.
    public var addedDeviceIDs: [Data] { added.compactMap { Hex.decode($0.deviceID) } }
    public var removedDeviceIDs: [Data] { removed.compactMap { Hex.decode($0) } }

    /// Verify the manifest's ECDSA-P256 device signature over the exact stored manifest bytes,
    /// under `deviceKeyX963` — which the caller MUST obtain from the transparency log, not from the
    /// server's assertion for this event (see `verifyIncomingMembershipEvent`).
    public func verifyManifestSignature(deviceKeyX963: Data) -> Bool {
        guard let manifestBytes = Hex.decode(manifest),
            let sigBytes = Hex.decode(signature),
            let key = try? P256.Signing.PublicKey(x963Representation: deviceKeyX963),
            let sig = try? P256.Signing.ECDSASignature(rawRepresentation: sigBytes)
        else { return false }
        return key.isValidSignature(sig, for: manifestBytes)
    }
}

/// Result of fully verifying an incoming membership event (transparency anchor + manifest
/// signature). Only `.verified` should be fed to `MlsClient.processCommit`.
public enum MembershipVerifyResult: Sendable, Equatable {
    /// Fully verified: feed `(added, removed, nextEpoch)` to the correspondence check.
    case verified(added: [Data], removed: [Data], nextEpoch: UInt64)
    /// The log advertised a key different from the pinned one (possible key-directory swap).
    case logKeyChanged
    /// STH signature, actor-device binding, or its inclusion proof did not verify.
    case badTransparencyProof
    /// The manifest signature did not verify under the actor's transparency-logged device key.
    case badSignature
}

/// A sealed-sender certificate issued by the server for this device (ADR-0012 Slice 1b): the
/// certificate plus its signature and the server's cert public key. The device embeds
/// `certificate` + `signature` inside the E2EE payload of a sealed-sender message; the recipient
/// verifies them under its **pinned** cert public key — never the `certPublicKeyX963` echoed here.
public struct IssuedSenderCertificate: Sendable {
    public let certificate: SenderCertificate
    public let signature: Data
    /// The server's sender-cert public key as returned by the endpoint — for pinning/discovery
    /// only. A recipient MUST verify against its own out-of-band-pinned copy, not this field.
    public let certPublicKeyX963: Data

    /// True while the certificate is still valid at `now`.
    public func isFresh(now: UInt64) -> Bool { now <= certificate.expiresAt }

    /// Convenience: verify this issued certificate under a caller-supplied **pinned** cert key.
    public func verify(pinnedCertPublicKeyX963: Data, now: UInt64) -> Bool {
        certificate.verify(
            signature: signature, certPublicKeyX963: pinnedCertPublicKeyX963, now: now)
    }
}

extension SentinelClient {
    /// Fetch a fresh sealed-sender certificate for this device (`GET /v1/sender-certificate`,
    /// ADR-0012 Slice 1b). The device caches it until `expiresAt` and embeds it inside the E2EE
    /// payload of sealed-sender messages so the recipient verifies the sender the relay never saw.
    public func fetchSenderCertificate(accessToken: String) async throws -> IssuedSenderCertificate {
        struct Res: Decodable {
            let account_id: String
            let device_id: String
            let sender_public_key: String
            let expires_at: UInt64
            let signature: String
            let cert_public_key: String
        }
        let request = authed("GET", "/v1/sender-certificate", accessToken: accessToken)
        let res: Res = try decode(await perform(request))
        let cert = SenderCertificate(
            accountID: try hex(res.account_id),
            deviceID: try hex(res.device_id),
            senderPublicKeyX963: try hex(res.sender_public_key),
            expiresAt: res.expires_at)
        return IssuedSenderCertificate(
            certificate: cert,
            signature: try hex(res.signature),
            certPublicKeyX963: try hex(res.cert_public_key))
    }

    /// The conversation's current membership epoch (members only). Read this to rebase after a
    /// `staleEpoch` outcome.
    public func conversationEpoch(accessToken: String, conversationID: String) async throws -> UInt64
    {
        struct Res: Decodable { let epoch: UInt64 }
        let request = authed(
            "GET", "/v1/conversations/\(conversationID)/epoch", accessToken: accessToken)
        let res: Res = try decode(await perform(request))
        return res.epoch
    }

    /// Fetch a stored membership event (`epoch` = its `next_epoch`) so a recipient can run the
    /// correspondence check against `added`/`removed`.
    public func membershipEvent(
        accessToken: String, conversationID: String, epoch: UInt64
    ) async throws -> MembershipEvent {
        let request = authed(
            "GET", "/v1/conversations/\(conversationID)/membership/\(epoch)",
            accessToken: accessToken)
        return try decode(await perform(request))
    }

    /// Fully verify an incoming membership event before merging (ADR-0010 + R-201): the actor's
    /// device key is the one in the **transparency log** (STH signature under the *pinned* log key,
    /// the actor-device binding included under the signed root — so the server cannot substitute a
    /// key it never logged), and the manifest signature verifies under **that** key. Returns the
    /// verified delta for `MlsClient.processCommit`; the app merges only on `.verified`. This is the
    /// half of membership trust that closes the "valid-member lying manifest" gap for the
    /// *signature* — the correspondence check (in mls-core) closes the *content* half.
    public func verifyIncomingMembershipEvent(
        accessToken: String,
        conversationID: String,
        epoch: UInt64,
        pinnedLogPublicKeyX963: Data
    ) async throws -> MembershipVerifyResult {
        let event = try await membershipEvent(
            accessToken: accessToken, conversationID: conversationID, epoch: epoch)

        // 1. Signed tree head under the PINNED log key (reject a swapped/forged log key).
        let sth = try await transparencySignedTreeHead(accessToken: accessToken)
        guard let root = Hex.decode(sth.rootHash), let sthSig = Hex.decode(sth.signature),
            let advertised = Hex.decode(sth.logPublicKey)
        else { return .badTransparencyProof }
        if advertised != pinnedLogPublicKeyX963 { return .logKeyChanged }
        guard Transparency.verifySTHSignature(
            treeSize: sth.treeSize, root: root, timestamp: sth.timestamp,
            signature: sthSig, logPublicKeyX963: pinnedLogPublicKeyX963)
        else { return .badTransparencyProof }

        // 2. The actor's device binding, included under the signed root.
        let view = try await transparencyAccount(
            accessToken: accessToken, accountID: event.actorAccount, treeSize: sth.treeSize)
        guard let binding = view.bindings.first(where: { $0.deviceID == event.actorDevice }),
            let entry = Hex.decode(binding.entry), let loggedKey = Hex.decode(binding.publicKey)
        else { return .badTransparencyProof }
        let proof = binding.proof.compactMap { Hex.decode($0) }
        guard proof.count == binding.proof.count,
            Transparency.verifyInclusion(
                leaf: Transparency.hashLeaf(entry), index: Int(binding.leafIndex),
                treeSize: Int(sth.treeSize), proof: proof, root: root)
        else { return .badTransparencyProof }

        // 3. The manifest signature under the transparency-logged device key.
        guard event.verifyManifestSignature(deviceKeyX963: loggedKey) else { return .badSignature }

        return .verified(
            added: event.addedDeviceIDs, removed: event.removedDeviceIDs, nextEpoch: event.nextEpoch)
    }

    /// Build + sign the ADR-0010 manifest for `change` with `signer` (the device key — the private
    /// key never leaves the signer), then POST `/commit`. The returned outcome tells the caller
    /// whether to `mergeStaged()` (applied) or `clearStaged()` + rebase (staleEpoch) its local MLS
    /// commit. The commit hash is computed here, binding the manifest to these exact commit bytes.
    public func commitMembership(
        accessToken: String,
        conversationID: String,
        actorDevice: Data,
        change: MembershipChange,
        idempotencyKey: Data,
        ttlSeconds: UInt64,
        signer: DeviceSigner
    ) async throws -> MembershipCommitOutcome {
        guard let groupID = Hex.decode(conversationID) else { throw ClientError.decoding }
        let commitHash = Data(SHA256.hash(data: change.commit))
        let nextEpoch = change.prevEpoch + 1
        let expiresAt = UInt64(Date().timeIntervalSince1970) + ttlSeconds
        let manifest = MembershipManifest(
            control: change.control, groupID: groupID, prevEpoch: change.prevEpoch,
            nextEpoch: nextEpoch, commitHash: commitHash, actorDevice: actorDevice,
            added: change.added, removed: change.removed, idempotencyKey: idempotencyKey,
            expiresAt: expiresAt)
        let signature = try signer.sign(manifest.canonicalBytes())

        struct AddDto: Encodable {
            let account_id: String
            let device_id: String
        }
        struct Body: Encodable {
            let control_type: UInt8
            let prev_epoch: UInt64
            let next_epoch: UInt64
            let commit_hash: String
            let added: [AddDto]
            let removed: [String]
            let idempotency_key: String
            let expires_at: UInt64
            let signature: String
            let commit: String
            let welcomes: [String]
        }
        let body = Body(
            control_type: change.control.rawValue, prev_epoch: change.prevEpoch,
            next_epoch: nextEpoch, commit_hash: Hex.encode(commitHash),
            added: change.added.map {
                AddDto(account_id: Hex.encode($0.account), device_id: Hex.encode($0.device))
            },
            removed: change.removed.map { Hex.encode($0) },
            idempotency_key: Hex.encode(idempotencyKey), expires_at: expiresAt,
            signature: Hex.encode(signature), commit: Hex.encode(change.commit),
            welcomes: change.welcomes.map { Hex.encode($0) })
        var request = authed(
            "POST", "/v1/conversations/\(conversationID)/commit", accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)

        struct Res: Decodable {
            let applied: Bool
            let next_epoch: UInt64
        }
        do {
            let res: Res = try decode(await perform(request))
            return res.applied
                ? .applied(nextEpoch: res.next_epoch) : .alreadyApplied(nextEpoch: res.next_epoch)
        } catch ClientError.http(let status, let body) {
            if status == 409, body.contains("stale_epoch") { return .staleEpoch }
            if status == 409, body.contains("idempotency_conflict") { return .idempotencyConflict }
            if status == 403 { return .forbidden }
            throw ClientError.http(status: status, body: body)
        }
    }
}

// MARK: - Controlled multi-device (ADR-0008, R-903)

/// A device in the account's device list.
public struct DeviceSummary: Decodable, Sendable, Identifiable {
    public let deviceID: String
    public let revoked: Bool
    public let current: Bool
    public var id: String { deviceID }
    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id", revoked, current
    }
}

extension SentinelClient {
    /// Enroll a NEW device onto this account from a TRUSTED (already-enrolled) device (ADR-0008).
    /// `trustedSigner` is the trusted device's key; `newDevicePublicKeyX963` is the new device's
    /// SEC1 public key (obtained over the pairing channel, e.g. a scanned QR). Returns the new
    /// device's provisioned session, which the trusted device relays to it. A stolen
    /// username/password can never do this — only a trusted device's signature authorizes a device.
    public func enrollDevice(
        accessToken: String,
        accountID: String,
        trustedSigner: DeviceSigner,
        newDevicePublicKeyX963: Data
    ) async throws -> Session {
        struct Begin: Decodable {
            let device_id: String
            let txn_id: String
            let nonce: String
            let expires_at: UInt64
        }
        var beginReq = authed("POST", "/v1/devices/enroll/begin", accessToken: accessToken)
        beginReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
        beginReq.httpBody = try JSONEncoder().encode([String: String]())
        let ch: Begin = try decode(await perform(beginReq))

        guard let account = Hex.decode(accountID), let newDeviceID = Hex.decode(ch.device_id),
            let nonce = Hex.decode(ch.nonce), let txnID = Hex.decode(ch.txn_id)
        else { throw ClientError.decoding }
        let transcript = ClientTranscripts.deviceEnroll(
            accountID: account, newDeviceID: newDeviceID,
            newDevicePublicKey: newDevicePublicKeyX963, challengeNonce: nonce,
            expiresAt: ch.expires_at, txnID: txnID)
        let signature = try trustedSigner.sign(transcript)

        struct Finish: Encodable {
            let txn_id: String
            let device_public_key: String
            let signature: String
        }
        var finishReq = authed("POST", "/v1/devices/enroll/finish", accessToken: accessToken)
        finishReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
        finishReq.httpBody = try JSONEncoder().encode(
            Finish(
                txn_id: ch.txn_id,
                device_public_key: Hex.encode(newDevicePublicKeyX963),
                signature: Hex.encode(signature)))
        let session: SessionResponse = try decode(await perform(finishReq))
        return session.model
    }

    /// This account's devices (management list).
    public func listDevices(accessToken: String) async throws -> [DeviceSummary] {
        try decode(await perform(authed("GET", "/v1/devices", accessToken: accessToken)))
    }

    /// Revoke one of this account's devices (cascades tokens + refresh families).
    public func revokeDevice(accessToken: String, deviceID: String) async throws {
        struct Body: Encodable { let device_id: String }
        var request = authed("POST", "/v1/devices/revoke", accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(Body(device_id: deviceID))
        _ = try await perform(request)
    }
}

// MARK: - Account recovery (ADR-0003, R-304)

extension SentinelClient {
    /// Set (or replace) this account's recovery secret (authed; set it up while you hold a device).
    /// The secret is a generated high-entropy code; the server stores only its Argon2id hash.
    public func setRecoverySecret(accessToken: String, recoverySecret: String) async throws {
        struct Body: Encodable { let recovery_secret: String }
        var request = authed("POST", "/v1/recovery/set", accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(Body(recovery_secret: recoverySecret))
        _ = try await perform(request)
    }

    /// Recover an account onto a NEW device with the recovery secret (no other device needed). The
    /// new device self-signs a DeviceEnroll transcript (proof of possession). Returns the new
    /// device's session. Recovery restores account ACCESS, not E2EE history — the new device has a
    /// fresh identity and is re-added to conversations by other members.
    public func recoverAccount(
        username: String,
        recoverySecret: String,
        newDeviceSigner: DeviceSigner
    ) async throws -> Session {
        struct Begin: Decodable {
            let account_id: String
            let device_id: String
            let txn_id: String
            let nonce: String
            let expires_at: UInt64
        }
        let ch: Begin = try await post("/v1/recover/begin", body: ["username": username])

        guard let account = Hex.decode(ch.account_id), let deviceID = Hex.decode(ch.device_id),
            let nonce = Hex.decode(ch.nonce), let txnID = Hex.decode(ch.txn_id)
        else { throw ClientError.decoding }
        let transcript = ClientTranscripts.deviceEnroll(
            accountID: account, newDeviceID: deviceID,
            newDevicePublicKey: newDeviceSigner.publicKeyX963, challengeNonce: nonce,
            expiresAt: ch.expires_at, txnID: txnID)
        let signature = try newDeviceSigner.sign(transcript)

        struct Finish: Encodable {
            let username: String
            let recovery_secret: String
            let txn_id: String
            let device_public_key: String
            let signature: String
        }
        let session: SessionResponse = try await post(
            "/v1/recover/finish",
            body: Finish(
                username: username, recovery_secret: recoverySecret, txn_id: ch.txn_id,
                device_public_key: Hex.encode(newDeviceSigner.publicKeyX963),
                signature: Hex.encode(signature)))
        return session.model
    }
}
