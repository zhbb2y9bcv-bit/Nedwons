import CryptoKit
import Foundation
import MlsFfi
import NedwonsKit
import NedwonsUI

/// The messaging pipeline. Owns one `MlsClient` per conversation (plus the lobby of joiner
/// identities), and is the ONLY place that links both the UI and the MLS core, so plaintext never
/// leaves the device: previews and thread lines are built here from already-decrypted local
/// history, never from anything the relay supplied (INV-1).
///
/// What it does, end to end:
///
///   * **prekeys** — keeps `minimumKeyPackages` joiner identities published so others can add
///     this device (`ensureKeyPackages`);
///   * **bootstrap** — when the relay has created a conversation, builds its MLS group: claims each
///     member's prekey, adds them, delivers their Welcomes, and the growing commits to members
///     already in (`bootstrap`);
///   * **send** — enqueue → encrypt → upload → mark sent. An upload that fails leaves the message
///     durably *unsent*; `retryUnsent` replays it with the SAME ciphertext (the core caches it, so
///     a retry never advances the ratchet twice) under a deterministic idempotency key, so the
///     relay deduplicates a retry of a send whose response was lost;
///   * **receive** — long-polls the inbox, decrypts into the matching store (or joins via a lobby
///     identity when the envelope is a Welcome), acks, re-renders.
///
/// MLS secrets stay inside the Rust core — this type holds handles, not key material.
@MainActor
public final class ConversationCoordinator {
    /// The at-rest key for one store id (HKDF from the Keychain root on device).
    public typealias KeyProvider = @Sendable (String) throws -> Data

    private let model: AppModel
    private let relay: any ConversationRelay
    private let storeDirectory: URL
    private let keyProvider: KeyProvider
    private let minimumKeyPackages: Int
    private var index: MlsStoreIndex
    /// conversation id → Active client
    private var clients: [String: MlsClient] = [:]
    /// store id → Pending (lobby) client
    private var lobbyClients: [String: MlsClient] = [:]
    private var receiveTask: Task<Void, Never>?
    /// The most recent background failure, for diagnostics; the UI shows banners on user actions.
    public private(set) var lastSyncError: Error?

    public init(
        model: AppModel,
        relay: any ConversationRelay,
        storeDirectory: URL,
        keyProvider: @escaping KeyProvider,
        minimumKeyPackages: Int = 3
    ) {
        self.model = model
        self.relay = relay
        self.storeDirectory = storeDirectory
        self.keyProvider = keyProvider
        self.minimumKeyPackages = minimumKeyPackages
        try? FileManager.default.createDirectory(
            at: storeDirectory, withIntermediateDirectories: true)
        index = MlsStoreIndex.load(from: storeDirectory.appendingPathComponent(MlsStoreIndex.fileName))
    }

    // MARK: Wiring

    /// Wire the model's injected actions to this coordinator. Called once, before the
    /// authenticated UI renders.
    public func attach(aliasStore: ContactAliasStore?) {
        model.aliasStore = aliasStore
        model.secretTombstoneText = secretTombstoneText()
        model.sendMessageAction = { [weak self] body, conversationID in
            guard let self else { throw CoordinatorError.notSignedIn }
            try await self.send(body, in: conversationID)
        }
        model.bootstrapConversationAction = { [weak self] conversationID, members in
            guard let self else { throw CoordinatorError.notSignedIn }
            try await self.bootstrap(conversationID: conversationID, memberAccountIDs: members)
        }
        model.addMembersToConversationAction = { [weak self] conversationID, members in
            guard let self else { throw CoordinatorError.notSignedIn }
            try await self.addMembers(to: conversationID, memberAccountIDs: members)
        }
        model.renameGroupAction = { [weak self] conversationID, name in
            guard let self else { throw CoordinatorError.notSignedIn }
            try await self.renameGroup(conversationID, to: name)
        }
        model.markConversationReadAction = { [weak self] conversationID in
            self?.markRead(conversationID)
        }
        model.sendAttachmentAction = { [weak self] data, mime, filename, caption, conversationID in
            guard let self else { throw CoordinatorError.notSignedIn }
            try await self.sendAttachment(
                data, mime: mime, filename: filename, caption: caption, to: conversationID)
        }
        model.loadAttachmentAction = { [weak self] blobID in
            guard let self else { throw CoordinatorError.notSignedIn }
            return try await self.loadAttachment(blobID)
        }
        model.clearHistoryAction = { [weak self] conversationID in
            try self?.clearHistory(in: conversationID)
        }
        model.wipeAllLocalDataAction = { [weak self] in
            self?.wipeAllLocalData()
        }
    }

    /// Begin the receive loop for the signed-in session. Idempotent.
    public func start() {
        guard receiveTask == nil else { return }
        receiveTask = Task { [weak self] in
            await self?.prepare()
            while !Task.isCancelled {
                guard let self, self.token != nil else { return }
                do {
                    _ = try await self.syncOnce(waitSeconds: 25)
                    await self.retryUnsent()
                } catch is CancellationError {
                    return
                } catch {
                    self.lastSyncError = error
                    // Offline or the relay is unhappy: back off, then keep polling.
                    try? await Task.sleep(nanoseconds: 3_000_000_000)
                }
            }
        }
    }

    /// Stop polling and release every open store (sign-out). Nothing on disk is touched.
    public func stop() {
        receiveTask?.cancel()
        receiveTask = nil
        for client in clients.values { client.close() }
        for client in lobbyClients.values { client.close() }
        clients.removeAll()
        lobbyClients.removeAll()
    }

    /// One-time work after sign-in: render what is stored, replenish prekeys, resume any upload a
    /// crash or a dead connection interrupted.
    public func prepare() async {
        for conversationID in index.conversations.keys { refresh(conversationID) }
        await ensureKeyPackages()
        await retryUnsent()
    }

    // MARK: Prekeys

    /// Keep `minimumKeyPackages` prekeys outstanding at the relay, each backed by its own persisted
    /// joiner identity. Quiet on failure (retried on the next loop iteration).
    public func ensureKeyPackages() async {
        guard let token, let identity else { return }
        do {
            var available = try await relay.availableKeyPackages(accessToken: token)
            while available < minimumKeyPackages {
                let storeID = Self.newStoreID()
                let client = try MlsClient.newJoiner(
                    identity: identity, dbPath: path(storeID), atRestKey: try keyProvider(storeID))
                // Recorded BEFORE publishing: an unpublished lobby is harmless, an unrecorded one
                // is a prekey nobody can redeem.
                index.lobbies.append(storeID)
                try saveIndex()
                lobbyClients[storeID] = client
                try await relay.publishKeyPackage(accessToken: token, keyPackage: try client.keyPackage())
                available += 1
            }
        } catch {
            lastSyncError = error
        }
    }

    // MARK: Bootstrap

    /// Build the MLS group for a conversation the relay has just created. Members whose prekey
    /// cannot be claimed or whose Welcome cannot be delivered are reported together at the end;
    /// the group still exists with everyone who succeeded.
    public func bootstrap(conversationID: String, memberAccountIDs: [String]) async throws {
        guard let token, let identity else { throw CoordinatorError.notSignedIn }
        // Idempotent: a second call for a conversation this device already holds does nothing.
        guard index.conversations[conversationID] == nil else { return }
        let storeID = Self.newStoreID()
        let client = try MlsClient.createGroup(
            identity: identity, dbPath: path(storeID), atRestKey: try keyProvider(storeID))
        index.conversations[conversationID] = storeID
        try saveIndex()
        clients[conversationID] = client

        let failed = await grow(
            client: client, conversationID: conversationID, accounts: memberAccountIDs, token: token)
        refresh(conversationID)
        if !failed.isEmpty {
            throw CoordinatorError.membersNotSetUp(failed)
        }
    }

    /// Add people to an EXISTING conversation's MLS group, after the relay has added them to
    /// routing. Without this they would be routed ciphertext they hold no key for.
    ///
    /// The newcomers also need the group's name, which lives only inside the ciphertext: it is
    /// re-sent after the adds so a new member's list shows the group by name rather than by size.
    public func addMembers(to conversationID: String, memberAccountIDs: [String]) async throws {
        guard let token else { throw CoordinatorError.notSignedIn }
        guard let client = activeClient(for: conversationID) else {
            throw CoordinatorError.noSessionForConversation
        }
        let failed = await grow(
            client: client, conversationID: conversationID, accounts: memberAccountIDs, token: token)
        if failed.isEmpty, let name = (try? client.groupName()) ?? nil {
            // Best effort: a group whose name did not reach a newcomer is cosmetic, and the next
            // rename fixes it. Never fail an add over it.
            try? await sendGroupName(name, client: client, conversationID: conversationID)
        }
        refresh(conversationID)
        if !failed.isEmpty {
            throw CoordinatorError.membersNotSetUp(failed)
        }
    }

    /// Add each account to the MLS group: claim a prekey, add, deliver the Welcome to that device,
    /// then publish the add's commit so every existing member reaches the new epoch. Returns the
    /// accounts that could not be added.
    ///
    /// The commit is FANNED OUT rather than hand-addressed to each member device. The relay already
    /// knows the conversation's routing membership, so it can do in one call what would otherwise
    /// need a per-device list this client has no business assembling. The newcomer is in routing
    /// too and receives the commit for the epoch it is joining at, which it cannot process — that
    /// envelope is discarded on their side, exactly like any out-of-epoch message, and the Welcome
    /// (sent first) is what actually admits them.
    private func grow(
        client: MlsClient, conversationID: String, accounts: [String], token: String
    ) async -> [String] {
        var failed: [String] = []
        for account in accounts {
            do {
                let claimed = try await relay.claimKeyPackage(accessToken: token, accountID: account)
                guard let keyPackage = Hex.decode(claimed.keyPackage) else {
                    throw CoordinatorError.badKeyPackage
                }
                let outcome = try client.addMember(keyPackage: keyPackage)
                try await relay.sendWelcome(
                    accessToken: token, conversationID: conversationID,
                    recipientDevice: claimed.deviceID, ciphertext: outcome.welcome,
                    idempotencyKey: Self.randomKey())
                _ = try await relay.sendMessage(
                    accessToken: token, conversationID: conversationID, ciphertext: outcome.commit,
                    idempotencyKey: Self.randomKey())
            } catch {
                failed.append(account)
            }
        }
        return failed
    }

    // MARK: Group name & read state

    /// Rename the group for everyone. The name is an ordinary E2EE message, so it uses the same
    /// upload path (and the same retry semantics) as anything else the user sends.
    public func renameGroup(_ conversationID: String, to name: String) async throws {
        guard let client = activeClient(for: conversationID) else {
            throw CoordinatorError.noSessionForConversation
        }
        try await sendGroupName(name, client: client, conversationID: conversationID)
        refresh(conversationID)
    }

    private func sendGroupName(_ name: String, client: MlsClient, conversationID: String) async throws {
        let localID = try client.setGroupName(name: name)
        try await upload(localID: localID, client: client, conversationID: conversationID)
    }

    // MARK: Attachments

    /// Encrypt a file, upload the ciphertext, then send the message that references it.
    ///
    /// The order is load-bearing. Encryption happens first and locally, so the relay never sees the
    /// file. The upload happens SECOND and the message THIRD, so a failed upload leaves no message
    /// pointing at bytes that do not exist — the failure is a file that was never sent, not a
    /// permanently broken bubble in someone's thread.
    public func sendAttachment(
        _ data: Data, mime: String, filename: String, caption: String, to conversationID: String
    ) async throws {
        guard let token else { throw CoordinatorError.notSignedIn }
        guard let client = activeClient(for: conversationID) else {
            throw CoordinatorError.noSessionForConversation
        }
        let sealed = try sealAttachment(plaintext: data)
        let blobHex = try await relay.uploadAttachment(
            accessToken: token, conversationID: conversationID, ciphertext: sealed.ciphertext)
        guard let blobID = Hex.decode(blobHex), blobID.count == 16 else {
            throw CoordinatorError.badBlobID
        }
        let localID = try client.sendAttachment(
            blobId: blobID, key: sealed.key, digest: sealed.digest, size: UInt64(data.count),
            mime: mime, filename: filename, caption: caption)
        defer { refresh(conversationID) }
        try await upload(localID: localID, client: client, conversationID: conversationID)
    }

    /// Fetch one attachment's ciphertext and open it with the key that came over MLS.
    ///
    /// The digest check inside `openAttachment` is what makes this safe against the relay serving
    /// different bytes under the same id — it is checked before decryption, so a substitution is
    /// reported as such rather than as a decryption failure.
    public func loadAttachment(_ blobID: String) async throws -> Data {
        guard let token else { throw CoordinatorError.notSignedIn }
        guard let reference = attachmentReference(blobID) else {
            throw CoordinatorError.unknownAttachment
        }
        let ciphertext = try await relay.downloadAttachment(accessToken: token, blobID: blobID)
        return try openAttachment(
            key: reference.key, digest: reference.digest, ciphertext: ciphertext)
    }

    /// The reference (with its key) as stored in whichever conversation's log carries this blob.
    /// Read from local state, never from the network: the key must come from the message the group
    /// sent, not from anything the relay could influence.
    private func attachmentReference(_ blobID: String) -> AttachmentInfo? {
        for conversationID in index.conversations.keys {
            guard let client = activeClient(for: conversationID),
                let messages = try? client.messages()
            else { continue }
            for message in messages {
                if let attachment = message.attachment, Hex.encode(attachment.blobId) == blobID {
                    return attachment
                }
            }
        }
        return nil
    }

    /// The user is looking at the conversation: everything in it is read.
    public func markRead(_ conversationID: String) {
        guard let client = activeClient(for: conversationID) else { return }
        try? client.markRead()
        refresh(conversationID)
    }

    // MARK: Send

    /// Enqueue → encrypt → upload → mark sent. A failed upload leaves the message durably unsent
    /// and the error propagates so the UI can say so — but the thread is re-rendered either way, so
    /// the message appears as *sending* rather than vanishing until a later retry succeeds. That
    /// refresh must not be skipped on the failure path; it is the whole difference between "we lost
    /// your message" and "we're still trying".
    private func send(_ body: String, in conversationID: String) async throws {
        guard let client = activeClient(for: conversationID) else {
            throw CoordinatorError.noSessionForConversation
        }
        let localID = try client.enqueue(plaintext: Data(body.utf8))
        defer { refresh(conversationID) }
        try await upload(localID: localID, client: client, conversationID: conversationID)
    }

    /// Replay every upload the relay has not accepted, oldest first, per conversation. Stops at the
    /// first failure in a conversation (order is preserved) and skips conversations whose composer
    /// is locked — a message drafted while muted waits for the mute to lift rather than being
    /// refused again on every loop.
    public func retryUnsent() async {
        for conversationID in index.conversations.keys.sorted() {
            guard model.composerLock(for: conversationID) == nil,
                let client = activeClient(for: conversationID),
                let unsent = try? client.unsentLocalIds(), !unsent.isEmpty
            else { continue }
            for localID in unsent {
                do {
                    try await upload(localID: localID, client: client, conversationID: conversationID)
                } catch {
                    lastSyncError = error
                    break
                }
            }
            refresh(conversationID)
        }
    }

    /// The upload half of a send. `encrypt` is idempotent in the core (cached ciphertext), and the
    /// idempotency key is a pure function of (conversation, local id), so a retry of a send whose
    /// response was lost is deduplicated by the relay instead of delivered twice.
    private func upload(localID: UInt64, client: MlsClient, conversationID: String) async throws {
        guard let token else { throw CoordinatorError.notSignedIn }
        let ciphertext = try client.encrypt(localId: localID)
        _ = try await relay.sendMessage(
            accessToken: token, conversationID: conversationID, ciphertext: ciphertext,
            idempotencyKey: Self.idempotencyKey(conversationID: conversationID, localID: localID))
        try client.markSent(localId: localID)
    }

    // MARK: Receive

    /// One inbox pass: fetch (long-polling up to `waitSeconds`), decrypt each identified envelope
    /// into its store — joining via a lobby identity when it is a Welcome for a conversation we do
    /// not hold yet — ack what was consumed, re-render what changed. Returns the number of
    /// envelopes acked.
    ///
    /// Sealed-sender and self-group envelopes are left for their own consumers (separate id
    /// spaces); this pass never acks them.
    @discardableResult
    public func syncOnce(waitSeconds: Int = 0) async throws -> Int {
        guard let token else { throw CoordinatorError.notSignedIn }
        let envelopes = try await relay.fetchInbox(accessToken: token, waitSeconds: waitSeconds)
        var acked: [Int] = []
        var touched = Set<String>()
        var joined = false
        for envelope in envelopes.sorted(by: { $0.id < $1.id })
        where !envelope.sealed && !envelope.selfGroup {
            guard let conversationID = envelope.conversationID,
                let bytes = Hex.decode(envelope.ciphertext)
            else {
                acked.append(envelope.id)  // malformed: nothing will ever process it
                continue
            }
            if let client = activeClient(for: conversationID) {
                // A commit we already applied, a duplicate, or garbage all surface as errors here;
                // none can ever be processed later, so the envelope is consumed either way. The
                // error is kept for diagnostics, never shown: the user did nothing to cause it.
                do {
                    _ = try client.processInbound(envelopeId: UInt64(envelope.id), ciphertext: bytes)
                } catch {
                    lastSyncError = error
                }
                touched.insert(conversationID)
                acked.append(envelope.id)
            } else if try joinViaLobby(welcome: bytes, conversationID: conversationID) {
                touched.insert(conversationID)
                acked.append(envelope.id)
                joined = true
            } else {
                // Not a Welcome any of our identities can redeem, and no session for it: it can
                // never be processed on this device. Consumed rather than left to block the queue.
                acked.append(envelope.id)
            }
        }
        if !acked.isEmpty {
            try await relay.ackInbox(accessToken: token, ids: acked)
        }
        for conversationID in touched { refresh(conversationID) }
        if joined {
            await model.refreshConversations()
            await ensureKeyPackages()  // one lobby identity was consumed
        }
        return acked.count
    }

    /// Try the Welcome against each lobby identity. The one whose prekey it was made for joins and
    /// becomes the conversation's store; the rest are untouched (a bad Welcome leaves a joiner
    /// Pending and retryable, by construction of the core).
    private func joinViaLobby(welcome: Data, conversationID: String) throws -> Bool {
        for storeID in index.lobbies {
            guard let client = lobbyClient(storeID) else { continue }
            do {
                try client.joinGroup(welcome: welcome)
            } catch {
                continue
            }
            index.lobbies.removeAll { $0 == storeID }
            index.conversations[conversationID] = storeID
            try saveIndex()
            lobbyClients.removeValue(forKey: storeID)
            clients[conversationID] = client
            return true
        }
        return false
    }

    // MARK: Stores

    private func activeClient(for conversationID: String) -> MlsClient? {
        if let existing = clients[conversationID] { return existing }
        guard let storeID = index.conversations[conversationID],
            let opened = try? MlsClient.open(dbPath: path(storeID), atRestKey: try keyProvider(storeID)),
            (try? opened.isPending()) == false
        else { return nil }
        clients[conversationID] = opened
        return opened
    }

    private func lobbyClient(_ storeID: String) -> MlsClient? {
        if let existing = lobbyClients[storeID] { return existing }
        guard let opened = try? MlsClient.open(dbPath: path(storeID), atRestKey: try keyProvider(storeID)),
            (try? opened.isPending()) == true
        else {
            // Unreadable or no longer pending: it can never redeem a Welcome. Forget it.
            index.lobbies.removeAll { $0 == storeID }
            try? saveIndex()
            return nil
        }
        lobbyClients[storeID] = opened
        return opened
    }

    /// Destroy every on-device MLS store for this account (account deletion only).
    ///
    /// The opposite of `clearHistory`, and the distinction is load-bearing: `clearHistory` keeps
    /// the ratchet, replay watermark and secret records so a later message still decrypts and a
    /// spent secret cannot be re-viewed. Here the account is gone, so leaving decryptable key
    /// material on the device would mean a "deleted" account whose ratchet state is still sitting
    /// in the container.
    public func wipeAllLocalData() {
        stop()
        index = MlsStoreIndex()
        guard
            let entries = try? FileManager.default.contentsOfDirectory(
                at: storeDirectory, includingPropertiesForKeys: nil)
        else { return }
        for entry in entries
        where entry.lastPathComponent.hasPrefix("store-") || entry.lastPathComponent.hasPrefix("conv-")
            || entry.lastPathComponent == MlsStoreIndex.fileName
        {
            try? FileManager.default.removeItem(at: entry)
        }
    }

    /// Local-only erase of the visible log. Protocol state is retained by the core, so a later
    /// message still decrypts and the thread legitimately returns.
    private func clearHistory(in conversationID: String) throws {
        guard let client = activeClient(for: conversationID) else { return }
        try client.clearVisibleHistory()
        model.threadLines[conversationID] = []
        model.localThreads.removeValue(forKey: conversationID)
    }

    /// Rebuild the rendered lines and list preview for one conversation from decrypted local state.
    public func refresh(_ conversationID: String) {
        guard let client = activeClient(for: conversationID),
            let stored = try? client.messages()
        else { return }

        let lines: [ThreadLine] = stored.map { message in
            let mine = message.direction == .outbound
            let timestamp = Self.timestamp(message.createdAtMs)
            if let secretID = message.secretId {
                let phase = (try? client.secretPhase(
                    secretId: secretID, nowMs: UptimeClock().nowMs())) ?? .unknown
                return ThreadLine(
                    id: message.localId,
                    kind: phase == .consumed ? .consumedSecret : .sealedSecret(secretID),
                    mine: mine,
                    timestamp: timestamp,
                    isPending: message.pending)
            }
            if let attachment = message.attachment {
                return ThreadLine(
                    id: message.localId,
                    kind: .attachment(
                        AttachmentLine(
                            blobID: Hex.encode(attachment.blobId),
                            mime: attachment.mime,
                            filename: attachment.filename,
                            size: attachment.size,
                            caption: String(decoding: message.plaintext, as: UTF8.self))),
                    mine: mine,
                    timestamp: timestamp,
                    isPending: message.pending)
            }
            return ThreadLine(
                id: message.localId,
                kind: .text(String(decoding: message.plaintext, as: UTF8.self)),
                mine: mine,
                timestamp: timestamp,
                isPending: message.pending)
        }
        model.threadLines[conversationID] = lines
        // The group's name lives only inside the ciphertext; this is the one place it is read.
        if let name = (try? client.groupName()) ?? nil {
            model.groupNames[conversationID] = name
        }

        // A secret never contributes its body to the preview — only that one arrived.
        let preview: String? = stored.last.map { last in
            if last.secretId != nil { return "Secret message" }
            let caption = String(decoding: last.plaintext, as: UTF8.self)
            guard let attachment = last.attachment else { return caption }
            // A file's preview names what it is; the caption follows when there is one.
            let kind = AttachmentLine(
                blobID: "", mime: attachment.mime, filename: attachment.filename,
                size: attachment.size, caption: caption
            ).displayName
            return caption.isEmpty ? kind : "\(kind) · \(caption)"
        }
        model.localThreads[conversationID] = AppModel.LocalThreadState(
            preview: preview,
            // The real time of the last message, so the list orders by activity rather than by
            // whenever this happened to refresh.
            lastActivity: stored.last.flatMap { Self.timestamp($0.createdAtMs) },
            unreadCount: Int((try? client.unreadCount()) ?? 0))
    }

    /// 0 means "logged before timestamps existed" — rendered without a time rather than as 1970.
    private static func timestamp(_ ms: UInt64) -> Date? {
        ms == 0 ? nil : Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
    }

    // MARK: Helpers

    private var token: String? { model.session?.accessToken }

    /// The MLS credential identity: this device's id (bytes), so a group's membership is
    /// attributable to enrolled devices.
    private var identity: Data? {
        guard let deviceID = model.session?.deviceID else { return nil }
        return Hex.decode(deviceID) ?? Data(deviceID.utf8)
    }

    private func path(_ storeID: String) -> String {
        storeDirectory.appendingPathComponent("store-\(storeID)").path
    }

    private func saveIndex() throws {
        try index.save(to: storeDirectory.appendingPathComponent(MlsStoreIndex.fileName))
    }

    private static func newStoreID() -> String {
        UUID().uuidString.lowercased()
    }

    private static func randomKey() -> Data {
        Data((0..<16).map { _ in UInt8.random(in: 0...255) })
    }

    /// Deterministic per (conversation, local id): a retry is the same logical send.
    static func idempotencyKey(conversationID: String, localID: UInt64) -> Data {
        var input = Data("nedwons-send-v1".utf8)
        input.append(Data(conversationID.utf8))
        withUnsafeBytes(of: localID.littleEndian) { input.append(contentsOf: $0) }
        return Data(SHA256.hash(data: input).prefix(16))
    }

    public enum CoordinatorError: Error, Equatable {
        case noSessionForConversation
        case notSignedIn
        case badKeyPackage
        /// The relay returned something that is not a 16-byte blob id.
        case badBlobID
        /// No message in local state references this blob, so there is no key to open it with.
        case unknownAttachment
        /// Account ids that could not be added (no prekey, or delivery failed).
        case membersNotSetUp([String])
    }
}
