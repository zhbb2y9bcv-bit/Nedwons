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

        var priorDevices: [String] = []
        var failed: [String] = []
        for account in memberAccountIDs {
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
                // Everyone already in the group needs this commit to reach the new epoch;
                // targeted, so the newcomer (who joins AT this epoch) never sees a commit it
                // cannot process.
                for device in priorDevices {
                    try await relay.sendWelcome(
                        accessToken: token, conversationID: conversationID, recipientDevice: device,
                        ciphertext: outcome.commit, idempotencyKey: Self.randomKey())
                }
                priorDevices.append(claimed.deviceID)
            } catch {
                failed.append(account)
            }
        }
        refresh(conversationID)
        if !failed.isEmpty {
            throw CoordinatorError.membersNotSetUp(failed)
        }
    }

    // MARK: Send

    /// Enqueue → encrypt → upload → mark sent. A failed upload leaves the message durably unsent
    /// (visible in the thread, retried later); the error propagates so the UI can say so.
    private func send(_ body: String, in conversationID: String) async throws {
        guard let client = activeClient(for: conversationID) else {
            throw CoordinatorError.noSessionForConversation
        }
        let localID = try client.enqueue(plaintext: Data(body.utf8))
        refresh(conversationID)
        try await upload(localID: localID, client: client, conversationID: conversationID)
        refresh(conversationID)
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
            if let secretID = message.secretId {
                let phase = (try? client.secretPhase(
                    secretId: secretID, nowMs: UptimeClock().nowMs())) ?? .unknown
                return ThreadLine(
                    id: message.localId,
                    kind: phase == .consumed ? .consumedSecret : .sealedSecret(secretID),
                    mine: mine)
            }
            return ThreadLine(
                id: message.localId,
                kind: .text(String(decoding: message.plaintext, as: UTF8.self)),
                mine: mine)
        }
        model.threadLines[conversationID] = lines

        // A secret never contributes its body to the preview — only that one arrived.
        let preview: String? = stored.last.map { last in
            last.secretId != nil
                ? "Secret message"
                : String(decoding: last.plaintext, as: UTF8.self)
        }
        model.localThreads[conversationID] = AppModel.LocalThreadState(
            preview: preview,
            lastActivity: stored.isEmpty ? nil : Date(),
            unreadCount: 0)
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
        /// Account ids that could not be added (no prekey, or delivery failed).
        case membersNotSetUp([String])
    }
}
