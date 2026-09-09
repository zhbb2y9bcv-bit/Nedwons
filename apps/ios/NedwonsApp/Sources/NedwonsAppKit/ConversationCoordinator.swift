import CryptoKit
import Foundation
import MlsFfi
import NedwonsKit
import NedwonsPush
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
    /// The cross-process single-writer lock over the (possibly shared) store directory. Held from
    /// `start()` to `stop()`; the notification extension takes it non-blockingly while we're away.
    private var storeLock: StoreLock?
    /// False only between `stop()` and the next `start()`: a still-unwinding loop iteration must
    /// not re-open stores that were just closed and unlocked. True from construction so direct
    /// (test/tool) use without a receive loop still works.
    private var isActive = true
    /// The most recent background failure, for diagnostics; the UI shows banners on user actions.
    public private(set) var lastSyncError: Error?
    /// Whether this device tells senders what it has received and read. A privacy choice, not a
    /// protocol requirement: with it off, nothing about what this device has seen is sent to
    /// anyone, and every other feature still works. (No settings toggle is wired to it yet.)
    public var sendReceipts = true

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
            await self?.markRead(conversationID)
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
        model.sendReplyAction = { [weak self] body, replyTo, conversationID in
            guard let self else { throw CoordinatorError.notSignedIn }
            try await self.sendReply(body, replyTo: replyTo, in: conversationID)
        }
        model.reactAction = { [weak self] messageID, emoji, remove, conversationID in
            guard let self else { throw CoordinatorError.notSignedIn }
            try await self.react(messageID, emoji: emoji, remove: remove, in: conversationID)
        }
        model.setTypingAction = { [weak self] active, conversationID in
            await self?.setTyping(active, in: conversationID)
        }
        model.clearHistoryAction = { [weak self] conversationID in
            try self?.clearHistory(in: conversationID)
        }
        model.wipeAllLocalDataAction = { [weak self] in
            self?.wipeAllLocalData()
        }
        model.setDisappearTimerAction = { [weak self] seconds, conversationID in
            guard let self else { throw CoordinatorError.notSignedIn }
            try await self.setDisappearTimer(seconds, in: conversationID)
        }
        model.deleteForEveryoneAction = { [weak self] messageID, conversationID in
            guard let self else { throw CoordinatorError.notSignedIn }
            try await self.deleteForEveryone(messageID: messageID, in: conversationID)
        }
        model.forwardMessageAction = { [weak self] lineID, sourceID, destinationID in
            guard let self else { throw CoordinatorError.notSignedIn }
            try await self.forward(lineID: lineID, from: sourceID, to: destinationID)
        }
        model.searchMessagesAction = { [weak self] query in
            self?.searchMessages(matching: query).map {
                MessageSearchHit(
                    conversationID: $0.conversationID, localID: $0.localID,
                    snippet: $0.snippet, timestamp: $0.timestamp, mine: $0.mine)
            } ?? []
        }
    }

    /// Begin the receive loop for the signed-in session. Idempotent.
    public func start() {
        guard receiveTask == nil else { return }
        isActive = true
        receiveTask = Task { [weak self] in
            // Single-writer (ADR-0007): the Notification Service Extension may be mid-decrypt in
            // the shared store. Wait for the cross-process lock BEFORE opening anything; the wait
            // is bounded by the extension's few-second budget and runs off the main thread.
            if let self, self.storeLock == nil {
                let url = SharedStoreLayout.lockURL(storeDirectory: self.storeDirectory)
                self.storeLock = await Task.detached { StoreLock.acquire(at: url) }.value
            }
            await self?.prepare()
            while !Task.isCancelled {
                guard let self, self.token != nil else { return }
                do {
                    _ = try await self.syncOnce(waitSeconds: 25)
                    await self.reconcileSetup()
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

    /// Stop polling and release every open store (sign-out, and entering the background so the
    /// notification extension can take the single-writer lock). Nothing on disk is touched.
    public func stop() {
        isActive = false
        receiveTask?.cancel()
        receiveTask = nil
        for client in clients.values { client.close() }
        for client in lobbyClients.values { client.close() }
        clients.removeAll()
        lobbyClients.removeAll()
        // Re-read on next start(): the extension may have advanced ratchets while we were away.
        index = MlsStoreIndex.load(from: storeDirectory.appendingPathComponent(MlsStoreIndex.fileName))
        storeLock?.release()
        storeLock = nil
    }

    /// One-time work after sign-in: render what is stored, replenish prekeys, resume any upload a
    /// crash or a dead connection interrupted.
    public func prepare() async {
        for conversationID in index.conversations.keys { refresh(conversationID) }
        await ensureKeyPackages()
        await reconcileSetup()
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

    /// Build the MLS group for a conversation the relay has just created, then drain its setup
    /// queue: the server has already listed every member DEVICE (V27 — including this account's
    /// own siblings), so the creator's job is one reconcile pass. Members whose prekeys aren't
    /// published yet are simply DEFERRED, not failed — a later sync completes them the moment
    /// they open the app.
    public func bootstrap(conversationID: String, memberAccountIDs: [String]) async throws {
        guard token != nil, let identity else { throw CoordinatorError.notSignedIn }
        // Idempotent: a second call for a conversation this device already holds does nothing.
        guard index.conversations[conversationID] == nil else { return }
        let storeID = Self.newStoreID()
        let client = try MlsClient.createGroup(
            identity: identity, dbPath: path(storeID), atRestKey: try keyProvider(storeID))
        index.conversations[conversationID] = storeID
        try saveIndex()
        clients[conversationID] = client
        _ = memberAccountIDs  // membership authority is the relay's queue, not this list
        await reconcileSetup()
        refresh(conversationID)
    }

    /// Add people to an EXISTING conversation's MLS group after the relay queued their devices
    /// (V27). One reconcile pass covers what is reachable now; the rest are deferred adds that
    /// complete on later syncs — including on OTHER members' devices, whoever syncs first.
    public func addMembers(to conversationID: String, memberAccountIDs: [String]) async throws {
        guard token != nil else { throw CoordinatorError.notSignedIn }
        guard activeClient(for: conversationID) != nil else {
            throw CoordinatorError.noSessionForConversation
        }
        _ = memberAccountIDs
        await reconcileSetup()
        refresh(conversationID)
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
    // MARK: Setup reconcile (V27) — the loop behind multi-device + automatic/deferred adds

    /// Drain the relay's MLS setup queue: every routed member device still awaiting its Welcome,
    /// across all of this device's conversations. For each reachable target — the relay's claim
    /// makes exactly one member's device do each add — this claims the target DEVICE's prekey,
    /// adds it to the group, delivers the Welcome, confirms, and fans out the commit so existing
    /// members reach the new epoch (the newcomer discards the out-of-epoch copy; the Welcome is
    /// what admits them, exactly as before).
    ///
    /// This single loop is what makes invite-link joins, approved join requests, adds of people
    /// with no prekeys yet (deferred adds), and freshly linked sibling devices all "just start
    /// working": a target that cannot be served now (no prekey published, no session here) stays
    /// queued, its claim expires, and someone's next sync picks it up.
    public func reconcileSetup(limit: Int = 8) async {
        guard let token else { return }
        guard let targets = try? await relay.setupNeeded(accessToken: token), !targets.isEmpty
        else { return }
        var touched = Set<String>()
        for target in targets.prefix(limit) {
            // Only a device that holds this conversation's MLS group can add to it.
            guard let client = activeClient(for: target.conversationID) else { continue }
            guard (try? await relay.claimSetup(
                accessToken: token, conversationID: target.conversationID,
                deviceID: target.deviceID)) == true
            else { continue }
            do {
                let claimed = try await relay.claimDeviceKeyPackage(
                    accessToken: token, deviceID: target.deviceID)
                guard let keyPackage = Hex.decode(claimed.keyPackage) else {
                    throw CoordinatorError.badKeyPackage
                }
                let outcome = try client.addMember(keyPackage: keyPackage)
                try await relay.sendWelcome(
                    accessToken: token, conversationID: target.conversationID,
                    recipientDevice: target.deviceID, ciphertext: outcome.welcome,
                    idempotencyKey: Self.randomKey())
                try await relay.confirmSetup(
                    accessToken: token, conversationID: target.conversationID,
                    deviceID: target.deviceID)
                _ = try await relay.sendMessage(
                    accessToken: token, conversationID: target.conversationID,
                    ciphertext: outcome.commit, idempotencyKey: Self.randomKey())
                // The name lives only inside the ciphertext; re-send it so the newcomer's list
                // shows the group by name. Best-effort — the next rename fixes a miss.
                if let name = (try? client.groupName()) ?? nil {
                    try? await sendGroupName(name, client: client, conversationID: target.conversationID)
                }
                touched.insert(target.conversationID)
            } catch {
                // No prekey yet (deferred add), or a transient failure: the claim expires and the
                // target is retried on a later sync — here or on another member's device.
                lastSyncError = error
            }
        }
        for conversationID in touched { refresh(conversationID) }
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

    // MARK: Disappearing messages, delete-for-everyone, forwarding, search

    /// Change the conversation's disappearing-message timer for everyone (0 = off). An ordinary
    /// E2EE message on the ordinary upload path; the local timer applies when the group is told.
    public func setDisappearTimer(_ seconds: UInt32, in conversationID: String) async throws {
        guard let client = activeClient(for: conversationID) else {
            throw CoordinatorError.noSessionForConversation
        }
        let localID = try client.setDisappearTimer(seconds: seconds)
        defer { refresh(conversationID) }
        try await upload(localID: localID, client: client, conversationID: conversationID)
    }

    /// Retract one of the user's OWN messages everywhere. The core refuses anyone else's message,
    /// and recipients independently refuse a delete from a non-author — the menu item is UX, the
    /// core checks are the rule. Best-effort by design (R-901).
    public func deleteForEveryone(messageID: String, in conversationID: String) async throws {
        guard let client = activeClient(for: conversationID),
            let target = Hex.decode(messageID)
        else { throw CoordinatorError.noSessionForConversation }
        let localID = try client.deleteForEveryone(target: target)
        defer { refresh(conversationID) }
        try await upload(localID: localID, client: client, conversationID: conversationID)
    }

    /// Forward a message to another conversation. Text forwards as text; a file is fetched,
    /// decrypted locally, and RE-encrypted under a fresh one-time key for the destination — the
    /// two conversations never share key material, and the relay sees an unrelated new blob.
    public func forward(lineID: UInt64, from sourceID: String, to destinationID: String) async throws {
        guard let source = activeClient(for: sourceID),
            let message = (try? source.messages())?.first(where: { $0.localId == lineID }),
            !message.deleted, message.secretId == nil
        else { throw CoordinatorError.noSessionForConversation }
        if let attachment = message.attachment {
            let data = try await loadAttachment(Hex.encode(attachment.blobId))
            try await sendAttachment(
                data, mime: attachment.mime, filename: attachment.filename,
                caption: String(decoding: message.plaintext, as: UTF8.self), to: destinationID)
        } else {
            try await send(String(decoding: message.plaintext, as: UTF8.self), in: destinationID)
        }
    }

    /// One search hit across the decrypted local history.
    public struct SearchHit: Sendable, Equatable, Identifiable {
        public let conversationID: String
        public let localID: UInt64
        public let snippet: String
        public let timestamp: Date?
        public let mine: Bool
        public var id: String { "\(conversationID)-\(localID)" }
    }

    /// Case-insensitive substring search over every conversation's DECRYPTED local log — entirely
    /// on-device, because the relay holds only ciphertext and there is deliberately nothing
    /// server-side to ask. Newest first, bounded.
    public func searchMessages(matching rawQuery: String, limit: Int = 50) -> [SearchHit] {
        let query = rawQuery.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !query.isEmpty else { return [] }
        var hits: [SearchHit] = []
        for conversationID in index.conversations.keys {
            guard let client = activeClient(for: conversationID),
                let messages = try? client.messages()
            else { continue }
            for message in messages where !message.deleted && message.secretId == nil {
                let text = String(decoding: message.plaintext, as: UTF8.self)
                let name = message.attachment?.filename ?? ""
                guard text.lowercased().contains(query) || name.lowercased().contains(query)
                else { continue }
                hits.append(
                    SearchHit(
                        conversationID: conversationID,
                        localID: message.localId,
                        snippet: text.isEmpty ? name : text,
                        timestamp: Self.timestamp(message.createdAtMs),
                        mine: message.direction == .outbound))
            }
        }
        return Array(
            hits.sorted { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
                .prefix(limit))
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

    // MARK: Replies, reactions, typing, receipts

    /// Send a message answering another. Same upload path as any message, so a reply that fails is
    /// retried like one.
    public func sendReply(_ body: String, replyTo: String, in conversationID: String) async throws {
        guard let client = activeClient(for: conversationID) else {
            throw CoordinatorError.noSessionForConversation
        }
        guard let target = Hex.decode(replyTo), target.count == 16 else {
            throw CoordinatorError.unknownMessage
        }
        let localID = try client.sendReply(body: Data(body.utf8), replyTo: target)
        defer { refresh(conversationID) }
        try await upload(localID: localID, client: client, conversationID: conversationID)
    }

    /// Add or remove one reaction.
    public func react(
        _ messageID: String, emoji: String, remove: Bool, in conversationID: String
    ) async throws {
        guard let client = activeClient(for: conversationID) else {
            throw CoordinatorError.noSessionForConversation
        }
        guard let target = Hex.decode(messageID), target.count == 16 else {
            throw CoordinatorError.unknownMessage
        }
        let localID = try client.react(target: target, emoji: emoji, remove: remove)
        defer { refresh(conversationID) }
        try await upload(localID: localID, client: client, conversationID: conversationID)
    }

    /// Tell the conversation whether this user is typing, THROTTLED.
    ///
    /// A typing indicator is a message like any other: it is encrypted, fanned out to every member
    /// device, and stored until acknowledged. Sending one per keystroke would turn a sentence into
    /// dozens of envelopes for every recipient — so a "started" is repeated at most every
    /// `typingInterval`, and a "stopped" is always sent (it is what clears the indicator).
    public func setTyping(_ active: Bool, in conversationID: String) async {
        guard let client = activeClient(for: conversationID) else { return }
        if active {
            let last = lastTypingSent[conversationID] ?? .distantPast
            guard Date().timeIntervalSince(last) > Self.typingInterval else { return }
            lastTypingSent[conversationID] = Date()
        } else {
            guard lastTypingSent[conversationID] != nil else { return }  // never started
            lastTypingSent.removeValue(forKey: conversationID)
        }
        // Best effort: a lost typing hint is not worth an error, and the receiver expires it.
        guard let localID = try? client.sendTyping(active: active) else { return }
        try? await upload(localID: localID, client: client, conversationID: conversationID)
    }

    private static let typingInterval: TimeInterval = 4
    private var lastTypingSent: [String: Date] = [:]

    /// Acknowledge what has arrived: `Delivered` for everything decrypted here, `Read` for what the
    /// user has actually seen. Batched and recorded, so one message is acknowledged once and not on
    /// every sync.
    ///
    /// Receipts are a privacy choice, not a protocol requirement: `sendReceipts` off means this
    /// device tells nobody what it has seen, and everything else still works.
    public func sendPendingReceipts(in conversationID: String) async {
        guard sendReceipts, let client = activeClient(for: conversationID) else { return }
        for kind in [ReceiptKindFfi.delivered, .read] {
            guard let owed = try? client.unacknowledged(kind: kind), !owed.isEmpty else { continue }
            guard let localID = try? client.sendReceipt(kind: kind, messageIds: owed) else { continue }
            do {
                try await upload(localID: localID, client: client, conversationID: conversationID)
            } catch {
                lastSyncError = error
            }
        }
    }

    /// The user is looking at the conversation: everything in it is read.
    /// `async` so the receipt it triggers is part of this call rather than an untracked task:
    /// "the user read it" and "the sender was told" should not be able to drift apart, and an
    /// unordered fire-and-forget makes that impossible to observe or test.
    public func markRead(_ conversationID: String) async {
        guard let client = activeClient(for: conversationID) else { return }
        try? client.markRead()
        refresh(conversationID)
        // Reading is what a read receipt reports, so it is sent from here — never from merely
        // receiving a message.
        await sendPendingReceipts(in: conversationID)
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
                    let result = try client.processInbound(
                        envelopeId: UInt64(envelope.id), ciphertext: bytes)
                    // Typing is the one result that is not about stored state: surface it now,
                    // because there is nothing in the log for a later refresh to find.
                    if case .typing(let sender, let active) = result {
                        model.noteTyping(
                            Hex.encode(sender), active: active, in: conversationID)
                    }
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
        for conversationID in touched {
            refresh(conversationID)
            // Everything that decrypted here is now owed a delivered receipt.
            await sendPendingReceipts(in: conversationID)
        }
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
        guard isActive else { return nil } // stopped: never re-open a store we just released
        guard let storeID = index.conversations[conversationID],
            let opened = try? MlsClient.open(dbPath: path(storeID), atRestKey: try keyProvider(storeID)),
            (try? opened.isPending()) == false
        else { return nil }
        clients[conversationID] = opened
        return opened
    }

    private func lobbyClient(_ storeID: String) -> MlsClient? {
        if let existing = lobbyClients[storeID] { return existing }
        guard isActive else { return nil }
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
        guard let client = activeClient(for: conversationID) else { return }
        // Disappearing messages: anything past its expiry goes before it is rendered. Cheap when
        // nothing expired (no commit), so it simply rides every refresh.
        _ = try? client.scrubExpired()
        model.disappearTimers[conversationID] = (try? client.disappearTimer()) ?? 0
        guard let stored = try? client.messages() else { return }

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
            let kind: ThreadLine.Kind =
                if let attachment = message.attachment {
                    .attachment(
                        AttachmentLine(
                            blobID: Hex.encode(attachment.blobId),
                            mime: attachment.mime,
                            filename: attachment.filename,
                            size: attachment.size,
                            caption: String(decoding: message.plaintext, as: UTF8.self)))
                } else {
                    .text(String(decoding: message.plaintext, as: UTF8.self))
                }
            return ThreadLine(
                id: message.localId,
                kind: kind,
                mine: mine,
                timestamp: timestamp,
                isPending: message.pending,
                // An all-zero id means "logged before ids existed": surfaced as empty, so the UI
                // withholds reply/react rather than offering an action that cannot work.
                messageID: message.messageId.allSatisfy { $0 == 0 }
                    ? "" : Hex.encode(message.messageId),
                replyTo: message.replyTo.map { Hex.encode($0) },
                reactions: Self.summarize(message.reactions, me: identity),
                deliveredCount: Int(message.deliveredCount),
                readCount: Int(message.readCount),
                deleted: message.deleted)
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

    /// Group reactions by emoji for display, marking the ones this device sent so tapping toggles
    /// rather than piling on.
    private static func summarize(_ reactions: [ReactionInfo], me: Data?) -> [ReactionSummary] {
        var order: [String] = []
        var counts: [String: (count: Int, mine: Bool)] = [:]
        for reaction in reactions {
            if counts[reaction.emoji] == nil { order.append(reaction.emoji) }
            let existing = counts[reaction.emoji] ?? (0, false)
            counts[reaction.emoji] = (existing.count + 1, existing.mine || reaction.sender == me)
        }
        return order.map {
            ReactionSummary(emoji: $0, count: counts[$0]!.count, includesMe: counts[$0]!.mine)
        }
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
        /// A message id that is not 16 bytes, so it names nothing.
        case unknownMessage
        /// Account ids that could not be added (no prekey, or delivery failed).
        case membersNotSetUp([String])
    }
}
