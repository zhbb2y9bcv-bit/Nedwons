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
    /// The cover-traffic scheduler (R-204), non-nil only while cover traffic is enabled AND the
    /// receive loop is running. Sends decoys on a randomized cadence.
    private var coverTask: Task<Void, Never>?
    /// The cross-process single-writer lock over the (possibly shared) store directory. Held from
    /// `start()` to `stop()`; the notification extension takes it non-blockingly while we're away.
    private var storeLock: StoreLock?
    /// False only between `stop()` and the next `start()`: a still-unwinding loop iteration must
    /// not re-open stores that were just closed and unlocked. True from construction so direct
    /// (test/tool) use without a receive loop still works.
    private var isActive = true
    /// The most recent background failure, for diagnostics; the UI shows banners on user actions.
    public private(set) var lastSyncError: Error?
    /// Whether this device tells senders when the user has READ their message. A privacy choice,
    /// not a protocol requirement. Delivery receipts are always sent (a sender should be able to see
    /// their message arrived); when this is off, only READ receipts are withheld — reading is no
    /// longer something anyone else is told. Driven by the Settings toggle via `model`.
    public var sendReadReceipts = true
    /// Whether this device broadcasts typing indicators. A privacy choice, driven by the Settings
    /// toggle via `model`; when off, `setTyping` sends nothing.
    public var sendTypingIndicators = true
    /// Sealed-sender key material (ADR-0014 2c): our own `K_r` and the grants contacts gave us.
    /// `nil` disables sealed sending entirely and everything falls back to identified delivery.
    public var deliveryKeys: DeliveryKeyStore?
    /// Our own device ids, learned once per session — a grant carries them so contacts can fan a
    /// sealed message out to every device of ours.
    private var myDeviceIDs: [String] = []
    /// True once this session registered our delivery verifier with the relay.
    private var deliveryKeyRegistered = false
    /// Resolves this device's **enrolled** signing key, which signs ADR-0010 membership manifests —
    /// the same key the server verified at registration and published in the transparency log, so
    /// every membership change is attributable to a specific device by anyone auditing the log.
    ///
    /// A closure rather than a stored signer because the key is provisioned at registration/sign-in,
    /// *after* the object graph is built: a value captured at construction would always be nil.
    /// Injectable so tests can supply a software signer.
    public var membershipSignerProvider: (@MainActor @Sendable () -> (any DeviceSigner)?)?
    /// Resolves the pinned transparency-log key, so an inbound manifest is verified against the
    /// **logged** actor key rather than one the server merely asserts. Same lazy reasoning.
    public var pinnedLogKeyProvider: (@Sendable () async throws -> Data)?

    /// The signer for membership manifests: an injected provider if one was set, otherwise the
    /// device's enrolled key straight from the model.
    ///
    /// The fallback is the fix for a real failure. A coordinator built without an explicit provider
    /// used to be unable to add anyone — silently, inside a swallowed error — which is exactly what
    /// happened to a live harness the moment new conversations became authoritative. The model
    /// always knows the enrolled key for a signed-in user, so there is no reason a coordinator
    /// should be able to exist without it. An explicit provider is now only for harnesses whose
    /// session was minted with a synthetic identity the model has never seen.
    private func membershipSigner() -> (any DeviceSigner)? {
        membershipSignerProvider?() ?? model.enrolledDeviceSigner()
    }

    /// Same shape for the pinned log key: injected, else the model's (configured or trust-on-first-
    /// use), so verification of inbound membership never silently has nothing to verify against.
    private func pinnedLogKey() async throws -> Data {
        if let provider = pinnedLogKeyProvider { return try await provider() }
        return try await model.currentPinnedLogKey()
    }

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
        model.reconcileMembershipAction = { [weak self] in
            await self?.reconcileSetup()
        }
        model.renameGroupAction = { [weak self] conversationID, name in
            guard let self else { throw CoordinatorError.notSignedIn }
            try await self.renameGroup(conversationID, to: name)
        }
        model.setGroupAvatarAction = { [weak self] thumbnail, conversationID in
            guard let self else { throw CoordinatorError.notSignedIn }
            try await self.setGroupAvatar(thumbnail, in: conversationID)
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
        model.editMessageAction = { [weak self] messageID, newBody, conversationID in
            guard let self else { throw CoordinatorError.notSignedIn }
            try await self.editMessage(messageID: messageID, newBody: newBody, in: conversationID)
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
        model.coverTrafficControl = { [weak self] enabled in
            self?.setCoverTraffic(enabled)
        }
        model.didBlockAction = { [weak self] accountID in
            await self?.revokeSealedAccess(for: accountID)
        }
        model.readReceiptsControl = { [weak self] enabled in
            self?.sendReadReceipts = enabled
        }
        model.typingIndicatorControl = { [weak self] enabled in
            self?.sendTypingIndicators = enabled
        }
        // Apply the persisted choices now, before any receipt is owed or a keystroke is typed.
        sendReadReceipts = model.readReceiptsEnabled
        sendTypingIndicators = model.typingIndicatorsEnabled
    }

    /// Begin the receive loop for the signed-in session. Idempotent.
    public func start() {
        guard receiveTask == nil else { return }
        isActive = true
        // Resume cover traffic if the user left it on. (No-op if disabled.)
        if model.coverTrafficEnabled { setCoverTraffic(true) }
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
                    await self.grantDeliveryKeysIfNeeded()
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
        coverTask?.cancel()
        coverTask = nil
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
        // Sealed sender: publish our verifier, then hand our key to contacts who don't have it.
        await ensureDeliveryKeyRegistered()
        await grantDeliveryKeysIfNeeded()
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

        // Departures first, batched per conversation. An account is present in the group through
        // every device it enrolled, so putting it out is ONE commit naming them all — not one epoch
        // per device, with the account half-removed in between and a fresh chance to lose the epoch
        // CAS at each step.
        let departures = Dictionary(grouping: targets.filter(\.removal), by: \.conversationID)
        for conversationID in departures.keys.sorted() {
            guard let group = departures[conversationID],
                let client = activeClient(for: conversationID)
            else { continue }
            var claimed: [SetupTarget] = []
            for target in group {
                if (try? await relay.claimSetup(
                    accessToken: token, conversationID: conversationID,
                    deviceID: target.deviceID)) == true
                {
                    claimed.append(target)
                }
            }
            guard !claimed.isEmpty else { continue }
            do {
                try await removeByCommit(
                    conversationID: conversationID, targets: claimed, client: client)
                touched.insert(conversationID)
            } catch {
                lastSyncError = error
                noteIfUnrecoverable(error)
            }
        }

        for target in targets.filter({ !$0.removal }).prefix(limit) {
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
                if target.authoritative {
                    // ADR-0010: the target is NOT a routing member yet — it holds a membership
                    // *intent*. The signed commit we post is what creates its routing membership,
                    // delivers its Welcome, and moves every existing member to the next epoch, all
                    // in one server transaction. Nothing is applied locally until the server's epoch
                    // CAS says ours won.
                    try await addByCommit(target: target, keyPackage: keyPackage, client: client)
                } else {
                    // Legacy V27: routing already exists; we deliver the Welcome, confirm, and fan
                    // the commit out as ordinary mail for recipients to merge unverified.
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
                }
                // The name and photo live only inside the ciphertext; re-send them so the
                // newcomer's list shows the real group. Best-effort — the next change fixes a miss.
                if let name = (try? client.groupName()) ?? nil {
                    try? await sendGroupName(name, client: client, conversationID: target.conversationID)
                }
                if let avatar = (try? client.groupAvatar()) ?? nil, !avatar.isEmpty {
                    if let localID = try? client.setGroupAvatar(image: avatar) {
                        try? await upload(
                            localID: localID, client: client,
                            conversationID: target.conversationID)
                    }
                }
                touched.insert(target.conversationID)
            } catch {
                // No prekey yet (deferred add), a lost epoch race, or a transient failure: the claim
                // expires and the target is retried on a later sync — here or on another member's
                // device. Nothing partial was applied either way.
                lastSyncError = error
                noteIfUnrecoverable(error)
            }
        }
        for conversationID in touched { refresh(conversationID) }
    }

    // MARK: MLS-commit-authoritative membership (ADR-0010, R-506)

    /// Add one intended device with a **signed membership commit**, the only way routing membership
    /// changes in an authoritative conversation.
    ///
    /// The order is the whole point: stage locally (no epoch advance, nothing persisted) → ask the
    /// server to accept the signed manifest → merge only if it did. That way the relay's routing set
    /// and this device's MLS state move together or not at all. On refusal the staged commit is
    /// discarded rather than merged — merging a commit the server refused IS the divergence R-506
    /// exists to prevent.
    private func addByCommit(target: SetupTarget, keyPackage: Data, client: MlsClient) async throws {
        guard let token else { throw CoordinatorError.notSignedIn }
        guard let signer = membershipSigner() else {
            throw CoordinatorError.noMembershipSigner
        }
        guard let actorDevice = identity,
            let addedAccount = Hex.decode(target.accountID),
            let addedDevice = Hex.decode(target.deviceID)
        else { throw CoordinatorError.badKeyPackage }

        let prevEpoch = try client.epoch()
        let staged = try client.stageAdd(keyPackage: keyPackage)
        let change = MembershipChange(
            control: .add, prevEpoch: prevEpoch,
            added: [(account: addedAccount, device: addedDevice)], removed: [],
            commit: staged.commit, welcomes: [staged.welcome])
        let outcome = try await relay.commitMembership(
            accessToken: token, conversationID: target.conversationID, actorDevice: actorDevice,
            change: change, idempotencyKey: Self.randomKey(),
            ttlSeconds: Self.manifestTTLSeconds, signer: signer)
        try applyCommitOutcome(outcome, client: client)
    }

    /// Carry out authorized departures with one **remove commit**.
    ///
    /// Whoever syncs first does this, not necessarily an admin and never the person leaving: MLS
    /// refuses a commit that removes the committer's own leaf, so a leaver cannot evidence their own
    /// departure. The relay recorded the authorization (an admin's removal, or the account's own
    /// leave) as a removal intent and already purged that account's queued mail; this turns it into
    /// the cryptographic removal — new mail stops, and post-removal secrecy becomes MLS's job.
    ///
    /// The manifest's `removed` list is sorted and duplicate-free because that is part of the
    /// canonical encoding the server re-derives before checking our signature.
    private func removeByCommit(
        conversationID: String, targets: [SetupTarget], client: MlsClient
    ) async throws {
        guard let token else { throw CoordinatorError.notSignedIn }
        guard let signer = membershipSigner() else {
            throw CoordinatorError.noMembershipSigner
        }
        guard let actorDevice = identity else { throw CoordinatorError.notSignedIn }
        let removed = targets.compactMap { Hex.decode($0.deviceID) }
            .sorted { $0.lexicographicallyPrecedes($1) }
        guard removed.count == targets.count, !removed.isEmpty else {
            throw CoordinatorError.badKeyPackage
        }

        let prevEpoch = try client.epoch()
        let commit = try client.stageRemoveMany(identities: removed)
        let change = MembershipChange(
            control: .remove, prevEpoch: prevEpoch, added: [], removed: removed,
            commit: commit, welcomes: [])
        let outcome = try await relay.commitMembership(
            accessToken: token, conversationID: conversationID, actorDevice: actorDevice,
            change: change, idempotencyKey: Self.randomKey(),
            ttlSeconds: Self.manifestTTLSeconds, signer: signer)
        try applyCommitOutcome(outcome, client: client)
    }

    /// Merge or discard the staged commit according to what the server did with it. The refusal
    /// cases all cost us the prekey we claimed — an accepted price for never merging a change the
    /// relay did not record; the target's claim expires and a later pass rebuilds from the new epoch.
    private func applyCommitOutcome(
        _ outcome: MembershipCommitOutcome, client: MlsClient
    ) throws {
        switch outcome {
        case .applied, .alreadyApplied:
            // `alreadyApplied` means the server holds this exact manifest under this exact
            // idempotency key — the same durable state `applied` produces, so merging is right.
            try client.mergeStaged()
        case .staleEpoch:
            try client.clearStaged()
            throw CoordinatorError.membershipRaceLost
        case .forbidden, .idempotencyConflict:
            try client.clearStaged()
            throw CoordinatorError.membershipRefused
        }
    }

    /// Process an inbound envelope the relay tagged as an ADR-0010 membership commit. Verification
    /// happens **before** the merge and in two independent halves:
    ///
    /// 1. **Signature** — the manifest must be signed by the actor's device key *as published in the
    ///    transparency log*, checked under our pinned log key (`verifyIncomingMembershipEvent`), so
    ///    a server cannot mint a membership change or substitute a key it never logged.
    /// 2. **Correspondence** — the staged commit's real adds/removes must equal what the manifest
    ///    claimed (`processCommit`), so a *valid member* whose manifest lies changes nothing here.
    ///
    /// A refusal is not recoverable and is not meant to be: OpenMLS consumes a commit's decryption
    /// secret on processing, so the same bytes can never be re-processed. We are desynced by
    /// construction and rejoin by being re-added at a new epoch (ADR-0010's v1 resync rule).
    ///
    /// Returns true when the envelope is consumed (ack it either way — a commit we refuse can never
    /// become processable later, and leaving it would wedge the queue).
    private func processMembershipCommit(
        conversationID: String, epoch: UInt64, ciphertext: Data, client: MlsClient
    ) async -> Bool {
        guard let token else { return false }
        guard let pinnedLogKey = try? await pinnedLogKey() else {
            // With no pinned log key we cannot tell the actor's real device key from a server-chosen
            // one, and an unverified merge is exactly what R-506 forbids. Leave it unacked so a
            // later sync — once the key is available — can still verify and merge it.
            lastSyncError = CoordinatorError.noPinnedLogKey
            return false
        }
        do {
            let verdict = try await relay.verifyIncomingMembershipEvent(
                accessToken: token, conversationID: conversationID, epoch: epoch,
                pinnedLogPublicKeyX963: pinnedLogKey)
            guard case .verified(let added, let removed, let nextEpoch) = verdict else {
                model.noteSecurityEvent(
                    "A membership change in this group could not be verified and was rejected.")
                lastSyncError = CoordinatorError.membershipUnverified
                return true
            }
            try client.processCommit(
                envelope: ciphertext, nextEpoch: nextEpoch, added: added, removed: removed)
            return true
        } catch {
            // Either the correspondence check failed (a lying committer — the group's crypto state
            // simply does not follow the lie) or the fetch failed. Both leave local state untouched.
            model.noteSecurityEvent(
                "A membership change in this group did not match its signed description and was "
                    + "rejected.")
            lastSyncError = error
            return true
        }
    }

    /// How long a membership manifest is accepted in transit. Short: the epoch CAS is the real
    /// anti-replay, and this only bounds how long a captured manifest is worth anything.
    private static let manifestTTLSeconds: UInt64 = 300

    /// Most reconcile failures are ordinary and self-healing — no prekey published yet, a lost epoch
    /// race, a dropped connection — and retry on the next sync, so they stay in `lastSyncError` for
    /// diagnostics and out of the user's way.
    ///
    /// Missing an enrolled signer is not like that. Every membership change in an authoritative
    /// conversation needs one, so without it nobody is ever added and retrying forever changes
    /// nothing. Since new conversations are authoritative, that would look like invited people
    /// silently never arriving — so it is surfaced instead of retried in silence.
    private func noteIfUnrecoverable(_ error: Error) {
        guard case CoordinatorError.noMembershipSigner = error else { return }
        model.noteSecurityEvent(
            "This device can't sign membership changes, so people can't be added to or removed "
                + "from groups here. Signing in again on this device should restore it.")
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

    /// Set (or with nil remove) the group photo for everyone — E2EE, ordinary upload path.
    public func setGroupAvatar(_ thumbnail: Data?, in conversationID: String) async throws {
        guard let client = activeClient(for: conversationID) else {
            throw CoordinatorError.noSessionForConversation
        }
        let localID = try client.setGroupAvatar(image: thumbnail ?? Data())
        defer { refresh(conversationID) }
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

    /// Replace the text of the user's OWN message. The core refuses anyone else's message and
    /// recipients refuse a non-author's edit independently; every applied edit is visibly marked.
    public func editMessage(messageID: String, newBody: String, in conversationID: String) async throws {
        guard let client = activeClient(for: conversationID),
            let target = Hex.decode(messageID)
        else { throw CoordinatorError.noSessionForConversation }
        let localID = try client.editMessage(target: target, body: Data(newBody.utf8))
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
            guard let client = activeClient(for: conversationID) else { continue }
            let messages = allMessages(in: client)
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

    /// The FULL history of one conversation, paged out of the core (hot window + R-105 archive).
    /// Used by scans that must see everything — attachment-key lookup, search. Live rendering
    /// never calls this; it reads the hot window.
    private func allMessages(in client: MlsClient) -> [StoredMessage] {
        var out: [StoredMessage] = []
        var offset: UInt64 = 0
        while let page = try? client.messagesPage(offset: offset, limit: 256), !page.isEmpty {
            out.append(contentsOf: page)
            offset += UInt64(page.count)
        }
        return out
    }

    /// The reference (with its key) as stored in whichever conversation's log carries this blob.
    /// Read from local state, never from the network: the key must come from the message the group
    /// sent, not from anything the relay could influence.
    private func attachmentReference(_ blobID: String) -> AttachmentInfo? {
        for conversationID in index.conversations.keys {
            guard let client = activeClient(for: conversationID) else { continue }
            let messages = allMessages(in: client)
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
        guard sendTypingIndicators else { return }
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
    /// Receipts are a privacy choice, not a protocol requirement. Delivery is always acknowledged;
    /// READ receipts are withheld when the user has turned them off — so a sender can still see a
    /// message arrived, but never that it was read.
    public func sendPendingReceipts(in conversationID: String) async {
        guard let client = activeClient(for: conversationID) else { return }
        for kind in [ReceiptKindFfi.delivered, .read] {
            if kind == .read && !sendReadReceipts { continue }
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

    // MARK: Sealed sender (ADR-0014 slice 2c)

    /// Make sure the relay holds the verifier for our current `K_r`, so approved contacts can
    /// deliver to us sealed. Idempotent per session; quiet on failure (retried next sync — until it
    /// succeeds we simply keep receiving identified mail).
    func ensureDeliveryKeyRegistered() async {
        guard let token, let keys = deliveryKeys, !deliveryKeyRegistered else { return }
        do {
            try await relay.registerDeliveryAccessKey(
                accessToken: token, deliveryKey: keys.mineOrCreate())
            if myDeviceIDs.isEmpty {
                myDeviceIDs = try await relay.myDeviceIDs(accessToken: token)
            }
            deliveryKeyRegistered = true
        } catch {
            lastSyncError = error
        }
    }

    /// Hand our `K_r` (and our own device ids) to each 1:1 contact we haven't granted yet, over the
    /// E2EE channel — the relay never sees either. Only 1:1 conversations: a grant names ONE
    /// account's key, and in a group there is no single peer to attribute it to.
    func grantDeliveryKeysIfNeeded() async {
        guard let token, let keys = deliveryKeys, deliveryKeyRegistered else { return }
        let mine = keys.mineOrCreate()
        let devices = myDeviceIDs.compactMap { Hex.decode($0) }
        for conversationID in index.conversations.keys.sorted() {
            guard let peer = peerAccount(of: conversationID), !keys.hasGranted(to: peer),
                let client = activeClient(for: conversationID)
            else { continue }
            do {
                let localID = try client.enqueueDeliveryKeyGrant(
                    keyR: mine.key, deviceIds: devices)
                try await upload(localID: localID, client: client, conversationID: conversationID)
                keys.markGranted(to: peer)
            } catch {
                lastSyncError = error  // retried on a later sync
            }
        }
        _ = token
    }

    /// The other account in a 1:1 conversation, or nil for a group (or one we can't resolve).
    private func peerAccount(of conversationID: String) -> String? {
        guard let me = model.session?.accountID,
            let conversation = model.conversations.first(where: {
                $0.conversationID == conversationID
            })
        else { return nil }
        let others = conversation.memberAccountIDs.filter { $0 != me }
        return others.count == 1 ? others.first : nil
    }

    /// Whether this conversation's message can go out sealed: a 1:1 with a contact whose grant we
    /// hold. Anything else (a group, or a contact who never granted us) takes the identified path.
    private func sealedRecipients(for conversationID: String) -> (DeliveryGrant, DeliveryAccessKey)? {
        guard let keys = deliveryKeys, let peer = peerAccount(of: conversationID),
            let grant = keys.grant(from: peer), grant.key != nil
        else { return nil }
        return (grant, keys.mineOrCreate())
    }

    /// Client-side per-device fan-out of one ciphertext: every device of the peer (under THEIR
    /// `K_r`) and every other device of ours (under our own), so our siblings still get the
    /// message. Throws if any delivery fails, so the caller can fall back to identified delivery
    /// rather than losing the message.
    private func deliverSealedToAll(
        ciphertext: Data, grant: DeliveryGrant, mine: DeliveryAccessKey, localID: UInt64,
        conversationID: String
    ) async throws {
        guard let peerKey = grant.key else { throw CoordinatorError.notSignedIn }
        for device in grant.deviceIDs {
            try await relay.deliverSealed(
                deliveryKey: peerKey, recipientDevice: device, ciphertext: ciphertext,
                idempotencyKey: Self.idempotencyKey(conversationID: conversationID, localID: localID))
        }
        for device in myDeviceIDs where device != model.session?.deviceID {
            try await relay.deliverSealed(
                deliveryKey: mine, recipientDevice: device, ciphertext: ciphertext,
                idempotencyKey: Self.idempotencyKey(conversationID: conversationID, localID: localID))
        }
    }

    /// Blocking someone must also revoke their sealed access: rotate `K_r` (which invalidates every
    /// holder at the relay), forget their grant, and let the next sync re-grant everyone else.
    public func revokeSealedAccess(for blockedAccount: String) async {
        guard let token, let keys = deliveryKeys else { return }
        let rotation = SealedSenderPolicy.rotateOnBlock(
            approvedContacts: keys.grantedKeys(), blocking: blockedAccount)
        do {
            try await relay.registerDeliveryAccessKey(
                accessToken: token, deliveryKey: rotation.newKey)
            keys.rotateMine(to: rotation.newKey)
            keys.forgetGrant(from: blockedAccount)
            await grantDeliveryKeysIfNeeded()  // re-grant the remaining contacts
        } catch {
            lastSyncError = error
        }
    }

    // MARK: Cover traffic (R-204)

    /// The decoy cadence: a fresh random gap in this range before each cover send. Deliberately
    /// coarse — cover traffic here raises the cost of timing analysis without the battery/data cost
    /// (and the collateral traffic to contacts) of a tight constant rate. Honest scope: this is not
    /// enough to defeat a global passive adversary; see ADR-0014 (R-204).
    private static let coverGapSeconds: ClosedRange<UInt64> = 90...420

    /// Start or stop the decoy scheduler. Idempotent; only runs while the receive loop is active.
    func setCoverTraffic(_ enabled: Bool) {
        coverTask?.cancel()
        coverTask = nil
        guard enabled, isActive else { return }
        coverTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                let gap = UInt64.random(in: Self.coverGapSeconds)
                try? await Task.sleep(nanoseconds: gap * 1_000_000_000)
                if Task.isCancelled { return }
                await self.sendCoverDecoy()
            }
        }
    }

    /// Send one decoy into a randomly chosen conversation. The padding length is drawn so the decoy
    /// lands in a plausible envelope size bucket (arc J), making it indistinguishable to the relay
    /// from a real message. Best-effort and silent: a decoy that fails to send is simply skipped.
    private func sendCoverDecoy() async {
        guard token != nil, isActive else { return }
        // Only conversations whose composer isn't locked (a muted member can't send anyway).
        let candidates = index.conversations.keys.filter { model.composerLock(for: $0) == nil }
        guard let conversationID = candidates.randomElement(),
            let client = activeClient(for: conversationID)
        else { return }
        // Random size within the normal body range, so bucketed envelopes look like real chatter.
        // The bytes are discarded on arrival, so ordinary randomness is enough — no need for the
        // CSPRNG, and the content is meaningless either way.
        let padLen = Int.random(in: 0...512)
        let padding = Data((0..<padLen).map { _ in UInt8.random(in: 0...255) })
        do {
            let localID = try client.sendCover(padding: padding)
            try await upload(localID: localID, client: client, conversationID: conversationID)
        } catch {
            lastSyncError = error
        }
    }

    /// The upload half of a send. `encrypt` is idempotent in the core (cached ciphertext), and the
    /// idempotency key is a pure function of (conversation, local id), so a retry of a send whose
    /// response was lost is deduplicated by the relay instead of delivered twice.
    private func upload(localID: UInt64, client: MlsClient, conversationID: String) async throws {
        guard let token else { throw CoordinatorError.notSignedIn }
        let ciphertext = try client.encrypt(localId: localID)
        // Sealed when we can: a 1:1 contact whose K_r we hold. The relay then stores the envelope
        // with NO sender. If any sealed delivery fails we fall back to the identified path rather
        // than lose the message — privacy is best-effort here, delivery is not.
        if let (grant, mine) = sealedRecipients(for: conversationID) {
            do {
                try await deliverSealedToAll(
                    ciphertext: ciphertext, grant: grant, mine: mine, localID: localID,
                    conversationID: conversationID)
                try client.markSent(localId: localID)
                return
            } catch {
                lastSyncError = error
            }
        }
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
                // ADR-0010 membership commits are NOT ordinary mail: they must be verified against
                // their signed manifest before they may advance this group's state, so they never
                // reach `processInbound`.
                if let epoch = envelope.membershipEpoch {
                    if await processMembershipCommit(
                        conversationID: conversationID, epoch: epoch, ciphertext: bytes,
                        client: client)
                    {
                        touched.insert(conversationID)
                        acked.append(envelope.id)
                    }
                    continue
                }
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
                    // A contact handing us their sealed-sender key (and their devices), so we can
                    // seal to them from here on. Grants ride the ordinary E2EE path.
                    if case .deliveryKeyGranted(let keyR, let deviceIDs) = result,
                        let peer = peerAccount(of: conversationID)
                    {
                        storeGrant(keyR: keyR, deviceIDs: deviceIDs, from: peer)
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
        // Sealed envelopes (ADR-0014): no sender AND no conversation id, so we resolve the
        // conversation by trying each store. A failed decrypt is inert — proven in the core — so
        // probing cannot corrupt a store it does not belong to, and the id is not burned.
        var sealedAcked: [Int] = []
        for envelope in envelopes.sorted(by: { $0.id < $1.id }) where envelope.sealed {
            guard let bytes = Hex.decode(envelope.ciphertext) else {
                sealedAcked.append(envelope.id)
                continue
            }
            if let conversationID = processSealed(envelopeID: envelope.id, ciphertext: bytes) {
                touched.insert(conversationID)
            }
            // Acked either way: nothing that failed every store can ever be processed later, and a
            // sealed envelope from someone we blocked is meant to go nowhere.
            sealedAcked.append(envelope.id)
        }
        if !sealedAcked.isEmpty {
            try await relay.ackSealed(accessToken: token, sealedIDs: sealedAcked)
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

    /// Resolve a sealed envelope to a conversation by trying each store, returning the conversation
    /// it belonged to (nil if none could decrypt it).
    ///
    /// **Recipient-side block-drop happens here, before any state changes:** a store whose peer we
    /// have blocked is never even probed, so a sealed message from a blocked contact decrypts
    /// nowhere and is discarded. Doing it this way — rather than deleting after the fact — means a
    /// blocked sender's message never enters the log at all. (The primary control is still the
    /// relay-side one: blocking rotates `K_r`, which revokes their ability to deliver sealed.)
    private func processSealed(envelopeID: Int, ciphertext: Data) -> String? {
        let blocked = Set(model.blocked.map(\.accountID))
        for conversationID in index.conversations.keys.sorted() {
            if let peer = peerAccount(of: conversationID),
                SealedSenderPolicy.shouldDropDecrypted(
                    verifiedSenderAccountID: peer, blocked: blocked)
            {
                continue  // blocked: do not even try
            }
            guard let client = activeClient(for: conversationID) else { continue }
            guard
                let result = try? client.processSealedInbound(
                    envelopeId: UInt64(envelopeID), ciphertext: ciphertext)
            else { continue }
            if case .typing(let sender, let active) = result {
                model.noteTyping(Hex.encode(sender), active: active, in: conversationID)
            }
            // A contact handing us their K_r: remember it (and their devices) so we can seal back.
            if case .deliveryKeyGranted(let keyR, let deviceIDs) = result,
                let peer = peerAccount(of: conversationID)
            {
                storeGrant(keyR: keyR, deviceIDs: deviceIDs, from: peer)
            }
            return conversationID
        }
        return nil
    }

    /// Persist a contact's delivery grant so we can send them sealed messages.
    private func storeGrant(keyR: Data, deviceIDs: [Data], from account: String) {
        deliveryKeys?.storeGrant(
            DeliveryGrant(keyHex: Hex.encode(keyR), deviceIDs: deviceIDs.map { Hex.encode($0) }),
            from: account)
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
                deleted: message.deleted,
                senderDeviceID: Hex.encode(message.sender),
                edited: message.edited)
        }
        model.threadLines[conversationID] = lines
        // The group's name lives only inside the ciphertext; this is the one place it is read.
        if let name = (try? client.groupName()) ?? nil {
            model.groupNames[conversationID] = name
        }
        if let avatar = (try? client.groupAvatar()) ?? nil {
            model.groupAvatars[conversationID] = avatar
        } else {
            model.groupAvatars.removeValue(forKey: conversationID)
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
        /// No enrolled device signer, so this device cannot sign an ADR-0010 membership manifest.
        /// It can still receive and verify everyone else's.
        case noMembershipSigner
        /// A concurrent commit won the epoch CAS. Nothing was applied anywhere; rebuild and retry.
        case membershipRaceLost
        /// The relay refused the membership change (governance, or a reused idempotency key).
        case membershipRefused
        /// An inbound membership commit's manifest did not verify against the actor's
        /// transparency-logged device key — refused rather than merged.
        case membershipUnverified
        /// No pinned transparency-log key yet, so an inbound membership commit cannot be verified.
        /// It is left unacked rather than merged unverified.
        case noPinnedLogKey
    }
}
