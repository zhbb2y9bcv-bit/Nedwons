import Foundation
import NedwonsKit
import SwiftUI

/// The root state machine. The UI renders exactly one of these; protected content is unreachable
/// from every phase except `.authenticated`, which is what stops a conversation flashing before
/// session validation finishes.
public enum AppPhase: Equatable, Sendable {
    /// Validating a stored session at launch.
    case booting
    case unauthenticated
    /// A register/login round trip is in flight.
    case authenticating
    case authenticated
    /// A stored session existed but the server rejected it; the user must sign in again.
    case sessionExpired
    /// Local state is unusable (e.g. the enrolled device key is unreadable) and needs recovery.
    case fatalRecoveryRequired(String)
}

/// Observable app state backing the UI. Every button calls one of these async methods against the
/// backend, so the controls are functionally wired, not decorative. Keys go through
/// `DeviceIdentity`, so sign-in reloads the *same* enrolled key rather than signing a fresh one
/// each launch — which is what makes device binding (INV-2) actually hold.
@MainActor
public final class AppModel: ObservableObject {
    @Published public private(set) var phase: AppPhase = .booting
    @Published public var session: NedwonsClient.Session?
    @Published public var myProfile: Profile?
    @Published public var friends: [ProfileSummary] = []
    @Published public var incomingRequests: [ProfileSummary] = []
    @Published public var searchResults: [ProfileSummary] = []
    @Published public var blocked: [ProfileSummary] = []
    @Published public var conversations: [Conversation] = []
    @Published public var inbox: [InboxEnvelope] = []
    @Published public var isBusy = false
    @Published public var banner: String?
    /// Assurance level of the key backing the current session (hardware vs software fallback).
    @Published public var deviceAssurance: DeviceAssurance?

    private let client: NedwonsClient
    private let deviceIdentity: DeviceIdentity
    private let sessionStore: SessionStore

    /// Fail closed by default: a device without a Secure Enclave will **not** silently enroll a
    /// software key. Flip to `.allowSoftwareFallback` only after the user acknowledges the lower
    /// assurance (e.g. from a Settings toggle).
    public var provisionPolicy: DeviceProvisionPolicy = .requireHardware

    public init(
        baseURL: URL,
        pinnedLogKey: Data? = nil,
        deviceIdentity: DeviceIdentity = DeviceIdentity(),
        sessionStore: SessionStore = SessionStore()
    ) {
        client = NedwonsClient(baseURL: baseURL)
        self.pinnedLogKey = pinnedLogKey
        self.deviceIdentity = deviceIdentity
        self.sessionStore = sessionStore
    }

    /// Convenience: construct from the build's `AppConfig` (server URL + out-of-band-pinned
    /// transparency log key). This is what the shipped `@main` uses.
    public convenience init() {
        self.init(baseURL: AppConfig.serverURL, pinnedLogKey: AppConfig.pinnedTransparencyLogKey)
    }

    public var isLoggedIn: Bool { phase == .authenticated && session != nil }

    // MARK: Launch

    /// Launch path. Restores a stored session and validates it against the server before showing
    /// anything protected. A fresh install (no stored session, or no enrolled device key) lands on
    /// `.unauthenticated`; a stored-but-rejected session lands on `.sessionExpired`.
    ///
    /// Device binding is re-checked here, not assumed: a session whose device key is missing from
    /// this device is discarded rather than trusted.
    public func restoreSession() async {
        guard let stored = sessionStore.load() else {
            phase = .unauthenticated
            return
        }
        // A session without its enrolled key on this device is unusable — never resume on it.
        let hasKey: Bool
        do {
            hasKey = try deviceIdentity.loadEnrolled() != nil
        } catch {
            sessionStore.clear()
            phase = .fatalRecoveryRequired(
                "This device's saved key is unreadable. Sign in again to re-enroll this device.")
            return
        }
        guard hasKey else {
            sessionStore.clear()
            phase = .unauthenticated
            return
        }
        do {
            let who = try await client.whoami(accessToken: stored.accessToken)
            guard who.accountID == stored.accountID, who.deviceID == stored.deviceID else {
                sessionStore.clear()
                phase = .sessionExpired
                return
            }
            session = stored
            await loadInitial()
            phase = .authenticated
        } catch NedwonsClient.ClientError.transport {
            // Offline at launch is not an auth failure; keep the session and let the user retry.
            session = stored
            phase = .authenticated
            banner = "You're offline. Showing what's stored on this device."
        } catch {
            sessionStore.clear()
            phase = .sessionExpired
        }
    }

    private var token: String? { session?.accessToken }

    /// Run an async action with busy state + error capture, so callers (buttons) stay tiny.
    private func run(_ action: @escaping () async throws -> Void) async {
        isBusy = true
        defer { isBusy = false }
        do {
            try await action()
        } catch let NedwonsClient.ClientError.http(status, _) {
            banner = errorText(for: status)
        } catch NedwonsClient.ClientError.transport {
            banner = "Can't reach the server. Check your connection."
        } catch DeviceIdentityError.secureHardwareUnavailable {
            banner = "This device has no Secure Enclave, which Nedwons requires to protect your "
                + "key. Use a supported device, or enable a lower-assurance software key in Settings."
        } catch DeviceIdentityError.corruptKeyMaterial {
            banner = "This device's saved key is unreadable. Re-register or recover your account."
        } catch is DeviceIdentityError {
            banner = "Couldn't access this device's secure key store."
        } catch {
            banner = "Something went wrong."
        }
    }

    private func errorText(for status: Int) -> String {
        switch status {
        case 401: "Not authorized."
        case 403: "Not allowed. A block between people here may be preventing this."
        case 409: "That username is taken."
        default: "Request failed (\(status))."
        }
    }

    // MARK: Auth (scaffold uses the software signer; device uses Secure Enclave)

    public func register(username: String, password: String) async {
        phase = .authenticating
        await run { [self] in
            // Enroll (and persist) the device key: Secure Enclave when available, else per policy.
            let enrolled = try deviceIdentity.provision(policy: provisionPolicy)
            deviceAssurance = enrolled.assurance
            let s = try await client.register(
                username: username, password: password, signer: enrolled.signer
            )
            adopt(s)
            if enrolled.assurance == .software {
                banner = "This device has no Secure Enclave — using a lower-assurance software key."
            }
            await loadInitial()
        }
        // `run` swallows failures into `banner`; only a real session advances the phase.
        phase = session == nil ? .unauthenticated : .authenticated
    }

    public func signIn(username: String, password: String) async {
        phase = .authenticating
        await run { [self] in
            // Sign with the SAME key enrolled at registration (INV-2), reloaded from the Keychain.
            // No password-only path: without the enrolled key this device cannot get a session.
            guard let enrolled = try deviceIdentity.loadEnrolled() else {
                banner = "This device isn't enrolled on any account yet. Create an account, or "
                    + "recover an existing one to enroll this device."
                return
            }
            deviceAssurance = enrolled.assurance
            let s = try await client.login(
                username: username, password: password, signer: enrolled.signer
            )
            adopt(s)
            await loadInitial()
        }
        phase = session == nil ? .unauthenticated : .authenticated
    }

    /// Persist + adopt a freshly issued session. The current device is trusted from enrollment.
    private func adopt(_ s: NedwonsClient.Session) {
        session = s
        acknowledgedDeviceIDs = [s.deviceID]
        try? sessionStore.save(s)
    }

    public func signOut() {
        // Clears session state only; the enrolled device key stays in the Keychain so the same
        // device can sign back in (device binding persists across sign-out).
        sessionStore.clear()
        session = nil
        myProfile = nil
        friends = []
        incomingRequests = []
        searchResults = []
        blocked = []
        inbox = []
        conversations = []
        devices = []
        deviceAssurance = nil
        phase = .unauthenticated
    }

    private func loadInitial() async {
        guard let token else { return }
        myProfile = try? await client.myProfile(accessToken: token)
        friends = (try? await client.listFriends(accessToken: token)) ?? []
        incomingRequests = (try? await client.friendRequests(accessToken: token)) ?? []
        blocked = (try? await client.listBlocked(accessToken: token)) ?? []
        conversations = (try? await client.listConversations(accessToken: token)) ?? []
        rememberUsernames(friends + incomingRequests + blocked)
    }

    public func refreshConversations() async {
        await run { [self] in
            guard let token else { return }
            conversations = try await client.listConversations(accessToken: token)
        }
    }

    // MARK: Devices, linking & key-transparency monitoring (#8/#9)

    /// This account's devices (management list).
    @Published public var devices: [DeviceSummary] = []
    /// Sibling devices enrolled but not yet linked into the self-group (candidates to link).
    @Published public var pendingLinkDevices: [String] = []
    /// Result of the last account-level transparency audit (nil until run).
    @Published public var deviceAudit: AccountDeviceAudit?
    /// Devices the user has ACKNOWLEDGED as their own — the trusted expected set the audit compares
    /// the transparency log against. Seeded with the current device on sign-in; the user confirms
    /// others. (A real app persists this locally; here it lives for the session.)
    @Published public var acknowledgedDeviceIDs: Set<String> = []
    /// The out-of-band-pinned transparency log key (fetched once at sign-in in this shell).
    private var pinnedLogKey: Data?

    /// True while a link pass is running (drives the Devices button's spinner).
    @Published public var isLinking = false

    /// Injected by the composition layer that holds the MLS client (`NedwonsAppKit`), which
    /// `NedwonsUI` cannot import. Runs the real `SelfGroupLinker` over this device's `MlsClient`
    /// and returns the sibling ids newly linked. `nil` in the dev shell without an MLS session — the
    /// Devices button then explains linking isn't available in this build. Not `@Sendable`: it may
    /// capture the (non-`Sendable`) `MlsClient`, and it is only ever called here on the main actor.
    public var linkDevicesAction: (() async throws -> [String])?

    public func refreshDevices() async {
        await run { [self] in
            guard let token else { return }
            devices = try await client.listDevices(accessToken: token)
            pendingLinkDevices = try await client.pendingSelfGroupDevices(accessToken: token)
        }
    }

    /// Link every pending sibling into this account's self-group by driving the injected
    /// `SelfGroupLinker` (the same code proven live by `SelfGroupLiveRun`), then refresh the list.
    /// Fail-safe: without a wired linker it just reports that this build can't link.
    public func linkPendingDevices() async {
        guard let linkDevicesAction else {
            banner = "Device linking isn't available in this build."
            return
        }
        isLinking = true
        defer { isLinking = false }
        await run { [self] in
            let linked = try await linkDevicesAction()
            banner =
                linked.isEmpty
                ? "No devices were waiting to link."
                : "Linked \(linked.count) device\(linked.count == 1 ? "" : "s")."
        }
        await refreshDevices()
    }

    /// The user confirms a device is theirs, adding it to the trusted expected set.
    public func acknowledgeDevice(_ deviceID: String) {
        acknowledgedDeviceIDs.insert(deviceID)
    }

    /// Audit the account's logged device set against the acknowledged set (#8). An unexpected logged
    /// device raises the alarm banner.
    public func auditDevices() async {
        await run { [self] in
            guard let token, let account = session?.accountID else { return }
            let pinned = try await currentPinnedLogKey()
            deviceAudit = try await client.auditAccountDevices(
                accessToken: token, accountID: account,
                expectedDeviceIDs: acknowledgedDeviceIDs, pinnedLogPublicKeyX963: pinned)
        }
    }

    /// Register this device's push token so it is woken when not connected (#4).
    public func registerPush(token pushToken: Data) async {
        await run { [self] in
            guard let token else { return }
            try await client.registerPushToken(accessToken: token, token: pushToken)
        }
    }

    private func currentPinnedLogKey() async throws -> Data {
        if let pinnedLogKey { return pinnedLogKey }
        guard let token else { throw NedwonsClient.ClientError.decoding }
        let sth = try await client.transparencySignedTreeHead(accessToken: token)
        guard let key = Hex.decode(sth.logPublicKey) else {
            throw NedwonsClient.ClientError.decoding
        }
        pinnedLogKey = key
        return key
    }

    // MARK: Profile

    public func saveProfile(displayName: String, bio: String) async {
        await run { [self] in
            guard let token else { return }
            try await client.updateProfile(accessToken: token, displayName: displayName, bio: bio)
            myProfile = try await client.myProfile(accessToken: token)
            banner = "Profile saved."
        }
    }

    // MARK: Search & friends

    /// Distinct from `isBusy`: the search field shows its own spinner without disabling the shell.
    @Published public var isSearching = false
    @Published public var searchFailed = false
    private var searchTask: Task<Void, Never>?

    /// Debounced + cancelling. Each keystroke supersedes the previous request, so a slow response
    /// for an old prefix can never overwrite results for the current one.
    public func searchDebounced(_ query: String, delayMs: UInt64 = 250) {
        searchTask?.cancel()
        let trimmed = query.trimmingCharacters(in: .whitespaces)
        guard trimmed.count >= 2 else {
            searchResults = []
            isSearching = false
            searchFailed = false
            return
        }
        isSearching = true
        searchFailed = false
        searchTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: delayMs * 1_000_000)
            guard !Task.isCancelled else { return }
            await self?.search(trimmed)
        }
    }

    public func search(_ query: String) async {
        let trimmed = query.trimmingCharacters(in: .whitespaces)
        guard trimmed.count >= 2, let token else {
            searchResults = []
            isSearching = false
            return
        }
        isSearching = true
        defer { isSearching = false }
        do {
            let results = try await client.searchProfiles(accessToken: token, query: trimmed)
            guard !Task.isCancelled else { return }
            searchResults = Self.prioritizeExactMatch(results, query: trimmed)
            rememberUsernames(searchResults)
            searchFailed = false
        } catch {
            guard !Task.isCancelled else { return }
            searchResults = []
            searchFailed = true
        }
    }

    /// An exact username match sorts first; the backend returns prefix matches alphabetically.
    /// Case-folded because usernames are stored normalized.
    nonisolated static func prioritizeExactMatch(_ results: [ProfileSummary], query: String)
        -> [ProfileSummary]
    {
        let needle = query.lowercased()
        guard let hit = results.firstIndex(where: { $0.username.lowercased() == needle }) else {
            return results
        }
        var reordered = results
        reordered.insert(reordered.remove(at: hit), at: 0)
        return reordered
    }

    public func sendFriendRequest(to accountID: String) async {
        await run { [self] in
            guard let token else { return }
            let status = try await client.sendFriendRequest(accessToken: token, accountID: accountID)
            banner = status == "friended" ? "You're now friends." : "Request sent."
            friends = try await client.listFriends(accessToken: token)
        }
    }

    public func accept(_ accountID: String) async {
        await run { [self] in
            guard let token else { return }
            try await client.acceptFriend(accessToken: token, accountID: accountID)
            friends = try await client.listFriends(accessToken: token)
            incomingRequests = try await client.friendRequests(accessToken: token)
        }
    }

    public func decline(_ accountID: String) async {
        await run { [self] in
            guard let token else { return }
            try await client.declineFriend(accessToken: token, accountID: accountID)
            incomingRequests = try await client.friendRequests(accessToken: token)
        }
    }

    public func refreshFriends() async {
        await run { [self] in
            guard let token else { return }
            friends = try await client.listFriends(accessToken: token)
            incomingRequests = try await client.friendRequests(accessToken: token)
        }
    }

    // MARK: Blocking & reporting

    /// Block an account: the server severs any friendship and refuses future requests.
    public func block(_ accountID: String) async {
        await run { [self] in
            guard let token else { return }
            try await client.blockUser(accessToken: token, accountID: accountID)
            friends = try await client.listFriends(accessToken: token)
            blocked = try await client.listBlocked(accessToken: token)
            banner = "Blocked."
        }
    }

    public func unblock(_ accountID: String) async {
        await run { [self] in
            guard let token else { return }
            try await client.unblock(accessToken: token, accountID: accountID)
            blocked = try await client.listBlocked(accessToken: token)
        }
    }

    /// File an abuse report. `evidence` is only what the user chooses to submit (E2EE-safe).
    public func report(_ accountID: String, reason: String, evidence: String? = nil) async {
        await run { [self] in
            guard let token else { return }
            _ = try await client.reportUser(
                accessToken: token, accountID: accountID, reason: reason, evidence: evidence
            )
            banner = "Report submitted."
        }
    }

    // MARK: Groups

    /// Leave a group: consent withdrawal. The server removes this account from routing and purges
    /// its queued mail for the conversation; the Chats list refreshes without it.
    public func leaveGroup(_ conversationID: String) async {
        await run { [self] in
            guard let token else { return }
            try await client.leaveConversation(accessToken: token, conversationID: conversationID)
            conversations = try await client.listConversations(accessToken: token)
            banner = "You left the group."
        }
    }

    /// Open the 1:1 conversation with `person`, reusing an existing one when present so a second
    /// thread is never created for the same pair. A brand-new conversation goes through the normal
    /// group-creation path, which performs the real MLS setup (key packages, welcome) — there is no
    /// plaintext placeholder conversation at any point.
    public func openDirectConversation(with person: ProfileSummary) async -> ChatSummary? {
        usernamesByAccountID[person.accountID] = person.username

        if let existing = existingDirectConversation(with: person.accountID) {
            // A previously deleted thread is reachable again the moment the user reopens it.
            unhideConversation(existing.conversationID)
            return summary(for: existing, peer: person)
        }
        guard let created = await createGroup(memberAccountIDs: [person.accountID]) else {
            return nil
        }
        await refreshConversations()
        guard let made = conversations.first(where: { $0.conversationID == created }) else {
            return nil
        }
        return summary(for: made, peer: person)
    }

    private func existingDirectConversation(with accountID: String) -> Conversation? {
        conversations.first { conversation in
            let others = conversation.memberAccountIDs.filter { $0 != session?.accountID }
            return others.count == 1 && others.first == accountID
        }
    }

    private func summary(for conversation: Conversation, peer: ProfileSummary) -> ChatSummary {
        ChatSummary(
            conversationID: conversation.conversationID,
            peerAccountID: peer.accountID,
            peerUsername: peer.username,
            memberCount: max(conversation.memberAccountIDs.count, 2),
            lastMessagePreview: localPreview(for: conversation.conversationID),
            lastActivity: localLastActivity(for: conversation.conversationID)
        )
    }

    // MARK: Private aliases (viewer-local, never transmitted)

    /// Injected by the composition layer, which owns the at-rest key. `nil` in previews/tests that
    /// don't exercise aliases; the UI then simply shows real usernames.
    public var aliasStore: ContactAliasStore?

    /// Bumped on every alias mutation so SwiftUI re-renders names without the store being
    /// `ObservableObject` (it is a plain, lockable value store shared with non-UI code).
    @Published public var aliasRevision = 0

    public func alias(for accountID: String) -> String? {
        _ = aliasRevision
        return aliasStore?.alias(for: accountID)
    }

    /// The name shown in lists and headers: the private alias when set, otherwise the real
    /// username. The real username is always displayed on the profile regardless.
    public func displayName(for accountID: String, username: String) -> String {
        alias(for: accountID) ?? username
    }

    @discardableResult
    public func setAlias(_ raw: String, for accountID: String) -> AliasValidation {
        guard let aliasStore else { return .empty }
        let result = aliasStore.setAlias(raw, for: accountID)
        switch result {
        case .valid:
            aliasRevision += 1
            banner = "Renamed for you only."
        case .empty:
            banner = "Enter a name."
        case .tooLong:
            banner = "That name is too long (max \(AliasValidation.maxLength))."
        case .unsafeCharacters:
            banner = "That name contains characters that aren't allowed."
        }
        return result
    }

    public func removeAlias(for accountID: String) {
        aliasStore?.removeAlias(for: accountID)
        aliasRevision += 1
        banner = "Alias removed."
    }

    // MARK: Local display state (never server-supplied)

    /// account id → username, accumulated from profile/friend/search responses. Usernames are a
    /// public lookup handle; the account id remains the only identity used for keys and routing.
    @Published public private(set) var usernamesByAccountID: [String: String] = [:]

    public func username(forAccountID id: String) -> String? { usernamesByAccountID[id] }

    public func rememberUsernames(_ people: [ProfileSummary]) {
        for person in people { usernamesByAccountID[person.accountID] = person.username }
    }

    /// One decrypted-history snapshot per conversation, supplied by the composition layer that owns
    /// the `MlsClient`. The relay never sees these strings — they are generated on device from
    /// already-decrypted local state (INV-1).
    public struct LocalThreadState: Sendable, Equatable {
        public let preview: String?
        public let lastActivity: Date?
        public let unreadCount: Int

        public init(preview: String?, lastActivity: Date?, unreadCount: Int = 0) {
            self.preview = preview
            self.lastActivity = lastActivity
            self.unreadCount = unreadCount
        }
    }

    @Published public var localThreads: [String: LocalThreadState] = [:]

    /// Decrypted, render-ready lines per conversation, published by the composition layer. Held
    /// here rather than fetched from the view so `NedwonsUI` stays free of the MLS core.
    @Published public var threadLines: [String: [ThreadLine]] = [:]

    /// Injected by the composition layer: encrypt + enqueue + send one message. Not `@Sendable`
    /// (captures the non-`Sendable` `MlsClient`); only invoked here on the main actor.
    public var sendMessageAction: ((String, String) async throws -> Void)?

    /// Injected: begin the deliberate reveal of a view-once secret. Never called automatically.
    public var revealSecret: ((Data) -> Void)?

    /// Supplied by the core so the tombstone wording lives in exactly one place.
    public var secretTombstoneText: String = "a secret message has been sent"

    public func sendMessage(_ body: String, to conversationID: String) async {
        let trimmed = body.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        guard let sendMessageAction else {
            banner = "Messaging isn't available in this build."
            return
        }
        do {
            try await sendMessageAction(trimmed, conversationID)
            // A thread the user deleted returns as soon as they legitimately use it again.
            unhideConversation(conversationID)
        } catch {
            banner = "Couldn't send that message. It stays queued and will retry."
        }
    }

    public func localPreview(for conversationID: String) -> String? {
        localThreads[conversationID]?.preview
    }

    public func localLastActivity(for conversationID: String) -> Date? {
        localThreads[conversationID]?.lastActivity
    }

    // MARK: Local conversation deletion

    /// Conversations hidden from the Chats list on THIS device. Deliberately presentation state:
    /// the MLS group, ratchet and replay data are untouched, so a later message still decrypts and
    /// the thread legitimately returns (see `MlsClient.clearVisibleHistory`).
    @Published public private(set) var locallyDeletedConversationIDs: Set<String> = []

    /// Injected by the composition layer holding the `MlsClient` for a conversation. It clears that
    /// conversation's visible message log without touching protocol state. Not `@Sendable`: it
    /// captures the non-`Sendable` `MlsClient` and is only called here on the main actor.
    public var clearHistoryAction: ((String) async throws -> Void)?

    /// Local-only deletion. Nothing is sent: no "delete for everyone" event exists, the peer's copy
    /// is unaffected, the person is not blocked or removed, and any private alias is kept.
    public func deleteConversationLocally(_ conversationID: String) async {
        locallyDeletedConversationIDs.insert(conversationID)
        // Drop the cached preview too, so no fragment of the deleted thread survives in the list.
        localThreads.removeValue(forKey: conversationID)
        if let clearHistoryAction {
            do {
                try await clearHistoryAction(conversationID)
            } catch {
                banner = "Couldn't clear this device's copy of that conversation."
            }
        }
        banner = "Conversation removed from this device."
    }

    /// A legitimate new message un-hides the thread; the previously deleted messages stay gone
    /// because they were erased from the local log, not merely filtered.
    public func unhideConversation(_ conversationID: String) {
        locallyDeletedConversationIDs.remove(conversationID)
    }

    /// What the Chats list renders.
    public var visibleConversations: [Conversation] {
        conversations.filter { !locallyDeletedConversationIDs.contains($0.conversationID) }
    }

    /// Create a group from selected people; the server refuses only if a blocked pair is included.
    /// Returns the new conversation id, or nil on failure (banner explains why).
    public func createGroup(memberAccountIDs: [String]) async -> String? {
        var conversationID: String?
        await run { [self] in
            guard let token else { return }
            let group = try await client.createGroup(accessToken: token, memberAccountIDs: memberAccountIDs)
            conversationID = group.conversationID
            conversations = try await client.listConversations(accessToken: token)
            banner = "Group created."
        }
        return conversationID
    }
}
