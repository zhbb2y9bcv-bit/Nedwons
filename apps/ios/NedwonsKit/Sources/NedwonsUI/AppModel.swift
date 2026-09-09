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
    /// Group panel state per conversation (roles, mutes, settings), loaded when a conversation or
    /// its panel opens and refreshed after every admin action. Keyed by conversation id.
    @Published public var groupStates: [String: GroupState] = [:]
    /// Group names, decrypted on this device. They live INSIDE the MLS ciphertext, so the relay has
    /// no name to serve and this map is populated only by the composition layer reading local
    /// state — never from a server response.
    @Published public var groupNames: [String: String] = [:]
    @Published public var inbox: [InboxEnvelope] = []
    @Published public var isBusy = false
    @Published public var banner: String?
    /// Assurance level of the key backing the current session (hardware vs software fallback).
    @Published public var deviceAssurance: DeviceAssurance?

    // Internal (not private) so the group-administration surface can live in its own file
    // (`GroupAdminModel.swift`) as an extension; extensions cannot add stored state, but they
    // can share this transport.
    let client: NedwonsClient
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

    /// Inject a preconfigured client — unit tests and the UI-test harness hand in one whose
    /// `URLSession` is served by an in-process fixture, so the real model + real screens run against
    /// a deterministic backend with no network at all.
    public init(
        client: NedwonsClient,
        pinnedLogKey: Data? = nil,
        deviceIdentity: DeviceIdentity = DeviceIdentity(),
        sessionStore: SessionStore = SessionStore()
    ) {
        self.client = client
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
            loadVerifiedPeers()
            phase = .authenticated
            banner = "You're offline. Showing what's stored on this device."
        } catch {
            sessionStore.clear()
            phase = .sessionExpired
        }
    }

    var token: String? { session?.accessToken }

    /// Run an async action with busy state + error capture, so callers (buttons) stay tiny.
    func run(_ action: @escaping () async throws -> Void) async {
        isBusy = true
        defer { isBusy = false }
        do {
            try await action()
        } catch let NedwonsClient.ClientError.http(status, body) {
            banner = errorText(for: status, body: body)
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

    /// Specific refusal codes (`GroupRefusal`) win over the status-only text: "a group needs at
    /// least one admin" is actionable, "request failed (409)" is not. The generic `forbidden`
    /// code is deliberately NOT mapped here — it means different things on different endpoints,
    /// and the group-admin runner supplies its own wording for it.
    func errorText(for status: Int, body: String = "") -> String {
        if let refusal = GroupRefusal.from(errorBody: body), refusal != .forbidden {
            return refusal.userFacingText
        }
        if body.contains("account_banned") {
            return "This account has been suspended for violating Nedwons' rules on illegal "
                + "content. If you believe this is a mistake, contact support."
        }
        return switch status {
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
        verifiedPeers = [] // published copy only; the per-account persisted set survives sign-out
        phase = .unauthenticated
    }

    /// Revoke another of this account's devices.
    ///
    /// Revocation is how a lost or stolen phone stops being able to act, so it must take effect
    /// server-side (tokens and refresh families are burned there) rather than merely disappearing
    /// from this list. Refuses to revoke the CURRENT device: doing so would sign this session out
    /// through a path that looks like device management, which is a confusing way to lose access —
    /// "Sign out" is the honest control for that.
    public func revokeDevice(_ deviceID: String) async {
        guard let token, let session else { return }
        guard deviceID != session.deviceID else {
            banner = "This is the device you're using. Use Sign out instead."
            return
        }
        await run { [self] in
            try await client.revokeDevice(accessToken: token, deviceID: deviceID)
            await refreshDevices()
            banner = "Device revoked. Its sessions are now dead."
        }
    }

    /// Set (or replace) the recovery secret.
    ///
    /// This is the ONLY path back in when every enrolled device is lost — without it, losing the
    /// device means losing the account, because a password alone can never enroll a new device
    /// (INV-2). The UI must say that plainly rather than presenting this as optional polish.
    public func setRecoverySecret(_ secret: String) async -> String? {
        guard let token else { return "You are not signed in." }
        do {
            try await client.setRecoverySecret(accessToken: token, recoverySecret: secret)
            return nil
        } catch let NedwonsClient.ClientError.http(status, _) where status == 400 {
            return "That recovery phrase is too weak. Use a longer, unique phrase."
        } catch {
            return "Couldn't save the recovery phrase. Check your connection and try again."
        }
    }

    /// Change the account password. Returns an error message on failure, `nil` on success.
    public func changePassword(current: String, new: String) async -> String? {
        guard let token, let session else { return "You are not signed in." }
        guard let enrolled = try? deviceIdentity.loadEnrolled() else {
            return "This device's key is unavailable, so the password cannot be changed."
        }
        do {
            try await client.changePassword(
                accessToken: token,
                accountID: session.accountID,
                currentPassword: current,
                newPassword: new,
                signer: enrolled.signer)
            return nil
        } catch let NedwonsClient.ClientError.http(status, _) where status == 400 {
            return "That new password was rejected. Use at least 12 characters and avoid common "
                + "or breached passwords."
        } catch {
            // Same text for a wrong current password and other refusals: distinguishing them would
            // make this endpoint a password oracle for someone holding a stolen token.
            return "Couldn't change the password. Check your current password and try again."
        }
    }

    /// Permanently delete this account, then erase everything this device still holds.
    ///
    /// Order matters and is not interchangeable. The server erasure goes FIRST, because it is the
    /// step that can fail and that the user can retry: wiping locally first would leave an account
    /// alive on the server that this device can no longer authenticate to, and therefore can no
    /// longer delete. Only once the server confirms do we destroy the local state.
    ///
    /// The local wipe is the part no server can do for us. Aliases, the MLS store and the enrolled
    /// device key never leave the device, so if they are not erased here they outlive the account
    /// they describe — a "deleted" account whose contact names and ratchet state are still sitting
    /// in the container.
    ///
    /// Returns an error message on failure, `nil` on success, so the caller can show the reason
    /// rather than a generic failure. A wrong password is the expected failure and must be
    /// recoverable.
    @discardableResult
    public func deleteAccount(password: String) async -> String? {
        guard let token, let session else { return "You are not signed in." }
        guard let enrolled = try? deviceIdentity.loadEnrolled() else {
            return "This device's key is unavailable, so deletion cannot be authorized."
        }
        do {
            try await client.deleteAccount(
                accessToken: token,
                accountID: session.accountID,
                password: password,
                signer: enrolled.signer)
        } catch {
            // Deliberately not distinguishing "wrong password" from other refusals in the returned
            // text: the server answers both with the same status so deletion cannot become a
            // password oracle for someone holding a stolen token.
            return "Deletion was refused. Check your password and try again."
        }

        wipeLocalStateAfterDeletion()
        return nil
    }

    /// Erase every local trace of the account. Separate and non-throwing on purpose: once the
    /// server has deleted the account there is no state worth preserving, so a failure to remove
    /// one artefact must not stop the others from being removed.
    private func wipeLocalStateAfterDeletion() {
        aliasStore?.eraseAll()
        // NOT `clearHistoryAction`: that clears the visible message log while deliberately
        // PRESERVING the ratchet, replay watermark and secret records, so a later message still
        // decrypts. Account deletion wants the opposite — the key material must be destroyed.
        wipeAllLocalDataAction?()
        try? deviceIdentity.reset()
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
        localThreads = [:]
        threadLines = [:]
        locallyDeletedConversationIDs = []
        usernamesByAccountID = [:]
        phase = .unauthenticated
    }

    private func loadInitial() async {
        loadVerifiedPeers() // local-only; before any network so badges render immediately
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

    // MARK: Safety numbers & peer verification (stored here; behavior in VerificationModel.swift)

    /// Peers this user has marked verified after comparing safety numbers. Local state only — a
    /// verification is this device's judgment, never something the server is told or asked about.
    @Published public internal(set) var verifiedPeers: Set<String> = []
    /// Persists `verifiedPeers` across launches, keyed by the signed-in account. Replaceable in
    /// tests; the default keeps it in `UserDefaults` (it holds no secrets — account ids only).
    public var verifiedPeersStore: VerifiedPeersStoring = UserDefaultsVerifiedPeersStore()

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

    // Internal (not private) so the verification surface (`VerificationModel.swift`) shares it.
    func currentPinnedLogKey() async throws -> Data {
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

    /// Report one message (docs/MODERATION.md). The report carries exactly what the reporter
    /// chose here — the category, their words, optionally the message text as this device
    /// decrypted it, optionally the decrypted media bytes — and identifies the author by MLS
    /// device identity (server-resolved) or, failing that, by the 1:1 peer's account.
    /// Returns true on success so the sheet can also apply "block sender".
    @discardableResult
    public func reportMessage(
        _ line: ThreadLine,
        in conversationID: String,
        category: String,
        note: String,
        includeText: Bool,
        media: Data? = nil,
        mediaMime: String? = nil,
        fallbackAccountID: String? = nil
    ) async -> Bool {
        var ok = false
        await run { [self] in
            guard let token else { return }
            let deviceID = line.senderDeviceID.isEmpty ? nil : line.senderDeviceID
            let accountID = deviceID == nil ? fallbackAccountID : nil
            guard deviceID != nil || accountID != nil else {
                banner = "This message is too old to be reported directly. Report the person from their profile instead."
                return
            }
            _ = try await client.reportContent(
                accessToken: token,
                accountID: accountID,
                deviceID: deviceID,
                reason: note.isEmpty ? "reported from the conversation" : note,
                category: category,
                evidence: includeText ? line.quotableText : nil,
                conversationID: conversationID,
                messageID: line.messageID.isEmpty ? nil : line.messageID,
                evidenceMedia: media,
                evidenceMediaMime: mediaMime)
            banner = "Report submitted. Our team reviews reports of illegal content."
            ok = true
        }
        return ok
    }

    /// Decrypted bytes for an attachment, if this device has (or can fetch) them — what a report
    /// attaches as media evidence when the reporter opts in.
    public func attachmentEvidence(_ attachment: AttachmentLine) async -> Data? {
        if case .loaded(let data) = attachmentState(attachment.blobID) { return data }
        await loadAttachment(attachment)
        if case .loaded(let data) = attachmentState(attachment.blobID) { return data }
        return nil
    }

    // MARK: Groups

    /// The group's name on this device, if a member has set one.
    public func groupName(for conversationID: String) -> String? {
        groupNames[conversationID]
    }

    /// What a conversation is called in the list and the header: the group's E2EE name when it has
    /// one, else a description of who is in it. A 1:1 thread is titled by the other person (alias
    /// first, then their real username — an alias never hides who an account is).
    public func conversationTitle(for chat: ChatSummary) -> String {
        if let name = groupNames[chat.conversationID], !name.isEmpty { return name }
        if chat.isGroup { return "Group · \(chat.memberCount) people" }
        guard let accountID = chat.peerAccountID else { return "Conversation" }
        return displayName(for: accountID, username: chat.peerUsername ?? "Unknown")
    }

    /// Rename the group for everyone. The name travels inside the MLS ciphertext, so the relay
    /// never learns it; every member sees the change on their next sync.
    @discardableResult
    public func renameGroup(_ conversationID: String, to rawName: String) async -> Bool {
        let name = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { return false }
        guard let renameGroupAction else {
            banner = "Renaming isn't available in this build."
            return false
        }
        var ok = false
        await run {
            try await renameGroupAction(conversationID, name)
            ok = true
        }
        if ok { banner = "Group renamed." }
        return ok
    }

    /// The user is looking at this conversation, so it is read. Quiet: nothing here is worth
    /// interrupting them with if it fails.
    public func markConversationRead(_ conversationID: String) async {
        await markConversationReadAction?(conversationID)
    }

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

    /// Single-entry form, for callers that learn a username outside a profile lookup (the group
    /// panel's member list carries usernames for every member).
    public func rememberUsername(_ username: String, forAccountID id: String) {
        guard !username.isEmpty else { return }
        usernamesByAccountID[id] = username
    }

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
        } catch let NedwonsClient.ClientError.http(_, body)
            where GroupRefusal.from(errorBody: body).map(\.isSendRefusal) == true
        {
            // The composer is normally locked before this can happen; this is the race where an
            // admin muted you (or locked the group) while you were typing. Say so, and reload the
            // panel state so the composer locks now rather than after the next send.
            banner = GroupRefusal.from(errorBody: body)?.userFacingText
            await refreshGroupState(conversationID)
        } catch {
            banner = "Couldn't send that message. It stays queued and will retry."
        }
    }

    /// Every visible conversation as the UI renders it: the server's routing metadata joined with
    /// decrypted local display state (previews, unread counts). Shared by the chats list, the
    /// forward picker, and message search.
    public var chatSummaries: [ChatSummary] {
        visibleConversations.map { conversation in
            let peer = conversation.memberAccountIDs.first { $0 != session?.accountID }
            return ChatSummary(
                conversationID: conversation.conversationID,
                peerAccountID: peer,
                peerUsername: peer.flatMap { username(forAccountID: $0) },
                memberCount: conversation.memberAccountIDs.count,
                lastMessagePreview: localPreview(for: conversation.conversationID),
                lastActivity: localLastActivity(for: conversation.conversationID),
                unreadCount: unreadCount(for: conversation.conversationID)
            )
        }
    }

    public func localPreview(for conversationID: String) -> String? {
        localThreads[conversationID]?.preview
    }

    public func localLastActivity(for conversationID: String) -> Date? {
        localThreads[conversationID]?.lastActivity
    }

    /// Unread inbound messages on THIS device. Derived from decrypted local state — the relay
    /// cannot count what it cannot read, and never sees a read receipt.
    public func unreadCount(for conversationID: String) -> Int {
        localThreads[conversationID]?.unreadCount ?? 0
    }

    // MARK: Local conversation deletion

    /// Conversations hidden from the Chats list on THIS device. Deliberately presentation state:
    /// the MLS group, ratchet and replay data are untouched, so a later message still decrypts and
    /// the thread legitimately returns (see `MlsClient.clearVisibleHistory`).
    @Published public private(set) var locallyDeletedConversationIDs: Set<String> = []

    /// Injected by the composition layer holding the `MlsClient` for a conversation. It clears that
    /// conversation's visible message log without touching protocol state. Not `@Sendable`: it
    /// captures the non-`Sendable` `MlsClient` and is only called here on the main actor.
    /// Destroy the entire on-device MLS store (ratchet state, key material, message log).
    ///
    /// Injected by the composition layer, which owns the `MlsClient` instances and their files.
    /// Distinct from `clearHistoryAction`, which preserves crypto state by design: this is the
    /// account-deletion path, where preserving it would leave decryptable material behind for an
    /// account that no longer exists.
    public var wipeAllLocalDataAction: (() -> Void)?

    /// Injected by the composition layer: after the relay has created a conversation, set up its
    /// MLS group — claim each member's prekey, add them, deliver their Welcomes. Without it a
    /// conversation exists for routing but nothing can be encrypted into it.
    public var bootstrapConversationAction: ((String, [String]) async throws -> Void)?

    /// Injected: add people to an EXISTING conversation's MLS group after the relay has added them
    /// to routing. Without it they would be routed ciphertext they hold no key for.
    public var addMembersToConversationAction: ((String, [String]) async throws -> Void)?

    /// Injected: rename the group for everyone, over the E2EE channel.
    public var renameGroupAction: ((String, String) async throws -> Void)?

    /// Injected: mark a conversation read on this device.
    public var markConversationReadAction: ((String) async -> Void)?

    /// Injected: encrypt a file, upload the ciphertext, and send the message that references it.
    public var sendAttachmentAction: ((Data, String, String, String, String) async throws -> Void)?

    /// Injected: fetch and decrypt one attachment's bytes.
    public var loadAttachmentAction: ((String) async throws -> Data)?

    /// Injected: send a message answering another (`body`, `replyTo`, conversation).
    public var sendReplyAction: ((String, String, String) async throws -> Void)?

    /// Injected: add or remove a reaction (`messageID`, `emoji`, `remove`, conversation).
    public var reactAction: ((String, String, Bool, String) async throws -> Void)?

    /// Injected: tell the conversation whether this user is typing.
    public var setTypingAction: ((Bool, String) async -> Void)?

    /// Injected: change the disappearing-message timer for everyone (`seconds`, conversation).
    public var setDisappearTimerAction: ((UInt32, String) async throws -> Void)?

    /// Injected: retract one of the user's OWN messages everywhere (`messageID`, conversation).
    public var deleteForEveryoneAction: ((String, String) async throws -> Void)?

    /// Injected: forward a message (`lineID`, from conversation, to conversation).
    public var forwardMessageAction: ((UInt64, String, String) async throws -> Void)?

    /// Injected: on-device search over the decrypted local history.
    public var searchMessagesAction: ((String) -> [MessageSearchHit])?

    /// Injected: seal the message stores + at-rest root under a passphrase (docs/BACKUPS.md).
    public var createBackupAction: ((String) async throws -> Data)?
    /// Injected: restore a sealed backup into an empty store (returns files restored).
    public var restoreBackupAction: ((Data, String) async throws -> Int)?

    /// Create an encrypted backup and hand back a temp file URL for the share sheet. `nil` (with
    /// a banner) on failure. The passphrase never leaves the device — it seals the file.
    public func createBackup(passphrase: String) async -> URL? {
        guard let createBackupAction else {
            banner = "Backups aren't available in this build."
            return nil
        }
        do {
            let data = try await createBackupAction(passphrase)
            let stamp = ISO8601DateFormatter().string(from: Date()).prefix(10)
            let url = FileManager.default.temporaryDirectory
                .appendingPathComponent("nedwons-backup-\(stamp).nedwonsbackup")
            try data.write(to: url, options: .atomic)
            banner = "Backup created. Store it somewhere safe — it opens only with your passphrase."
            return url
        } catch {
            banner = "Couldn't create the backup."
            return nil
        }
    }

    /// Restore from a backup file. Honest failure modes: wrong passphrase and a damaged file are
    /// indistinguishable (by design), and restoring over existing conversations is refused.
    public func restoreBackup(from url: URL, passphrase: String) async -> Bool {
        guard let restoreBackupAction else {
            banner = "Restore isn't available in this build."
            return false
        }
        do {
            let secured = url.startAccessingSecurityScopedResource()
            defer { if secured { url.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: url)
            let count = try await restoreBackupAction(data, passphrase)
            banner = "Restored \(count) file\(count == 1 ? "" : "s") of chat history."
            await refreshConversations()
            return true
        } catch Backup.BackupError.cannotOpen {
            banner = "Wrong passphrase, or the file is damaged. Nothing was restored."
            return false
        } catch Backup.BackupError.unsupportedVersion {
            banner = "This backup was made by a newer version of Nedwons. Update the app first."
            return false
        } catch {
            banner = "Couldn't restore. This device already has chat data, or the file is not a Nedwons backup."
            return false
        }
    }

    /// Disappearing-message timer per conversation, in seconds (0/absent = off). Decrypted local
    /// state, published by the composition layer — never a server field.
    @Published public var disappearTimers: [String: UInt32] = [:]

    public func disappearTimer(for conversationID: String) -> UInt32 {
        disappearTimers[conversationID] ?? 0
    }

    /// Change the disappearing timer for everyone; the honest wording lives with the control.
    public func setDisappearTimer(_ seconds: UInt32, in conversationID: String) async {
        guard let setDisappearTimerAction else {
            banner = "Disappearing messages aren't available in this build."
            return
        }
        do {
            try await setDisappearTimerAction(seconds, conversationID)
            banner = seconds == 0
                ? "Disappearing messages are off for new messages."
                : "New messages now disappear after \(Self.timerLabel(seconds))."
        } catch {
            banner = "Couldn't change the timer. It stays as it was."
        }
    }

    /// Retract one of the user's own messages everywhere (best-effort, R-901 — the honest copy is
    /// on the confirm dialog).
    public func deleteForEveryone(_ line: ThreadLine, in conversationID: String) async {
        guard line.mine, !line.messageID.isEmpty, let deleteForEveryoneAction else { return }
        do {
            try await deleteForEveryoneAction(line.messageID, conversationID)
        } catch {
            banner = "Couldn't delete that message everywhere."
        }
    }

    /// Forward a message to another conversation this user is in.
    public func forward(_ line: ThreadLine, from sourceID: String, to destinationID: String) async {
        guard let forwardMessageAction else {
            banner = "Forwarding isn't available in this build."
            return
        }
        do {
            try await forwardMessageAction(line.id, sourceID, destinationID)
            banner = "Forwarded."
        } catch {
            banner = "Couldn't forward that message."
        }
    }

    /// On-device message search results for the chats screen, refreshed as the user types.
    @Published public var messageSearchHits: [MessageSearchHit] = []

    public func searchMessages(_ query: String) {
        messageSearchHits = searchMessagesAction?(query) ?? []
    }

    static func timerLabel(_ seconds: UInt32) -> String {
        switch seconds {
        case 0: return "off"
        case ..<3600: return "\(seconds / 60) min"
        case ..<86400: return "\(seconds / 3600) hour\(seconds == 3600 ? "" : "s")"
        case ..<604_800: return "\(seconds / 86400) day\(seconds == 86400 ? "" : "s")"
        default: return "\(seconds / 604_800) week\(seconds == 604_800 ? "" : "s")"
        }
    }

    /// Who is currently typing, per conversation, as last reported. Ephemeral by construction: it
    /// is never persisted, and each entry expires on its own — a "stopped typing" that never
    /// arrives (the app was killed mid-word) must not leave someone typing forever.
    @Published public var typingBy: [String: Set<String>] = [:]

    /// The message being replied to, per conversation, while the user composes.
    @Published public var replyDrafts: [String: ThreadLine] = [:]

    public func typingNames(in conversationID: String) -> [String] {
        (typingBy[conversationID] ?? []).sorted().map { id in
            displayName(for: id, username: username(forAccountID: id) ?? "Someone")
        }
    }

    /// Record a typing signal and schedule its expiry. Called by the composition layer when a
    /// typing message arrives.
    public func noteTyping(_ senderID: String, active: Bool, in conversationID: String) {
        var current = typingBy[conversationID] ?? []
        if active {
            current.insert(senderID)
        } else {
            current.remove(senderID)
        }
        typingBy[conversationID] = current.isEmpty ? nil : current
        guard active else { return }
        // Expire on our own clock rather than waiting for a "stopped" that may never come.
        typingExpiry[senderID]?.cancel()
        typingExpiry[senderID] = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 8_000_000_000)
            guard !Task.isCancelled else { return }
            self?.noteTyping(senderID, active: false, in: conversationID)
        }
    }

    private var typingExpiry: [String: Task<Void, Never>] = [:]

    /// Begin (or continue) composing a reply to `line`.
    public func startReply(to line: ThreadLine, in conversationID: String) {
        guard !line.messageID.isEmpty else {
            banner = "This message is too old to reply to."
            return
        }
        replyDrafts[conversationID] = line
    }

    public func cancelReply(in conversationID: String) {
        replyDrafts.removeValue(forKey: conversationID)
    }

    /// Send `body`, answering the pending reply draft if there is one.
    public func sendMessageOrReply(_ body: String, to conversationID: String) async {
        let trimmed = body.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        guard let draft = replyDrafts[conversationID], let sendReplyAction else {
            await sendMessage(trimmed, to: conversationID)
            return
        }
        replyDrafts.removeValue(forKey: conversationID)
        do {
            try await sendReplyAction(trimmed, draft.messageID, conversationID)
            unhideConversation(conversationID)
        } catch let NedwonsClient.ClientError.http(_, body)
            where GroupRefusal.from(errorBody: body).map(\.isSendRefusal) == true
        {
            banner = GroupRefusal.from(errorBody: body)?.userFacingText
            await refreshGroupState(conversationID)
        } catch {
            banner = "Couldn't send that message. It stays queued and will retry."
        }
    }

    /// Toggle one emoji on one message.
    public func toggleReaction(_ emoji: String, on line: ThreadLine, in conversationID: String) async {
        guard !line.messageID.isEmpty else {
            banner = "This message is too old to react to."
            return
        }
        guard let reactAction else { return }
        let remove = line.reactions.contains { $0.emoji == emoji && $0.includesMe }
        do {
            try await reactAction(line.messageID, emoji, remove, conversationID)
        } catch {
            banner = "Couldn't send that reaction."
        }
    }

    /// Tell the conversation this user is typing. The composition layer throttles; this is the
    /// intent, not a per-keystroke signal.
    public func setTyping(_ active: Bool, in conversationID: String) async {
        await setTypingAction?(active, conversationID)
    }

    /// Decrypted attachment bytes for this session, keyed by blob id.
    ///
    /// In memory on purpose: a decrypted photo written to a cache directory outlives the moment it
    /// was shown and survives in backups, which is not what someone sending a picture through an
    /// E2EE messenger expects. The cost is that they download again next launch.
    @Published public private(set) var attachments: [String: AttachmentState] = [:]

    public func attachmentState(_ blobID: String) -> AttachmentState {
        attachments[blobID] ?? .notLoaded
    }

    /// Encrypt, upload, and send a file. The bytes are encrypted before anything leaves the device.
    public func sendAttachment(
        _ data: Data, mime: String, filename: String, caption: String, to conversationID: String
    ) async {
        guard let sendAttachmentAction else {
            banner = "Sending files isn't available in this build."
            return
        }
        isBusy = true
        defer { isBusy = false }
        do {
            try await sendAttachmentAction(data, mime, filename, caption, conversationID)
            unhideConversation(conversationID)
        } catch let NedwonsClient.ClientError.http(_, body)
            where GroupRefusal.from(errorBody: body).map(\.isSendRefusal) == true
        {
            banner = GroupRefusal.from(errorBody: body)?.userFacingText
            await refreshGroupState(conversationID)
        } catch {
            banner = "Couldn't send that file."
        }
    }

    /// Fetch and decrypt one attachment, remembering the result for this session.
    public func loadAttachment(_ attachment: AttachmentLine) async {
        guard let loadAttachmentAction else { return }
        if case .loading = attachmentState(attachment.blobID) { return }
        attachments[attachment.blobID] = .loading
        do {
            attachments[attachment.blobID] = .loaded(try await loadAttachmentAction(attachment.blobID))
        } catch let NedwonsClient.ClientError.http(status, _) {
            // 410 is the relay's honest answer that the bytes aged out of retention; every other
            // status is something a retry might fix.
            attachments[attachment.blobID] = .failed(
                status == 410 ? "No longer available" : "Couldn't download — tap to retry")
        } catch {
            attachments[attachment.blobID] = .failed("Couldn't download — tap to retry")
        }
    }

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
            if let bootstrapConversationAction {
                do {
                    try await bootstrapConversationAction(group.conversationID, memberAccountIDs)
                } catch {
                    // The conversation exists for routing; anyone not reachable yet (never opened
                    // the app, so no prekey) is queued and joins automatically on a later sync
                    // (V27 deferred adds) — said plainly, without a manual chore.
                    banner = "Group created. Anyone who hasn't opened Nedwons yet joins "
                        + "automatically when they do."
                }
            }
        }
        return conversationID
    }
}

/// One on-device search hit over decrypted local history (there is deliberately no server-side
/// search: the relay holds only ciphertext).
public struct MessageSearchHit: Sendable, Equatable, Identifiable {
    public let conversationID: String
    public let localID: UInt64
    public let snippet: String
    public let timestamp: Date?
    public let mine: Bool
    public var id: String { "\(conversationID)-\(localID)" }

    public init(
        conversationID: String, localID: UInt64, snippet: String, timestamp: Date?, mine: Bool
    ) {
        self.conversationID = conversationID
        self.localID = localID
        self.snippet = snippet
        self.timestamp = timestamp
        self.mine = mine
    }
}
