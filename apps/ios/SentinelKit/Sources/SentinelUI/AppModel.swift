import Foundation
import SentinelKit
import SwiftUI

/// Observable app state that backs the UI. Every button calls one of these async methods,
/// which call `SentinelClient` against the backend — so the controls are functionally wired,
/// not decorative. The device proof-of-possession key is provisioned and reloaded through
/// `DeviceIdentity`: registration enrolls the Secure Enclave key when the hardware exists (else
/// an explicit, acknowledged software fallback), and sign-in reloads that *same* enrolled key —
/// so device binding (INV-2) actually holds instead of signing a fresh key each launch.
@MainActor
public final class AppModel: ObservableObject {
    @Published public var session: SentinelClient.Session?
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

    private let client: SentinelClient
    private let deviceIdentity: DeviceIdentity

    /// Fail closed by default: a device without a Secure Enclave will **not** silently enroll a
    /// software key. Flip to `.allowSoftwareFallback` only after the user acknowledges the lower
    /// assurance (e.g. from a Settings toggle).
    public var provisionPolicy: DeviceProvisionPolicy = .requireHardware

    public init(
        baseURL: URL,
        pinnedLogKey: Data? = nil,
        deviceIdentity: DeviceIdentity = DeviceIdentity()
    ) {
        client = SentinelClient(baseURL: baseURL)
        self.pinnedLogKey = pinnedLogKey
        self.deviceIdentity = deviceIdentity
    }

    /// Convenience: construct from the build's `AppConfig` (server URL + out-of-band-pinned
    /// transparency log key). This is what the shipped `@main` uses.
    public convenience init() {
        self.init(baseURL: AppConfig.serverURL, pinnedLogKey: AppConfig.pinnedTransparencyLogKey)
    }

    public var isLoggedIn: Bool { session != nil }

    private var token: String? { session?.accessToken }

    /// Run an async action with busy state + error capture, so callers (buttons) stay tiny.
    private func run(_ action: @escaping () async throws -> Void) async {
        isBusy = true
        defer { isBusy = false }
        do {
            try await action()
        } catch let SentinelClient.ClientError.http(status, _) {
            banner = errorText(for: status)
        } catch SentinelClient.ClientError.transport {
            banner = "Can't reach the server. Check your connection."
        } catch DeviceIdentityError.secureHardwareUnavailable {
            banner = "This device has no Secure Enclave, which Sentinel requires to protect your "
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
        await run { [self] in
            // Enroll (and persist) the device key: Secure Enclave when available, else per policy.
            let enrolled = try deviceIdentity.provision(policy: provisionPolicy)
            deviceAssurance = enrolled.assurance
            let s = try await client.register(
                username: username, password: password, signer: enrolled.signer
            )
            session = s
            acknowledgedDeviceIDs = [s.deviceID] // this device is trusted from enrollment
            if enrolled.assurance == .software {
                banner = "This device has no Secure Enclave — using a lower-assurance software key."
            }
            await loadInitial()
        }
    }

    public func signIn(username: String, password: String) async {
        await run { [self] in
            // Sign with the SAME key enrolled at registration (INV-2), reloaded from the Keychain.
            guard let enrolled = try deviceIdentity.loadEnrolled() else {
                banner = "No device key on this device yet. Register, or recover your account."
                return
            }
            deviceAssurance = enrolled.assurance
            let s = try await client.login(
                username: username, password: password, signer: enrolled.signer
            )
            session = s
            acknowledgedDeviceIDs = [s.deviceID]
            await loadInitial()
        }
    }

    public func signOut() {
        // Clears session state only; the enrolled device key stays in the Keychain so the same
        // device can sign back in (device binding persists across sign-out).
        session = nil
        myProfile = nil
        friends = []
        incomingRequests = []
        searchResults = []
        blocked = []
        inbox = []
        deviceAssurance = nil
    }

    private func loadInitial() async {
        guard let token else { return }
        myProfile = try? await client.myProfile(accessToken: token)
        friends = (try? await client.listFriends(accessToken: token)) ?? []
        incomingRequests = (try? await client.friendRequests(accessToken: token)) ?? []
        blocked = (try? await client.listBlocked(accessToken: token)) ?? []
        conversations = (try? await client.listConversations(accessToken: token)) ?? []
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

    /// Injected by the composition layer that holds the MLS client (`SentinelAppKit`), which
    /// `SentinelUI` cannot import. Runs the real `SelfGroupLinker` over this device's `MlsClient`
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
        guard let token else { throw SentinelClient.ClientError.decoding }
        let sth = try await client.transparencySignedTreeHead(accessToken: token)
        guard let key = Hex.decode(sth.logPublicKey) else {
            throw SentinelClient.ClientError.decoding
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

    public func search(_ query: String) async {
        guard query.trimmingCharacters(in: .whitespaces).count >= 2 else {
            searchResults = []
            return
        }
        await run { [self] in
            guard let token else { return }
            searchResults = try await client.searchProfiles(accessToken: token, query: query)
        }
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
