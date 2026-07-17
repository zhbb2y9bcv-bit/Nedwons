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

    public init(baseURL: URL, deviceIdentity: DeviceIdentity = DeviceIdentity()) {
        client = SentinelClient(baseURL: baseURL)
        self.deviceIdentity = deviceIdentity
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
        case 403: "Not allowed — everyone in a group must be friends first."
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
        inbox = []
        deviceAssurance = nil
    }

    private func loadInitial() async {
        guard let token else { return }
        myProfile = try? await client.myProfile(accessToken: token)
        friends = (try? await client.listFriends(accessToken: token)) ?? []
        incomingRequests = (try? await client.friendRequests(accessToken: token)) ?? []
        conversations = (try? await client.listConversations(accessToken: token)) ?? []
    }

    public func refreshConversations() async {
        await run { [self] in
            guard let token else { return }
            conversations = try await client.listConversations(accessToken: token)
        }
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

    // MARK: Groups

    /// Create a group from selected friends; the server enforces the mutual-friend clique.
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
