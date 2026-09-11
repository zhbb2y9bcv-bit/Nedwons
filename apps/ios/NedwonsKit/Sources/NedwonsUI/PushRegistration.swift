import Foundation

#if canImport(UserNotifications)
    import UserNotifications
#endif

/// The APNs client lifecycle: ask permission, register with the system, receive the device token,
/// and tell the relay about it — in whatever order those actually happen (#4).
///
/// ## Why this is a state machine and not four call sites
///
/// The two facts needed to register a token with the server arrive independently and in an order
/// nobody controls:
///
///   * APNs hands over the device token whenever it feels like it, often before the user has
///     signed in, and again — unannounced — whenever iOS rotates it (restore from backup, app
///     reinstall, OS upgrade).
///   * The session appears when the user authenticates, which may be long after launch.
///
/// The pre-existing `AppModel.registerPush(token:)` silently did nothing when there was no session
/// yet, so the common real-device ordering (token first, sign-in second) registered NOTHING and the
/// device was never woken again. This type holds whichever half arrives first and registers as soon
/// as both exist, which is the only ordering-independent way to get it right.
///
/// It also refuses to re-POST an unchanged (account, token) pair. Re-registering on every
/// foreground is a needless authenticated write, and on a proof-enforcing server it is a needless
/// signature too.
@MainActor
public final class PushRegistrationCoordinator: ObservableObject {
    /// What the user has granted. `notDetermined` means we have not asked yet.
    public enum Authorization: String, Equatable, Sendable {
        case notDetermined
        case denied
        case authorized
        /// Quiet delivery granted without an explicit prompt.
        case provisional
    }

    @Published public private(set) var authorization: Authorization = .notDetermined
    /// The last error the system reported for remote-notification registration, for display.
    @Published public private(set) var lastFailure: String?

    /// The most recent token APNs handed us, whether or not it has been registered yet.
    public private(set) var deviceToken: Data?
    /// The account the app is currently signed in as, if any.
    private var accountID: String?
    /// The exact (account, token) pair already accepted by the server, so an unchanged pair is not
    /// re-sent. Cleared on sign-out so the next sign-in always registers.
    private var registered: (account: String, token: Data)?

    /// Performs the authenticated `POST /v1/push/register`. Injected so the whole lifecycle is
    /// testable with no network and no APNs.
    private let register: @MainActor (Data) async throws -> Void

    public init(register: @escaping @MainActor (Data) async throws -> Void) {
        self.register = register
    }

    /// APNs delivered a device token (`didRegisterForRemoteNotificationsWithDeviceToken`).
    ///
    /// Also the ROTATION path: iOS re-delivers here with a new value and no other signal, so a
    /// changed token must be treated exactly like a first one.
    public func apnsTokenReceived(_ token: Data) async {
        lastFailure = nil
        deviceToken = token
        await registerIfReady()
    }

    /// The system refused to register for remote notifications. Recorded rather than swallowed:
    /// without it, "no pushes" is indistinguishable from "no messages".
    public func apnsRegistrationFailed(_ message: String) {
        lastFailure = message
    }

    /// A session now exists. Called after sign-in AND after a launch restore.
    public func sessionEstablished(accountID: String) async {
        self.accountID = accountID
        await registerIfReady()
    }

    /// Signed out: forget what was registered so the next sign-in re-registers, even if APNs never
    /// hands us a new token (it usually does not — the token belongs to the install, not the user).
    public func signedOut() {
        accountID = nil
        registered = nil
    }

    /// True when the server already holds exactly this pair.
    public func isRegistered(account: String, token: Data) -> Bool {
        registered.map { $0.account == account && $0.token == token } ?? false
    }

    private func registerIfReady() async {
        guard let accountID, let deviceToken else { return }
        if isRegistered(account: accountID, token: deviceToken) { return }
        do {
            try await register(deviceToken)
            registered = (accountID, deviceToken)
        } catch {
            // Left unrecorded so the next trigger (foreground, re-auth, rotation) retries. A wake
            // push is a latency optimisation, never the delivery path — the long-poll and
            // WebSocket still deliver — so a failure here must not surface as an error to the user.
            lastFailure = "Could not register for notifications."
        }
    }

    #if canImport(UserNotifications)
        /// Ask for notification permission, then — only if granted — register with APNs.
        ///
        /// Deliberately called after authentication rather than at launch: a permission prompt on
        /// first launch, before the user has seen what the app is, is the reliable way to get it
        /// denied permanently.
        ///
        /// `registerWithSystem` is the platform call (`UIApplication.registerForRemoteNotifications`),
        /// injected so this stays testable and so the macOS target can supply its own.
        public func requestAuthorization(
            center: UNUserNotificationCenter = .current(),
            registerWithSystem: @MainActor () -> Void
        ) async {
            let granted: Bool
            do {
                granted = try await center.requestAuthorization(options: [.alert, .badge, .sound])
            } catch {
                authorization = .denied
                lastFailure = "Notification permission could not be requested."
                return
            }
            authorization = granted ? .authorized : .denied
            // Registering for remote notifications when the user said no would still yield a token
            // (silent pushes work regardless), but asking the system to do it is pointless noise
            // and the wake would have nowhere to surface.
            guard granted else { return }
            registerWithSystem()
        }

        /// Re-read the system's current setting, which the user can change in Settings at any time
        /// without the app being told.
        public func refreshAuthorization(center: UNUserNotificationCenter = .current()) async {
            let settings = await center.notificationSettings()
            switch settings.authorizationStatus {
            case .authorized, .ephemeral: authorization = .authorized
            case .provisional: authorization = .provisional
            case .denied: authorization = .denied
            case .notDetermined: authorization = .notDetermined
            @unknown default: authorization = .notDetermined
            }
        }
    #endif
}

/// Hex, lowercase — the form APNs device tokens are registered in.
public func apnsTokenHex(_ token: Data) -> String {
    token.map { String(format: "%02x", $0) }.joined()
}
