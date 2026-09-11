#if os(iOS)
    import NedwonsUI
    import UIKit
    import UserNotifications

    /// The UIKit half of the APNs lifecycle (#4). SwiftUI has no hook for
    /// `didRegisterForRemoteNotificationsWithDeviceToken`, so the one place that callback can be
    /// received is an app delegate — attached with `@UIApplicationDelegateAdaptor`.
    ///
    /// It holds no logic of its own. Everything it learns is forwarded to
    /// `PushRegistrationCoordinator`, which is platform-free and unit-tested; this type exists only
    /// to receive callbacks and hand them over.
    final class PushAppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
        /// Set during composition. Weak: the coordinator is owned by the app's object graph, and an
        /// app delegate outliving it must not keep it alive.
        @MainActor static weak var coordinator: PushRegistrationCoordinator?

        func application(
            _ application: UIApplication,
            didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
        ) -> Bool {
            // Foreground presentation is routed through this delegate so a wake that arrives while
            // the app is open does not draw a banner over the conversation the user is reading.
            UNUserNotificationCenter.current().delegate = self
            return true
        }

        /// APNs issued this install's device token — at launch, and again whenever iOS rotates it
        /// (restore from backup, reinstall, OS upgrade). The rotation case arrives here with no
        /// other signal, which is why the coordinator treats every delivery as authoritative.
        func application(
            _ application: UIApplication,
            didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
        ) {
            Task { @MainActor in
                await Self.coordinator?.apnsTokenReceived(deviceToken)
            }
        }

        /// Registration failed (no network, no entitlement, Simulator without a push profile).
        /// Recorded rather than ignored: silently missing pushes is indistinguishable from silence.
        func application(
            _ application: UIApplication,
            didFailToRegisterForRemoteNotificationsWithError error: Error
        ) {
            Task { @MainActor in
                Self.coordinator?.apnsRegistrationFailed(error.localizedDescription)
            }
        }

        /// A contentless wake that lands while the app is in the foreground. The app is already
        /// fetching its inbox, so the notification itself is suppressed — showing "New message" on
        /// top of the open conversation would be both redundant and, since the alert text is a
        /// placeholder the extension rewrites, wrong.
        /// `nonisolated` because the delegate protocol hands over non-`Sendable` arguments
        /// (`UNUserNotificationCenter`, `UNNotification`) from an arbitrary context, which cannot
        /// cross into this main-actor-isolated class. Nothing here touches either argument or any
        /// actor-isolated state, so there is nothing to isolate.
        nonisolated func userNotificationCenter(
            _ center: UNUserNotificationCenter,
            willPresent notification: UNNotification
        ) async -> UNNotificationPresentationOptions {
            []
        }
    }
#endif
