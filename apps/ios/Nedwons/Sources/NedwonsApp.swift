import NedwonsAppKit
import NedwonsUI
import SwiftUI

/// The `@main` entry point. It boots the real product: `AppComposition.standard()` builds the
/// `AppModel` the screens render AND the `ConversationCoordinator` that gives it a messaging
/// pipeline (prekeys, MLS group bootstrap, upload-with-retry, inbox receive loop), then
/// `NedwonsAppRoot` runs the launch state machine (validate a stored session, else show
/// authentication) against the server and pinned log key configured for this build (`AppConfig`).
///
/// This target contains NO demo, seeded conversation, or sample data. Preview/test fixtures live in
/// test targets so they cannot execute during an ordinary Debug or Release launch.
///
/// The one exception is explicit and Debug-only: when the XCUITest suite launches the app with
/// `UITestLaunch.harnessFlag`, the model is wired to an in-process fixture instead of the network
/// (`UITestHarness.swift`). That code is compiled out of Release, where it would otherwise be an
/// authentication bypass, and it is never reachable without the launch argument.
@main
struct NedwonsApp: App {
    // @StateObject defers construction to the first (main-actor) body render, so the @MainActor
    // graph is built safely and persists across renders.
    @StateObject private var composition = NedwonsApp.makeComposition()
    @Environment(\.scenePhase) private var scenePhase

    #if os(iOS)
        // SwiftUI exposes no hook for `didRegisterForRemoteNotificationsWithDeviceToken`, so the
        // APNs device token can only be received through an app delegate (#4).
        @UIApplicationDelegateAdaptor(PushAppDelegate.self) private var pushDelegate
    #endif

    var body: some Scene {
        WindowGroup {
            NedwonsAppRoot(model: composition.model)
                #if os(iOS)
                    .task {
                        // Hand the delegate the coordinator it forwards callbacks to. Done here
                        // rather than in `init` because the delegate is constructed by UIKit before
                        // the SwiftUI graph exists.
                        PushAppDelegate.coordinator = composition.model.pushRegistration
                        await composition.model.pushRegistration.refreshAuthorization()
                    }
                    // Ask only once the user is signed in. A permission prompt on first launch —
                    // before they have seen what the app is — is the reliable way to get
                    // notifications denied permanently, and a denial cannot be re-prompted.
                    .onChange(of: composition.model.isLoggedIn) { _, signedIn in
                        guard signedIn else { return }
                        Task {
                            await composition.model.pushRegistration.requestAuthorization {
                                UIApplication.shared.registerForRemoteNotifications()
                            }
                        }
                    }
                #endif
        }
        // Single-writer handoff (ADR-0007): backgrounding closes every MLS store and releases the
        // cross-process lock so a push can be decrypted by the Notification Service Extension;
        // foregrounding re-opens and picks up whatever the extension committed. `.inactive`
        // (control centre, incoming call) deliberately changes nothing.
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .background: composition.sceneDidEnterBackground()
            case .active: composition.sceneDidBecomeActive()
            default: break
            }
        }
    }

    @MainActor
    private static func makeComposition() -> AppComposition {
        #if DEBUG
            if let scenario = UITestLaunch.scenario() {
                return .uiTestHarness(scenario: scenario)
            }
        #endif
        // Before anything else touches the network or the Keychain. In a Release build a
        // misconfiguration terminates here with a message naming it; in Debug/Staging the faults
        // are logged and the app continues, because the settings this checks are legitimately
        // absent during development.
        for fault in BuildConfiguration.validateAtLaunch() {
            print("[nedwons] build configuration: \(fault.description)")
        }
        return .standard()
    }
}
