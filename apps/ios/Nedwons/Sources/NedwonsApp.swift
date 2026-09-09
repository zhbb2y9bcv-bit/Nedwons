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

    var body: some Scene {
        WindowGroup {
            NedwonsAppRoot(model: composition.model)
        }
    }

    @MainActor
    private static func makeComposition() -> AppComposition {
        #if DEBUG
            if let scenario = UITestLaunch.scenario() {
                return .uiTestHarness(scenario: scenario)
            }
        #endif
        return .standard()
    }
}
