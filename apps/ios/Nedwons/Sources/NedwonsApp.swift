import NedwonsUI
import SwiftUI

/// The `@main` entry point. It boots the real product shell: `NedwonsAppRoot` runs the launch state
/// machine (validate a stored session, else show authentication) against the server and pinned log
/// key configured for this build (`AppConfig`, from `Info.plist`).
///
/// This target contains NO demo, seeded conversation, or sample data. Preview/test fixtures live in
/// test targets so they cannot execute during an ordinary Debug or Release launch.
@main
struct NedwonsApp: App {
    // @StateObject defers construction to the first (main-actor) body render, so the @MainActor
    // AppModel is built safely and its state persists across renders.
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            NedwonsAppRoot(model: model)
        }
    }
}
