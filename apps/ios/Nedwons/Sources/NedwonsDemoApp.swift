import NedwonsUI
import SwiftUI

/// Boots the real product shell against the server + pinned log key configured for this build
/// (`AppConfig`, from `Info.plist`; loopback dev server by default). `SecretDemoView` remains in
/// this target for isolated view-once testing on the simulator.
@main
struct NedwonsDemoApp: App {
    // @StateObject defers construction to the first (main-actor) body render, so the @MainActor
    // AppModel is built safely and its state persists across renders.
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            NedwonsAppRoot(model: model)
        }
    }
}
