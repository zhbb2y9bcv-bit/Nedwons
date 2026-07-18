import SentinelUI
import SwiftUI

/// The `@main` entry point. It boots the **real product shell** — `SentinelAppRoot` gates on auth and
/// presents Chats / Devices / Settings, wired to the live `AppModel` — against the server + pinned
/// transparency-log key configured for this build (`AppConfig`, from `Info.plist`; a loopback dev
/// server by default). The focused view-once demonstrator lives in `SecretDemoView` (still in this
/// target) for isolated secret-lifecycle testing on the simulator.
@main
struct SentinelDemoApp: App {
    // @StateObject defers construction to the first (main-actor) body render, so the @MainActor
    // AppModel is built safely and its state persists across renders.
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            SentinelAppRoot(model: model)
        }
    }
}
