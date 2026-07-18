import SwiftUI

/// The `@main` entry point (closes the software half of R-101 — a runnable iOS app target). This is
/// a focused **demonstrator** for the Secret Message feature: it wires SENTINEL's real SwiftUI views
/// (SentinelUI) to the real on-device MLS core (MlsFfi/Rust) with NO mock crypto. It is not the full
/// product shell — profiles, sign-in, and the live relay live in the SentinelUI/SentinelKit flows —
/// but it boots, renders, and drives the actual view-once lifecycle on the simulator.
@main
struct SentinelDemoApp: App {
    var body: some Scene {
        WindowGroup {
            SecretDemoView()
        }
    }
}
