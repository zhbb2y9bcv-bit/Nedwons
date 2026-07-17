import SentinelUI
import SwiftUI

/// Application entry point. This file belongs to the iOS app target created in Xcode (see
/// apps/ios/README.md) and is not built by the SwiftPM `swift build` used for the rest of
/// SentinelKit/SentinelUI. It requires Xcode 26 + the iOS 26 SDK (Apple's mandated minimum
/// since 2026-04-28).
///
/// The scaffold presents onboarding with device enrollment gated off (no backend
/// configured). Once enrollment lands (Milestone 1 completion), the app transitions to
/// `RootView` after a successful enrollment.
@main
struct SentinelApp: App {
    private let flags = FeatureFlags.scaffold

    var body: some Scene {
        WindowGroup {
            OnboardingView(flags: flags)
        }
    }
}
