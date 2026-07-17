import SentinelUI
import SwiftUI

/// Application entry point. This file belongs to the iOS app target created in Xcode (see
/// apps/ios/README.md) and is not built by the SwiftPM `swift build` used for the rest of
/// SentinelKit/SentinelUI. It requires Xcode 26 + the iOS 26 SDK.
///
/// It constructs an `AppModel` pointed at the backend and hands it to `AppRootView`, whose
/// buttons are wired to `SentinelClient` (sign in, search people, friend requests, profile
/// editing, and clique-gated group creation are all functional). On device the sign-in flow
/// uses a `SecureEnclaveDeviceSigner`; see AppModel for where to inject it.
@main
struct SentinelApp: App {
    @StateObject private var model = AppModel(baseURL: Self.backendURL)

    /// Configure per build (Info.plist / xcconfig). Loopback default matches the dev server.
    static var backendURL: URL {
        if let raw = Bundle.main.object(forInfoDictionaryKey: "SentinelBackendURL") as? String,
           let url = URL(string: raw) {
            return url
        }
        return URL(string: "http://127.0.0.1:8080")!
    }

    var body: some Scene {
        WindowGroup {
            AppRootView(model: model)
        }
    }
}
