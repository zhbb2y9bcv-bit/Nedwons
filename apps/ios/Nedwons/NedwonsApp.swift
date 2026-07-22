import NedwonsUI
import SwiftUI

/// Belongs to the Xcode iOS app target, NOT the SwiftPM `swift build` used for the rest of
/// NedwonsKit/NedwonsUI; requires Xcode 26 + the iOS 26 SDK.
///
/// Constructs an `AppModel` pointed at the backend and hands it to `AppRootView`. On device the
/// sign-in flow uses a `SecureEnclaveDeviceSigner`; see AppModel for where it is injected.
@main
struct NedwonsApp: App {
    @StateObject private var model = AppModel(baseURL: Self.backendURL)

    /// Configure per build (Info.plist / xcconfig). Loopback default matches the dev server.
    static var backendURL: URL {
        if let raw = Bundle.main.object(forInfoDictionaryKey: "NedwonsBackendURL") as? String,
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
