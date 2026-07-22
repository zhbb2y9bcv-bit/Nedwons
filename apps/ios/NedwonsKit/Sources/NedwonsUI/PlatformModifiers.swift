import SwiftUI

/// `NedwonsUI` also builds for macOS so it can be type-checked and unit-tested with `swift test`
/// (ADR-0005). These wrap the iOS-only presentation modifiers so the shared screens compile on
/// both without `#if` noise at every call site.
extension View {
    func inlineNavigationTitle() -> some View {
        #if os(iOS)
            return navigationBarTitleDisplayMode(.inline)
        #else
            return self
        #endif
    }

    /// Usernames are case-normalized server-side; never auto-capitalize or autocorrect them.
    func usernameInput() -> some View {
        #if os(iOS)
            return textInputAutocapitalization(.never).autocorrectionDisabled()
        #else
            return autocorrectionDisabled()
        #endif
    }
}
