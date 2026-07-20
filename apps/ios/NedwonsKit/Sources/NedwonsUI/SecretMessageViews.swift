import SwiftUI

// MARK: - Secret-message SwiftUI presentation
//
// Views only. All security state comes from `SecretMessageViewModel` (which forwards to the Rust
// core). No copy/select/share/forward affordances are attached to secret text; the underlying
// conversation stays alive behind the overlay and is restored intact on dismiss.

/// The exact, non-sensitive tombstone shown in the conversation after a secret is sent or consumed.
/// Bundled monospaced system font (never an unbundled font that could fail at runtime), smaller than
/// body text, muted, restrained letter-spacing — mysterious but readable and accessible.
public struct SecretTombstoneView: View {
    private let text: String

    /// `text` should be the engine's `tombstoneText` ("a secret message has been sent"). Defaulted
    /// for previews/tests, but production passes the Rust-owned constant so the two never drift.
    public init(text: String = "a secret message has been sent") {
        self.text = text
    }

    /// The rendered string, for tests (SwiftUI `Text` is otherwise opaque to assertions).
    var textForTesting: String { text }

    public var body: some View {
        Text(text)
            .font(Nedwons.TypeScale.monoSmall)
            .tracking(1.5)
            .foregroundStyle(.secondary)
            .italic()
            .accessibilityLabel(Text("A secret message. Its contents are not available."))
            // Not selectable → never contributes to copy/paste, and it carries no length/content
            // signal about the original secret.
            .textSelection(.disabled)
    }
}

/// The sealed placeholder shown inline in the conversation. The recipient must tap it intentionally
/// to begin — background delivery never starts the countdown.
public struct SecretSealedPlaceholderView: View {
    private let onTap: () -> Void
    public init(onTap: @escaping () -> Void) { self.onTap = onTap }

    public var body: some View {
        Button(action: onTap) {
            HStack(spacing: Nedwons.Spacing.sm) {
                Image(systemName: "eye.slash.circle.fill")
                Text("Tap to view secret message")
                    .font(Nedwons.TypeScale.callout)
            }
            .padding(.horizontal, Nedwons.Spacing.md)
            .padding(.vertical, Nedwons.Spacing.sm)
        }
        .accessibilityLabel(Text("Sealed secret message. Tap to reveal. It can be viewed once."))
    }
}

/// Full-cover privacy overlay: hides and disables the conversation, composer, and navigation while a
/// secret is counting down or visible. Presentation only — the conversation model keeps running.
public struct SecretOverlayView: View {
    @ObservedObject private var model: SecretMessageViewModel
    private let onFinished: () -> Void

    /// Drives `model.tick()` on a display-linked cadence without the view holding any plaintext.
    private let ticker = Timer.publish(every: 0.05, on: .main, in: .common).autoconnect()

    public init(model: SecretMessageViewModel, onFinished: @escaping () -> Void) {
        self.model = model
        self.onFinished = onFinished
    }

    public var body: some View {
        ZStack {
            // Opaque cover so nothing behind it (other messages, composer) can be seen or captured.
            Color.black.opacity(0.98).ignoresSafeArea()

            switch model.display {
            case .countdown(let n):
                VStack(spacing: Nedwons.Spacing.xl) {
                    Text("Secret message coming in")
                        .font(Nedwons.TypeScale.headline)
                        .foregroundStyle(.white.opacity(0.85))
                    Text("\(n)")
                        .font(.system(size: 96, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                        .contentTransition(.numericText())
                        .accessibilityLabel(Text("Revealing in \(n)"))
                }
            case .visible(let text, let fade):
                Text(text)
                    .font(Nedwons.TypeScale.title)
                    .foregroundStyle(.white)
                    .multilineTextAlignment(.center)
                    .padding(Nedwons.Spacing.xl)
                    .opacity(fade)
                    .textSelection(.disabled)  // no copy/paste/selection
                    .accessibilityLabel(Text("Secret message showing. It will disappear."))
            case .tombstone, .error, .sealed:
                // Reveal finished (or failed) — close the overlay and restore the conversation.
                Color.clear.onAppear(perform: onFinished)
            }
        }
        // Block copy/share/context actions on the whole overlay.
        .contentShape(Rectangle())
        .onReceive(ticker) { _ in model.tick() }
        #if os(iOS)
            .onReceive(NotificationCenter.default.publisher(
                for: UIApplication.userDidTakeScreenshotNotification)
            ) { _ in model.onScreenCapture() }
            .onReceive(NotificationCenter.default.publisher(
                for: UIApplication.didEnterBackgroundNotification)
            ) { _ in model.onBackground() }
            .onReceive(NotificationCenter.default.publisher(
                for: UIApplication.willEnterForegroundNotification)
            ) { _ in model.onForeground() }
            .onAppear { startCaptureMonitor() }
        #endif
    }

    #if os(iOS)
        /// If a screen recording / AirPlay mirroring is already active when the overlay appears, or
        /// begins while it is up, expire the reveal (safest behavior). Uses only the public
        /// `UIScreen.isCaptured` API.
        private func startCaptureMonitor() {
            if UIScreen.main.isCaptured { model.onScreenCapture() }
        }
    #endif
}

/// A discoverable "Secret Message" toggle for the composer, in the app's visual language. Clearly
/// distinguishes the armed state (so it can't be sent accidentally) and can be cancelled before send.
public struct SecretComposerToggle: View {
    @Binding private var isArmed: Bool
    public init(isArmed: Binding<Bool>) { self._isArmed = isArmed }

    public var body: some View {
        Button {
            isArmed.toggle()
        } label: {
            Image(systemName: isArmed ? "eye.slash.circle.fill" : "eye.slash.circle")
                .imageScale(.large)
                .foregroundStyle(isArmed ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                .frame(minWidth: Nedwons.minTouchTarget, minHeight: Nedwons.minTouchTarget)
        }
        .accessibilityLabel(Text("Secret message"))
        .accessibilityValue(Text(isArmed ? "On, this message will be view-once" : "Off"))
        .accessibilityHint(Text("Double tap to toggle sending a view-once secret message"))
    }
}
