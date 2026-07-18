import SwiftUI

// MARK: - Secret (view-once) message UI orchestration
//
// The SECURITY of the view-once lifecycle lives in Rust (`mls_core::secret` + `durable`): the
// state machine, the atomic + fail-closed reveal, the 3s/10s deadlines, expiry scrub, replay
// rejection, and crash recovery are all enforced and tested there and reached over the UniFFI
// `MlsClient` surface. This file is only PRESENTATION: it queries the engine for the current
// phase/body/remaining-time and maps that to what the overlay shows. It never reimplements the
// state machine and never holds decrypted secret text longer than a frame needs it.
//
// The controller is deliberately abstracted over a `SecretEngine` protocol + a `MonotonicClock`
// so the timing/lifecycle orchestration is deterministically testable with a fake clock, without
// the compiled xcframework. The real engine is a thin adapter over `MlsClient` (see
// `SecretEngine` docs); it lives in the app target that links SentinelMLS.

/// Reveal phase, mirroring `mls_ffi.SecretPhase` (kept local so SentinelUI stays free of the native
/// binding dependency and still type-checks with `swift build` on macOS).
public enum SecretPhase: Sendable, Equatable {
    case sealed
    case countdown
    case visible
    case consumed
    case unknown
}

/// The operations the overlay needs from the Rust core. A real conformance is a ~10-line adapter
/// over `MlsClient` (`beginSecretReveal`/`secretPhase`/`secretVisibleBody`/`secretRemaining`/
/// `consumeSecret`/`secretTombstoneText`), threading the app's monotonic `nowMs`. Every call maps
/// 1:1 to a `MlsClient` method, so the security checks (atomic persist, fail-closed, monotonic
/// guard, scrub) all happen in Rust — this protocol only forwards.
public protocol SecretEngine: AnyObject {
    /// Atomically begin the reveal. Throws (and reveals nothing) on an invalid transition or a
    /// failed state write — the caller must treat a throw as "stay sealed".
    func beginReveal(secretID: Data, nowMs: UInt64) throws
    func phase(secretID: Data, nowMs: UInt64) throws -> SecretPhase
    /// The plaintext iff currently visible; nil otherwise. Never cache the result.
    func visibleBody(secretID: Data, nowMs: UInt64) throws -> Data?
    /// (remaining countdown ms, remaining view ms) — both 0 outside that phase.
    func remaining(secretID: Data, nowMs: UInt64) throws -> (countdownMs: UInt64, viewMs: UInt64)
    /// Force the terminal tombstone (screenshot/capture detected, or overlay dismissed). Idempotent.
    func consume(secretID: Data) throws
    var tombstoneText: String { get }
}

/// Monotonic elapsed-time source (unaffected by wall-clock changes). Injected so tests are
/// deterministic and never wait real seconds.
public protocol MonotonicClock: Sendable {
    /// Milliseconds from an arbitrary fixed origin; only differences are meaningful.
    func nowMs() -> UInt64
}

/// Real monotonic clock: `DispatchTime` uptime is monotonic and immune to system-clock changes, so
/// "changing the system clock" cannot extend a window. It keeps counting while the app is
/// backgrounded (the deadline is measured in elapsed time, not foreground time).
public struct UptimeClock: MonotonicClock {
    public init() {}
    public func nowMs() -> UInt64 { DispatchTime.now().uptimeNanoseconds / 1_000_000 }
}

/// What the overlay should render right now. Derived purely from the engine + clock.
public enum SecretDisplay: Equatable {
    /// Not yet revealed — a sealed placeholder in the conversation (not the overlay).
    case sealed
    /// Countdown overlay showing this number (3, then 2, then 1) with "Secret message coming in".
    case countdown(Int)
    /// The secret text, with `fade` in 0...1 (1 = fully visible, 0 = unreadable by the deadline).
    case visible(text: String, fade: Double)
    /// Terminal tombstone (also the sealed placeholder's post-consumption state).
    case tombstone
    /// A generic, non-sensitive failure — shown instead of any plaintext when the engine throws.
    case error
}

/// Drives ONE secret message's overlay. `@MainActor` so all UI state changes are main-thread; the
/// conversation engine, network, and MLS work continue on their own actors/threads untouched.
@MainActor
public final class SecretMessageViewModel: ObservableObject {
    /// Fraction of the viewing window over which the text fades out (the final ~25%), so it is
    /// completely unreadable by the deadline with no extra readable time after it.
    public static let fadeFraction: Double = 0.25
    /// Total viewing window (ms) — mirrors `mls_core::secret::VIEW_MS`; used only to compute fade.
    public static let viewMs: UInt64 = 10_000

    @Published public private(set) var display: SecretDisplay = .sealed

    private let secretID: Data
    private let engine: SecretEngine
    private let clock: MonotonicClock

    public init(secretID: Data, engine: SecretEngine, clock: MonotonicClock = UptimeClock()) {
        self.secretID = secretID
        self.engine = engine
        self.clock = clock
        refresh()
    }

    /// The recipient tapped the sealed placeholder. Atomic + fail-closed in Rust; a throw keeps the
    /// message sealed and shows nothing.
    public func beginReveal() {
        do {
            try engine.beginReveal(secretID: secretID, nowMs: clock.nowMs())
            refresh()
        } catch {
            // Invalid transition (double tap / replay) or a failed state write → do not reveal.
            refresh()
        }
    }

    /// Recompute the display from the engine at the current time. The overlay calls this on a
    /// display-linked tick; it is idempotent and cheap (no plaintext retained between calls).
    public func tick() { refresh() }

    /// A screenshot or active screen capture was reported. Expire immediately and remove plaintext.
    public func onScreenCapture() {
        try? engine.consume(secretID: secretID)
        refresh()
    }

    /// Backgrounding hides plaintext immediately (the app-switcher cover handles snapshots); elapsed
    /// time keeps running in Rust, so returning shows only the remaining time — never a fresh window.
    public func onBackground() {
        // Nothing to persist — the deadline is already durable. Blank the display so no plaintext
        // sits in a view hierarchy that could be snapshotted.
        if case .visible = display { display = .visible(text: "", fade: 0) }
    }

    public func onForeground() { refresh() }

    private func refresh() {
        let now = clock.nowMs()
        let phase: SecretPhase
        do {
            phase = try engine.phase(secretID: secretID, nowMs: now)
        } catch {
            display = .error
            return
        }
        switch phase {
        case .sealed:
            display = .sealed
        case .countdown:
            let remaining = (try? engine.remaining(secretID: secretID, nowMs: now).countdownMs) ?? 0
            // 1..3: ceil(remaining/1000), clamped so it reads 3, 2, 1.
            let n = max(1, min(3, Int((remaining + 999) / 1000)))
            display = .countdown(n)
        case .visible:
            guard let body = (try? engine.visibleBody(secretID: secretID, nowMs: now)) ?? nil,
                let text = String(data: body, encoding: .utf8)
            else {
                // Visible per the state machine but no body (a race with expiry) → fail closed.
                display = .tombstone
                return
            }
            let viewRemaining = (try? engine.remaining(secretID: secretID, nowMs: now).viewMs) ?? 0
            display = .visible(text: text, fade: Self.fade(remainingMs: viewRemaining))
        case .consumed:
            display = .tombstone
        case .unknown:
            display = .error
        }
    }

    /// Fade opacity from remaining viewing ms: full until the final `fadeFraction`, then linearly to
    /// 0 at the deadline.
    static func fade(remainingMs: UInt64) -> Double {
        let fadeWindow = Double(viewMs) * fadeFraction
        let remaining = Double(remainingMs)
        if remaining >= fadeWindow { return 1 }
        return max(0, remaining / fadeWindow)
    }
}
