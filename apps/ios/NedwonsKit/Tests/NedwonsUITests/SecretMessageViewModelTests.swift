import XCTest

@testable import NedwonsUI

/// A deterministic monotonic clock for tests — no real time elapses.
final class FakeClock: MonotonicClock, @unchecked Sendable {
    private let lock = NSLock()
    private var ms: UInt64
    init(_ start: UInt64 = 0) { ms = start }
    func set(_ v: UInt64) { lock.lock(); ms = v; lock.unlock() }
    func nowMs() -> UInt64 { lock.lock(); defer { lock.unlock() }; return ms }
}

/// A deterministic test double for the Rust engine. It mirrors ONLY the observable state-machine
/// contract (the security enforcement itself is tested in Rust): sealed→countdown(3s)→visible(10s)
/// →consumed, one begin, fail-closed, scrub-on-expiry, and an injectable state-write failure.
final class FakeSecretEngine: SecretEngine {
    private let countdownMs: UInt64 = 3_000
    private let viewMs: UInt64 = 10_000
    private var began = false
    private var countdownDeadline: UInt64 = 0
    private var viewDeadline: UInt64 = 0
    private var body: Data?
    private var forcedConsumed = false
    /// When true, the next `beginReveal` throws (simulates a failed atomic state write).
    var failNextBegin = false

    let tombstoneText = "a secret message has been sent"

    init(body: Data) { self.body = body }

    private func phaseNow(_ now: UInt64) -> SecretPhase {
        if forcedConsumed { return .consumed }
        if !began { return .sealed }
        if now >= viewDeadline { body = nil; return .consumed }
        if now >= countdownDeadline { return .visible }
        return .countdown
    }

    func beginReveal(secretID: Data, nowMs: UInt64) throws {
        if failNextBegin { failNextBegin = false; throw Err.state }
        guard !began, !forcedConsumed else { throw Err.state }  // one opportunity only
        began = true
        countdownDeadline = nowMs + countdownMs
        viewDeadline = nowMs + countdownMs + viewMs
    }
    func phase(secretID: Data, nowMs: UInt64) throws -> SecretPhase { phaseNow(nowMs) }
    func visibleBody(secretID: Data, nowMs: UInt64) throws -> Data? {
        phaseNow(nowMs) == .visible ? body : nil
    }
    func remaining(secretID: Data, nowMs: UInt64) throws -> (countdownMs: UInt64, viewMs: UInt64) {
        switch phaseNow(nowMs) {
        case .countdown: return (countdownDeadline - nowMs, 0)
        case .visible: return (0, viewDeadline - nowMs)
        default: return (0, 0)
        }
    }
    func consume(secretID: Data) throws { forcedConsumed = true; body = nil }
    enum Err: Error { case state }
}

@MainActor
final class SecretMessageViewModelTests: XCTestCase {
    private func make(_ body: String = "launch code 42") -> (SecretMessageViewModel, FakeClock, FakeSecretEngine) {
        let clock = FakeClock(0)
        let engine = FakeSecretEngine(body: Data(body.utf8))
        let vm = SecretMessageViewModel(secretID: Data([1, 2, 3]), engine: engine, clock: clock)
        return (vm, clock, engine)
    }

    func testStartsSealedAndDoesNotRevealWithoutTap() {
        let (vm, clock, _) = make()
        XCTAssertEqual(vm.display, .sealed)
        // Time passing while sealed must not start any timer.
        clock.set(999_999); vm.tick()
        XCTAssertEqual(vm.display, .sealed)
    }

    func testExactThreeSecondCountdownTransitions() {
        let (vm, clock, _) = make()
        vm.beginReveal()
        XCTAssertEqual(vm.display, .countdown(3))
        clock.set(1_000); vm.tick(); XCTAssertEqual(vm.display, .countdown(2))
        clock.set(2_000); vm.tick(); XCTAssertEqual(vm.display, .countdown(1))
        clock.set(2_999); vm.tick(); XCTAssertEqual(vm.display, .countdown(1))
        clock.set(3_000); vm.tick()
        if case .visible = vm.display {} else { XCTFail("visible at exactly 3s, got \(vm.display)") }
    }

    func testExactTenSecondWindowAndFadeCompleteByDeadline() {
        let (vm, clock, _) = make("hello")
        vm.beginReveal()
        clock.set(3_000); vm.tick()
        XCTAssertEqual(vm.display, .visible(text: "hello", fade: 1))
        // Fade still full at 75% through the window (7.5s remaining), begins in the final 25%.
        clock.set(3_000 + 7_500); vm.tick()
        XCTAssertEqual(vm.display, .visible(text: "hello", fade: 1))
        // Halfway through the fade window (1.25s left of a 2.5s fade) → ~0.5 opacity.
        clock.set(3_000 + 8_750); vm.tick()
        if case .visible(_, let fade) = vm.display {
            XCTAssertEqual(fade, 0.5, accuracy: 0.05)
        } else { XCTFail("expected visible with partial fade") }
        // Unreadable (or consumed) exactly at the 13s deadline — no extra readable time after.
        clock.set(13_000); vm.tick()
        XCTAssertEqual(vm.display, .tombstone)
    }

    func testDoubleTapGrantsNoSecondWindow() {
        let (vm, clock, _) = make()
        vm.beginReveal()
        clock.set(500)
        vm.beginReveal()  // second tap — rejected by the engine, must not restart
        vm.tick()
        // Still on the ORIGINAL timeline: near the end of the countdown, not reset to 3.
        XCTAssertEqual(vm.display, .countdown(3))  // ceil((3000-500)/1000)=3, original deadline
        clock.set(13_000); vm.tick()
        XCTAssertEqual(vm.display, .tombstone)
    }

    func testFailedStateWriteDoesNotReveal() {
        let (vm, _, engine) = make()
        engine.failNextBegin = true
        vm.beginReveal()
        XCTAssertEqual(vm.display, .sealed, "a failed atomic state write must not reveal")
    }

    func testScreenshotExpiresImmediately() {
        let (vm, clock, _) = make("secret")
        vm.beginReveal()
        clock.set(3_500); vm.tick()
        if case .visible = vm.display {} else { XCTFail("should be visible") }
        vm.onScreenCapture()
        XCTAssertEqual(vm.display, .tombstone, "a screenshot removes the plaintext immediately")
    }

    func testBackgroundHidesPlaintextAndDeadlineStillPasses() {
        let (vm, clock, _) = make("shh")
        vm.beginReveal()
        clock.set(4_000); vm.tick()
        vm.onBackground()  // hide plaintext immediately
        XCTAssertEqual(vm.display, .visible(text: "", fade: 0))
        // Deadline passes while backgrounded; on return it is consumed, not re-shown.
        clock.set(20_000); vm.onForeground()
        XCTAssertEqual(vm.display, .tombstone)
    }

    func testBackgroundBeforeDeadlineShowsOnlyRemainingTime() {
        let (vm, clock, _) = make("shh")
        vm.beginReveal()
        clock.set(4_000); vm.tick()          // 9s of viewing left
        vm.onBackground()
        clock.set(6_000); vm.onForeground()  // returned before deadline
        if case .visible(let t, _) = vm.display {
            XCTAssertEqual(t, "shh")          // shown again, same window (never a new 10s)
        } else { XCTFail("should still be visible with remaining time") }
        clock.set(13_000); vm.tick()
        XCTAssertEqual(vm.display, .tombstone)
    }

    func testTombstoneTextIsExact() {
        let (_, _, engine) = make()
        XCTAssertEqual(engine.tombstoneText, "a secret message has been sent")
        XCTAssertEqual(SecretTombstoneView().textForTesting, "a secret message has been sent")
    }

    func testFadeCurve() {
        XCTAssertEqual(SecretMessageViewModel.fade(remainingMs: 10_000), 1)
        XCTAssertEqual(SecretMessageViewModel.fade(remainingMs: 2_500), 1)      // fade starts here
        XCTAssertEqual(SecretMessageViewModel.fade(remainingMs: 1_250), 0.5, accuracy: 0.001)
        XCTAssertEqual(SecretMessageViewModel.fade(remainingMs: 0), 0)          // unreadable at deadline
    }
}
