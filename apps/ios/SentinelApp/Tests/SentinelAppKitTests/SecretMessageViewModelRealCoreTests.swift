import MlsFfi
import SentinelUI
import XCTest

@testable import SentinelAppKit

/// Deterministic monotonic clock — no real time elapses.
private final class FakeClock: MonotonicClock, @unchecked Sendable {
    private let lock = NSLock()
    private var ms: UInt64
    init(_ start: UInt64 = 0) { ms = start }
    func set(_ v: UInt64) { lock.lock(); ms = v; lock.unlock() }
    func nowMs() -> UInt64 { lock.lock(); defer { lock.unlock() }; return ms }
}

/// Drives the SwiftUI `SecretMessageViewModel` over the **real** Rust MLS core (via
/// `MlsClientSecretEngine` → `MlsClient`), with a fake clock. This closes the gap the report noted:
/// the view-model orchestration is here proven against the actual state machine, not a fake engine.
/// Two real clients exchange the secret through the genuine MLS pipeline first.
@MainActor
final class SecretMessageViewModelRealCoreTests: XCTestCase {
    private let key = Data(repeating: 7, count: 32)
    private func tmp(_ t: String) -> String { NSTemporaryDirectory() + "app-\(t)-\(UUID().uuidString)" }

    /// Alice sends `body` as a secret; Bob processes it and returns (bobClient, secretID).
    private func deliverSecret(_ body: String) throws -> (MlsClient, Data) {
        let alice = try MlsClient.createGroup(
            identity: Data("alice".utf8), dbPath: tmp("a"), atRestKey: key)
        let bob = try MlsClient.newJoiner(
            identity: Data("bob".utf8), dbPath: tmp("b"), atRestKey: key)
        let add = try alice.addMember(keyPackage: try bob.keyPackage())
        try bob.joinGroup(welcome: add.welcome)

        let handle = try alice.enqueueSecret(body: Data(body.utf8))
        let envelope = try alice.encrypt(localId: handle.localId)
        guard case .secretSealed = try bob.processInbound(envelopeId: 1, ciphertext: envelope) else {
            throw XCTSkip("expected sealed")
        }
        return (bob, handle.secretId)
    }

    func testViewModelDrivesTheRealCoreThroughTheFullLifecycle() throws {
        let (bob, sid) = try deliverSecret("launch code 42")
        let clock = FakeClock(0)
        let vm = SecretMessageViewModel(
            secretID: sid, engine: MlsClientSecretEngine(client: bob), clock: clock)

        // Sealed until tapped; delivery does not start the timer even far in the future.
        XCTAssertEqual(vm.display, .sealed)
        clock.set(1_000_000); vm.tick()
        XCTAssertEqual(vm.display, .sealed)
        clock.set(0)

        // Tap → exact 3s countdown (driven by the real Rust deadlines).
        vm.beginReveal()
        XCTAssertEqual(vm.display, .countdown(3))
        clock.set(1_000); vm.tick(); XCTAssertEqual(vm.display, .countdown(2))
        clock.set(2_000); vm.tick(); XCTAssertEqual(vm.display, .countdown(1))

        // Visible for the 10s window; the plaintext comes from the real decrypted secret.
        clock.set(3_000); vm.tick()
        XCTAssertEqual(vm.display, .visible(text: "launch code 42", fade: 1))
        clock.set(3_000 + 8_750); vm.tick()  // in the fade window
        if case .visible(_, let fade) = vm.display {
            XCTAssertEqual(fade, 0.5, accuracy: 0.06)
        } else { XCTFail("expected fading visible") }

        // Expires into the tombstone at exactly 13s; the real core scrubbed the body.
        clock.set(13_000); vm.tick()
        XCTAssertEqual(vm.display, .tombstone)
        XCTAssertNil(try bob.secretVisibleBody(secretId: sid, nowMs: 13_000))
    }

    func testScreenshotConsumesInTheRealCore() throws {
        let (bob, sid) = try deliverSecret("burn")
        let clock = FakeClock(0)
        let vm = SecretMessageViewModel(
            secretID: sid, engine: MlsClientSecretEngine(client: bob), clock: clock)
        vm.beginReveal()
        clock.set(4_000); vm.tick()
        if case .visible = vm.display {} else { XCTFail("should be visible") }

        vm.onScreenCapture()  // forwards consume() to the real core
        XCTAssertEqual(vm.display, .tombstone)
        // The Rust core itself now reports Consumed — the UI and core agree.
        XCTAssertEqual(try bob.secretPhase(secretId: sid, nowMs: 5_000), .consumed)
        XCTAssertNil(try bob.secretVisibleBody(secretId: sid, nowMs: 5_000))
    }

    func testFailedRevealDoesNotShowPlaintext_realCoreRejectsDoubleTap() throws {
        let (bob, sid) = try deliverSecret("once")
        let clock = FakeClock(0)
        let vm = SecretMessageViewModel(
            secretID: sid, engine: MlsClientSecretEngine(client: bob), clock: clock)
        vm.beginReveal()
        clock.set(500)
        vm.beginReveal()  // real core rejects the second begin (InvalidMessage); no restart
        clock.set(13_000); vm.tick()
        XCTAssertEqual(vm.display, .tombstone)
    }

    /// ADR-0015 through Swift: revealing via the engine (with a broadcast path) EMITS a consumption
    /// envelope that a peer group member applies as `.secretConsumedRemotely`. This proves the
    /// adapter's fan-out wiring over the real core; the full two-recipient-device semantics (where
    /// the peer's OWN copy is consumed) are proven in `mls-core`'s
    /// `revealing_on_one_device_consumes_it_on_the_other`.
    func testRevealFansOutAConsumptionMessageAPeerApplies() throws {
        // `sender` sends a secret to `me`; `sender` is also the peer that applies the consumption.
        let sender = try MlsClient.createGroup(
            identity: Data("sender".utf8), dbPath: tmp("s"), atRestKey: key)
        let me = try MlsClient.newJoiner(identity: Data("me".utf8), dbPath: tmp("me"), atRestKey: key)
        let add = try sender.addMember(keyPackage: try me.keyPackage())
        try me.joinGroup(welcome: add.welcome)

        let handle = try sender.enqueueSecret(body: Data("shared".utf8))
        let env = try sender.encrypt(localId: handle.localId)
        _ = try me.processInbound(envelopeId: 1, ciphertext: env)  // `me` holds it sealed

        // Reveal on `me` via the engine, capturing the broadcast consumption envelope.
        var broadcast: Data?
        let engine = MlsClientSecretEngine(client: me) { broadcast = $0 }
        let vm = SecretMessageViewModel(secretID: handle.secretId, engine: engine, clock: FakeClock(0))
        vm.beginReveal()

        let consumption = try XCTUnwrap(broadcast, "reveal should fan out a consumption message")
        guard case let .secretConsumedRemotely(sid) = try sender.processInbound(
            envelopeId: 2, ciphertext: consumption)
        else { return XCTFail("peer should see a consumption message") }
        XCTAssertEqual(sid, handle.secretId)
    }

    func testTombstoneTextComesFromTheRealCore() throws {
        let (bob, _) = try deliverSecret("x")
        let engine = MlsClientSecretEngine(client: bob)
        XCTAssertEqual(engine.tombstoneText, "a secret message has been sent")
    }
}
