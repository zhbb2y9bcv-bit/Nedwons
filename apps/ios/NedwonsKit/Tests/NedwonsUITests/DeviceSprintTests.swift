import Foundation
import XCTest

@testable import NedwonsKit
@testable import NedwonsUI

// MARK: - Item 7: App Attest

/// A stand-in for `DCAppAttestService`, which is unavailable in the Simulator and to SwiftPM tests.
private final class FakeAttestation: AppAttestationProviding, @unchecked Sendable {
    var supported = true
    var generateResult: Result<String, Error> = .success("key-1")
    var attestResult: Result<Data, Error> = .success(Data([0x01]))
    private(set) var generateCalls = 0
    private(set) var attestCalls = 0

    var isSupported: Bool { supported }

    func generateKey() async throws -> String {
        generateCalls += 1
        return try generateResult.get()
    }

    func attestKey(_ keyID: String, challenge: Data) async throws -> Data {
        attestCalls += 1
        return try attestResult.get()
    }
}

private final class MemoryStore: SecretStore, @unchecked Sendable {
    private var items: [String: Data] = [:]
    func save(_ data: Data, account: String, accessible: CFString) throws { items[account] = data }
    func load(account: String) throws -> Data? { items[account] }
    func delete(account: String) throws { items[account] = nil }
}

@MainActor
final class AppAttestCoordinatorTests: XCTestCase {
    private func coordinator(
        _ attestation: FakeAttestation, _ store: MemoryStore = MemoryStore()
    ) -> AppAttestCoordinator {
        AppAttestCoordinator(attestation: attestation, store: store)
    }

    private func run(
        _ coordinator: AppAttestCoordinator,
        challenge: Data = Data([0xAA]),
        submit: @escaping (String, Data, Data) async throws -> Void = { _, _, _ in }
    ) async {
        await coordinator.attestIfNeeded(requestChallenge: { challenge }, submit: submit)
    }

    func testUnsupportedHardwareIsNotAnError() async {
        let attestation = FakeAttestation()
        attestation.supported = false
        let subject = coordinator(attestation)
        await run(subject)
        XCTAssertEqual(subject.status, .unsupported)
        XCTAssertEqual(attestation.generateCalls, 0, "no key is minted where it cannot be used")
    }

    func testSuccessfulAttestationIsRecordedAndNotRepeated() async {
        let attestation = FakeAttestation()
        let store = MemoryStore()
        let subject = coordinator(attestation, store)

        var submitted: [String] = []
        await run(subject) { keyID, _, _ in submitted.append(keyID) }
        XCTAssertEqual(subject.status, .attested)
        XCTAssertEqual(submitted, ["key-1"])

        // A second launch (fresh coordinator, same store) must not re-attest.
        let second = coordinator(attestation, store)
        await run(second) { _, _, _ in XCTFail("already attested") }
        XCTAssertEqual(second.status, .attested)
    }

    /// `generateKey()` provisions a key WITH APPLE. Calling it per attempt would leak a new key
    /// every time and attest none of them twice.
    func testTheKeyIDIsReusedAcrossAttempts() async {
        let attestation = FakeAttestation()
        attestation.attestResult = .failure(AppAttestError.temporary)
        let store = MemoryStore()

        let first = coordinator(attestation, store)
        await run(first)
        XCTAssertEqual(attestation.generateCalls, 1)
        XCTAssertEqual(first.storedKeyID, "key-1", "the id is persisted before the round trip")

        let second = coordinator(attestation, store)
        await run(second)
        XCTAssertEqual(attestation.generateCalls, 1, "the provisioned key is reused, not re-minted")
        XCTAssertEqual(attestation.attestCalls, 2)
    }

    /// The one failure where retrying the same key can never work: drop it so the next launch
    /// provisions a fresh one.
    func testAnInvalidKeyIsDiscarded() async {
        let attestation = FakeAttestation()
        attestation.attestResult = .failure(AppAttestError.invalidKey)
        let store = MemoryStore()
        let subject = coordinator(attestation, store)

        await run(subject)
        XCTAssertEqual(subject.status, .failed("invalidKey"))
        XCTAssertNil(subject.storedKeyID, "a permanently rejected key must not be retried")
    }

    /// Retries are bounded per launch, so a device that cannot attest does not hammer Apple's
    /// per-app rate limit on every foreground.
    func testAttemptsAreBoundedPerLaunch() async {
        let attestation = FakeAttestation()
        attestation.attestResult = .failure(AppAttestError.temporary)
        let subject = coordinator(attestation)

        for _ in 0 ..< 10 { await run(subject) }
        XCTAssertLessThanOrEqual(attestation.attestCalls, 2)
    }

    /// A server that refuses the submission leaves the device un-attested but usable — attestation
    /// is defence in depth and must never block sign-in.
    func testASubmissionFailureIsRecordedNotThrown() async {
        struct Refused: Error {}
        let attestation = FakeAttestation()
        let subject = coordinator(attestation)
        await run(subject) { _, _, _ in throw Refused() }
        XCTAssertEqual(subject.status, .failed("attestation could not be submitted"))
    }
}

// MARK: - Item 8: recovery secret policy

final class RecoverySecretTests: XCTestCase {
    /// The bug this replaces: the UI accepted 12 characters while `auth-core` requires 20, so a
    /// 12–19 character phrase passed every check the screen made and was then refused by the
    /// server — after the user had written it down.
    func testAGeneratedCodeClearsTheServerFloorWithMargin() {
        let code = RecoverySecret.generate()
        let normalized = RecoverySecret.normalize(code)
        XCTAssertEqual(normalized.count, RecoverySecret.dataLength)
        XCTAssertGreaterThan(
            normalized.count, RecoverySecret.minimumNormalizedLength,
            "a generated code must clear auth-core's MIN_RECOVERY_SECRET_CHARS")
        XCTAssertTrue(RecoverySecret.isAcceptable(code))
    }

    func testEntropyIsWellBeyondBruteForce() {
        XCTAssertEqual(RecoverySecret.entropyBits, 160)
    }

    /// Crockford base32: no I, L, O or U, so a handwritten code cannot be misread.
    func testTheAlphabetExcludesAmbiguousLetters() {
        for ambiguous in ["I", "L", "O", "U"] {
            XCTAssertFalse(
                RecoverySecret.alphabet.contains(Character(ambiguous)),
                "\(ambiguous) is too easily confused with a digit")
        }
    }

    /// Deterministic bytes prove grouping and mapping without depending on randomness.
    func testGroupingAndMappingAreStable() {
        let code = RecoverySecret.generate(randomBytes: { count in
            (0 ..< count).map { UInt8($0 % 32) }
        })
        XCTAssertEqual(code.prefix(9), "0123-4567")
        XCTAssertEqual(RecoverySecret.normalize(code).count, 32)
    }

    /// A user retyping the code with different spacing or case must not be told it is wrong.
    func testNormalisationIsForgivingOfTranscription() {
        let code = RecoverySecret.generate()
        let mangled = code.lowercased().replacingOccurrences(of: "-", with: " ")
        XCTAssertEqual(RecoverySecret.normalize(mangled), RecoverySecret.normalize(code))
    }

    /// The floor is enforced on the client so the screen never accepts what the backend refuses.
    func testShortInputIsRejected() {
        XCTAssertFalse(RecoverySecret.isAcceptable("SHORT"))
        XCTAssertFalse(
            RecoverySecret.isAcceptable("ABCD-EFGH-JKMN-PQ"),
            "19 significant characters is below auth-core's floor of 20")
        XCTAssertTrue(RecoverySecret.isAcceptable("ABCD-EFGH-JKMN-PQRS-TVWX"))
    }

    /// Two generated codes must differ — a fixed code would be catastrophic here.
    func testGeneratedCodesAreUnique() {
        let codes = Set((0 ..< 50).map { _ in RecoverySecret.generate() })
        XCTAssertEqual(codes.count, 50)
    }
}

// MARK: - Item 9: acknowledged devices survive relaunch

final class DeviceAcknowledgementsTests: XCTestCase {
    private func store() -> (DeviceAcknowledgements, UserDefaults) {
        let suite = UserDefaults(suiteName: "nedwons.test.\(UUID().uuidString)")!
        return (DeviceAcknowledgements(defaults: suite), suite)
    }

    /// The point of persisting: `DeviceAuditBanner` alarms on any unacknowledged device, and an
    /// alarm that fires on every relaunch is one users learn to ignore.
    func testAcknowledgementsSurviveARelaunch() {
        let (acks, suite) = store()
        acks.acknowledge("device-a", for: "account-1")

        // A "relaunch" is a fresh value over the same backing store.
        let reloaded = DeviceAcknowledgements(defaults: suite)
        XCTAssertEqual(reloaded.acknowledged(for: "account-1"), ["device-a"])
    }

    /// Keyed per account: a shared phone must not let one account inherit the other's trust.
    func testAcknowledgementsAreScopedToAnAccount() {
        let (acks, _) = store()
        acks.acknowledge("device-a", for: "account-1")
        acks.acknowledge("device-b", for: "account-2")

        XCTAssertEqual(acks.acknowledged(for: "account-1"), ["device-a"])
        XCTAssertEqual(acks.acknowledged(for: "account-2"), ["device-b"])
    }

    func testClearingOneAccountLeavesTheOther() {
        let (acks, _) = store()
        acks.acknowledge("device-a", for: "account-1")
        acks.acknowledge("device-b", for: "account-2")
        acks.clear(for: "account-1")

        XCTAssertTrue(acks.acknowledged(for: "account-1").isEmpty)
        XCTAssertEqual(acks.acknowledged(for: "account-2"), ["device-b"])
    }

    func testAcknowledgingIsIdempotent() {
        let (acks, _) = store()
        acks.acknowledge("device-a", for: "account-1")
        acks.acknowledge("device-a", for: "account-1")
        XCTAssertEqual(acks.acknowledged(for: "account-1"), ["device-a"])
    }
}
