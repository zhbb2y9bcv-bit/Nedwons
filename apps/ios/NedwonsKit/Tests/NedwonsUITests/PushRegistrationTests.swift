import XCTest

@testable import NedwonsUI

/// The APNs lifecycle (#4). The interesting cases are all about ORDERING: the device token and the
/// session arrive independently, and the pre-existing code registered only when the session
/// happened to come first — which is the rarer ordering on a real device.
@MainActor
final class PushRegistrationTests: XCTestCase {
    /// Records what the coordinator asked to be registered, and can be made to fail.
    final class Recorder: @unchecked Sendable {
        private(set) var registered: [Data] = []
        var failNext = false

        func register(_ token: Data) async throws {
            if failNext {
                failNext = false
                throw NedwonsClientStubError.refused
            }
            registered.append(token)
        }
    }

    enum NedwonsClientStubError: Error { case refused }

    private func make(_ recorder: Recorder) -> PushRegistrationCoordinator {
        PushRegistrationCoordinator { token in try await recorder.register(token) }
    }

    private let tokenOne = Data([0xde, 0xad, 0xbe, 0xef])
    private let tokenTwo = Data([0xca, 0xfe, 0xba, 0xbe])

    /// The ordering that used to register nothing: APNs hands over the token at launch, long
    /// before the user signs in. Holding it and registering on sign-in is the whole point.
    func testTokenArrivingBeforeSignInIsRegisteredOnSignIn() async {
        let recorder = Recorder()
        let coordinator = make(recorder)

        await coordinator.apnsTokenReceived(tokenOne)
        XCTAssertTrue(recorder.registered.isEmpty, "nothing to register against yet")

        await coordinator.sessionEstablished(accountID: "account-a")
        XCTAssertEqual(recorder.registered, [tokenOne])
    }

    /// The other ordering: signed in first, token arrives later.
    func testTokenArrivingAfterSignInRegistersImmediately() async {
        let recorder = Recorder()
        let coordinator = make(recorder)

        await coordinator.sessionEstablished(accountID: "account-a")
        XCTAssertTrue(recorder.registered.isEmpty)

        await coordinator.apnsTokenReceived(tokenOne)
        XCTAssertEqual(recorder.registered, [tokenOne])
    }

    /// iOS rotates the token with no signal other than re-delivering it here, so a changed value
    /// must be treated exactly like a first one.
    func testRotatedTokenIsReRegistered() async {
        let recorder = Recorder()
        let coordinator = make(recorder)

        await coordinator.sessionEstablished(accountID: "account-a")
        await coordinator.apnsTokenReceived(tokenOne)
        await coordinator.apnsTokenReceived(tokenTwo)

        XCTAssertEqual(recorder.registered, [tokenOne, tokenTwo])
    }

    /// An unchanged pair is not re-POSTed. Every foreground would otherwise be a pointless
    /// authenticated write — and, on a proof-enforcing server, a pointless signature.
    func testUnchangedPairIsNotReRegistered() async {
        let recorder = Recorder()
        let coordinator = make(recorder)

        await coordinator.sessionEstablished(accountID: "account-a")
        await coordinator.apnsTokenReceived(tokenOne)
        await coordinator.apnsTokenReceived(tokenOne)
        await coordinator.sessionEstablished(accountID: "account-a")

        XCTAssertEqual(recorder.registered, [tokenOne], "registered exactly once")
    }

    /// The APNs token belongs to the INSTALL, not the user. A second account signing in on the
    /// same device usually sees no new token, so without clearing state on sign-out it would be
    /// considered already registered and would never be woken.
    func testASecondAccountOnTheSameDeviceRegistersAgain() async {
        let recorder = Recorder()
        let coordinator = make(recorder)

        await coordinator.sessionEstablished(accountID: "account-a")
        await coordinator.apnsTokenReceived(tokenOne)
        XCTAssertEqual(recorder.registered, [tokenOne])

        coordinator.signedOut()
        await coordinator.sessionEstablished(accountID: "account-b")

        XCTAssertEqual(
            recorder.registered, [tokenOne, tokenOne],
            "the same token must be registered again for the new account")
    }

    /// A failed registration is not remembered as done, so the next trigger retries it.
    func testFailedRegistrationIsRetriedOnTheNextTrigger() async {
        let recorder = Recorder()
        let coordinator = make(recorder)
        recorder.failNext = true

        await coordinator.sessionEstablished(accountID: "account-a")
        await coordinator.apnsTokenReceived(tokenOne)
        XCTAssertTrue(recorder.registered.isEmpty, "the attempt failed")
        XCTAssertNotNil(coordinator.lastFailure)

        // A later trigger (foreground, re-auth) tries again rather than assuming success.
        await coordinator.sessionEstablished(accountID: "account-a")
        XCTAssertEqual(recorder.registered, [tokenOne])
    }

    /// Signed out with a token in hand: nothing is sent, because there is no session to attach it
    /// to and a registration without one would be meaningless.
    func testNoRegistrationWhileSignedOut() async {
        let recorder = Recorder()
        let coordinator = make(recorder)

        await coordinator.apnsTokenReceived(tokenOne)
        coordinator.signedOut()

        XCTAssertTrue(recorder.registered.isEmpty)
    }

    /// A system-level registration failure is surfaced rather than swallowed: "no pushes" and "no
    /// messages" look identical from the outside otherwise.
    func testSystemRegistrationFailureIsRecorded() async {
        let coordinator = make(Recorder())
        coordinator.apnsRegistrationFailed("no valid aps-environment entitlement")
        XCTAssertEqual(coordinator.lastFailure, "no valid aps-environment entitlement")

        // A subsequent successful token delivery clears it.
        await coordinator.apnsTokenReceived(tokenOne)
        XCTAssertNil(coordinator.lastFailure)
    }

    /// The wire format APNs tokens are registered in.
    func testTokenHexEncoding() {
        XCTAssertEqual(apnsTokenHex(Data([0x00, 0x0f, 0xff])), "000fff")
        XCTAssertEqual(apnsTokenHex(Data()), "")
    }
}
