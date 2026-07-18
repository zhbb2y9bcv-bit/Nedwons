import XCTest

@testable import SentinelKit

final class SealedSenderPolicyTests: XCTestCase {
    func testBlockDropOnlyDropsBlockedSenders() {
        let blocked: Set<String> = ["mallory", "eve"]
        XCTAssertTrue(
            SealedSenderPolicy.shouldDropDecrypted(verifiedSenderAccountID: "mallory", blocked: blocked))
        XCTAssertFalse(
            SealedSenderPolicy.shouldDropDecrypted(verifiedSenderAccountID: "bob", blocked: blocked))
    }

    func testCanSendSealedOnlyWithAGrantedKey() {
        let granted: Set<String> = ["bob"]
        XCTAssertTrue(SealedSenderPolicy.canSendSealed(to: "bob", grantedKeys: granted))
        // A non-contact has no K_r → falls back to the identified (message-request) path.
        XCTAssertFalse(SealedSenderPolicy.canSendSealed(to: "stranger", grantedKeys: granted))
    }

    func testRotateOnBlockExcludesTheBlockedAndRegrantsToTheRest() {
        let approved: Set<String> = ["bob", "carol", "mallory"]
        let rotation = SealedSenderPolicy.rotateOnBlock(approvedContacts: approved, blocking: "mallory")
        XCTAssertEqual(rotation.regrantTo, ["bob", "carol"], "blocked account is not re-granted")
        XCTAssertEqual(rotation.newKey.key.count, 32)
    }

    func testRotationProducesAFreshKey() {
        let approved: Set<String> = ["bob"]
        let a = SealedSenderPolicy.rotateOnBlock(approvedContacts: approved, blocking: "x")
        let b = SealedSenderPolicy.rotateOnBlock(approvedContacts: approved, blocking: "x")
        XCTAssertNotEqual(a.newKey.key, b.newKey.key, "each rotation mints a new K_r")
        // The new key's verifier is what gets registered to revoke old holders at the relay.
        XCTAssertEqual(a.newKey.verifier.count, 32)
    }
}
