import Foundation
import XCTest

@testable import NedwonsKit

/// The safety-number construction (roadmap step 4). These pin the properties the screen relies
/// on: determinism, symmetry (both parties render identical digits), key-order independence, and
/// sensitivity — any key change moves the number.
final class SafetyNumberTests: XCTestCase {
    private let keyA = Data(repeating: 0xA1, count: 65)
    private let keyB = Data(repeating: 0xB2, count: 65)
    private let keyC = Data(repeating: 0xC3, count: 65)

    func testDisplayIsDeterministicAndWellFormed() {
        let one = SafetyNumber.displayGroups(
            accountID: "alice", keysX963: [keyA], peerAccountID: "bob", peerKeysX963: [keyB])
        let two = SafetyNumber.displayGroups(
            accountID: "alice", keysX963: [keyA], peerAccountID: "bob", peerKeysX963: [keyB])
        XCTAssertEqual(one, two)
        XCTAssertEqual(one.count, 12, "60 digits as 12 groups")
        for group in one {
            XCTAssertEqual(group.count, 5)
            XCTAssertTrue(group.allSatisfy(\.isNumber))
        }
    }

    func testBothPartiesSeeTheSameNumber() {
        let mine = SafetyNumber.displayGroups(
            accountID: "alice", keysX963: [keyA], peerAccountID: "bob", peerKeysX963: [keyB])
        let theirs = SafetyNumber.displayGroups(
            accountID: "bob", keysX963: [keyB], peerAccountID: "alice", peerKeysX963: [keyA])
        XCTAssertEqual(mine, theirs, "the number must not depend on which side computes it")

        let myPayload = SafetyNumber.qrPayload(
            accountID: "alice", keysX963: [keyA], peerAccountID: "bob", peerKeysX963: [keyB])
        let theirPayload = SafetyNumber.qrPayload(
            accountID: "bob", keysX963: [keyB], peerAccountID: "alice", peerKeysX963: [keyA])
        XCTAssertEqual(myPayload, theirPayload)
        XCTAssertTrue(myPayload.hasPrefix("nedwons-verify:1:"))
    }

    func testDeviceKeyOrderDoesNotMatter() {
        let sorted = SafetyNumber.displayGroups(
            accountID: "alice", keysX963: [keyA, keyB], peerAccountID: "bob", peerKeysX963: [keyC])
        let reversed = SafetyNumber.displayGroups(
            accountID: "alice", keysX963: [keyB, keyA], peerAccountID: "bob", peerKeysX963: [keyC])
        XCTAssertEqual(sorted, reversed, "device enumeration order is unspecified")
    }

    func testAnyKeyChangeChangesTheNumber() {
        let base = SafetyNumber.displayGroups(
            accountID: "alice", keysX963: [keyA], peerAccountID: "bob", peerKeysX963: [keyB])
        let peerKeyChanged = SafetyNumber.displayGroups(
            accountID: "alice", keysX963: [keyA], peerAccountID: "bob", peerKeysX963: [keyC])
        let peerAddedDevice = SafetyNumber.displayGroups(
            accountID: "alice", keysX963: [keyA], peerAccountID: "bob", peerKeysX963: [keyB, keyC])
        let differentPeer = SafetyNumber.displayGroups(
            accountID: "alice", keysX963: [keyA], peerAccountID: "eve", peerKeysX963: [keyB])
        XCTAssertNotEqual(base, peerKeyChanged)
        XCTAssertNotEqual(base, peerAddedDevice)
        XCTAssertNotEqual(base, differentPeer, "the account id is bound in, not just the keys")
    }

    func testPayloadMatchRejectsForeignAndFutureCodes() {
        let payload = SafetyNumber.qrPayload(
            accountID: "alice", keysX963: [keyA], peerAccountID: "bob", peerKeysX963: [keyB])
        XCTAssertTrue(
            SafetyNumber.payloadMatches(
                payload,
                accountID: "bob", keysX963: [keyB], peerAccountID: "alice", peerKeysX963: [keyA]))
        // A code for a different pair does not match.
        XCTAssertFalse(
            SafetyNumber.payloadMatches(
                payload,
                accountID: "alice", keysX963: [keyA], peerAccountID: "eve", peerKeysX963: [keyC]))
        // A future version prefix is "no match", never a crash or a silent pass.
        XCTAssertFalse(
            SafetyNumber.payloadMatches(
                "nedwons-verify:2:aa:bb",
                accountID: "alice", keysX963: [keyA], peerAccountID: "bob", peerKeysX963: [keyB]))
    }
}

/// Invite QR payloads: the scanner must only ever forward a well-formed token to the join
/// endpoint, whatever QR it was pointed at.
final class InviteCodeTests: XCTestCase {
    private let token = String(repeating: "ab", count: 32) // 64 hex chars

    func testRoundTrip() {
        XCTAssertEqual(InviteCode.parse(InviteCode.payload(token: token)), token)
    }

    func testBareTokenPasteIsAccepted() {
        XCTAssertEqual(InviteCode.parse("  \(token.uppercased())\n"), token)
    }

    func testGarbageIsRefused() {
        XCTAssertNil(InviteCode.parse("https://example.com/not-an-invite"))
        XCTAssertNil(InviteCode.parse("nedwons-invite:1:tooshort"))
        XCTAssertNil(InviteCode.parse("nedwons-invite:1:" + String(repeating: "zz", count: 32)))
        XCTAssertNil(InviteCode.parse(""))
        // A safety-number code is not an invite.
        XCTAssertNil(InviteCode.parse("nedwons-verify:1:aa:bb"))
    }
}
