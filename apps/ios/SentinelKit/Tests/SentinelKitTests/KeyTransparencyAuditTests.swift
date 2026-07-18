import XCTest

@testable import SentinelKit

final class KeyTransparencyAuditTests: XCTestCase {
    func testMatchingSetsAreOk() {
        let r = KeyTransparencyAudit.classify(
            loggedActive: ["phone", "tablet"], expected: ["phone", "tablet"])
        XCTAssertEqual(r, .ok)
    }

    func testAnUnexpectedLoggedDeviceIsTheAlarm() {
        // The log binds a device the user never enrolled — a server-injected key.
        let r = KeyTransparencyAudit.classify(
            loggedActive: ["phone", "tablet", "attacker"], expected: ["phone", "tablet"])
        XCTAssertEqual(r, .unexpectedDevices(["attacker"]))
    }

    func testAMissingExpectedDeviceIsSofterThanAnUnexpectedOne() {
        // An enrollment not yet propagated to the log: flagged, but not an injection alarm.
        let r = KeyTransparencyAudit.classify(
            loggedActive: ["phone"], expected: ["phone", "tablet"])
        XCTAssertEqual(r, .missingDevices(["tablet"]))
    }

    func testBothDiscrepanciesAtOnce() {
        let r = KeyTransparencyAudit.classify(
            loggedActive: ["phone", "attacker"], expected: ["phone", "tablet"])
        XCTAssertEqual(r, .discrepancy(unexpected: ["attacker"], missing: ["tablet"]))
    }

    func testResultsAreSortedForStableComparison() {
        let r = KeyTransparencyAudit.classify(
            loggedActive: ["z", "a", "phone"], expected: ["phone"])
        XCTAssertEqual(r, .unexpectedDevices(["a", "z"]))
    }
}
