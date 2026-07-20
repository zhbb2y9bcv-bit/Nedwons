import XCTest

@testable import NedwonsKit
@testable import NedwonsUI

final class DeviceAuditBannerTests: XCTestCase {
    func testNoAuditYetShowsNoBanner() {
        XCTAssertNil(DeviceAuditBanner.present(nil))
    }

    func testOkIsInformational() {
        let b = DeviceAuditBanner.present(.ok)
        XCTAssertEqual(b?.severity, .ok)
    }

    func testUnexpectedDeviceIsAnAlarm() {
        let b = DeviceAuditBanner.present(.unexpectedDevices(["attacker"]))
        XCTAssertEqual(b?.severity, .alarm)
        XCTAssertTrue(b?.text.contains("attacker") ?? false)
    }

    func testMissingDeviceIsAWarningNotAnAlarm() {
        let b = DeviceAuditBanner.present(.missingDevices(["tablet"]))
        XCTAssertEqual(b?.severity, .warning)
    }

    func testUnverifiableLogIsAnAlarm() {
        XCTAssertEqual(DeviceAuditBanner.present(.badSignature)?.severity, .alarm)
        XCTAssertEqual(DeviceAuditBanner.present(.logKeyChanged)?.severity, .alarm)
        XCTAssertEqual(DeviceAuditBanner.present(.badProof)?.severity, .alarm)
    }
}
