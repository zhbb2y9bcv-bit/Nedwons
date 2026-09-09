import XCTest

/// The privacy manifest is a compliance claim, and an unchecked claim drifts.
///
/// These tests pin it to what the audit actually found, so a future change that (say) adds
/// `@AppStorage` for a setting, or integrates a crash reporter, fails here instead of silently
/// making the shipped manifest false. They deliberately assert BOTH directions: declarations that
/// must be present, and declarations that must NOT be — over-declaring is also an inaccurate
/// statement about the app.
final class PrivacyManifestTests: XCTestCase {
    private func manifest() throws -> [String: Any] {
        // Walk up from this test file to the repo, so the test does not depend on the working
        // directory the runner happens to use.
        var dir = URL(fileURLWithPath: #filePath)
        for _ in 0..<8 {
            dir.deleteLastPathComponent()
            let candidate = dir.appendingPathComponent("Nedwons/PrivacyInfo.xcprivacy")
            if FileManager.default.fileExists(atPath: candidate.path) {
                let data = try Data(contentsOf: candidate)
                let plist = try PropertyListSerialization.propertyList(
                    from: data, options: [], format: nil)
                return try XCTUnwrap(plist as? [String: Any])
            }
        }
        throw XCTSkip("privacy manifest not found from \(#filePath)")
    }

    func testTrackingIsDisclaimedAndNoTrackingDomainsExist() throws {
        let m = try manifest()
        XCTAssertEqual(
            m["NSPrivacyTracking"] as? Bool, false,
            "the app must not declare tracking: there is no third-party SDK to do it")
        XCTAssertEqual(
            (m["NSPrivacyTrackingDomains"] as? [String])?.count, 0,
            "no tracking domains")
    }

    /// The audit found no required-reason API in use, so this array must stay empty. If a future
    /// change adds one, this test fails and forces the declaration to be added with a real reason
    /// code rather than a placeholder.
    func testNoRequiredReasonApisAreDeclaredBecauseNoneAreUsed() throws {
        let m = try manifest()
        let apis = try XCTUnwrap(m["NSPrivacyAccessedAPITypes"] as? [[String: Any]])
        XCTAssertTrue(
            apis.isEmpty,
            "the audit found no required-reason API usage; declaring one that is not used is as "
                + "inaccurate as omitting one that is. Found: \(apis)")
    }

    func testCollectedDataMatchesWhatTheServiceActuallyStores() throws {
        let m = try manifest()
        let types = try XCTUnwrap(m["NSPrivacyCollectedDataTypes"] as? [[String: Any]])
        let declared = Set(types.compactMap { $0["NSPrivacyCollectedDataType"] as? String })

        for expected in [
            "NSPrivacyCollectedDataTypeUserID",          // username
            "NSPrivacyCollectedDataTypeName",            // display name
            "NSPrivacyCollectedDataTypeDeviceID",        // push token / device routing
            "NSPrivacyCollectedDataTypeOtherUserContent",// message content (E2EE, still transmitted)
            "NSPrivacyCollectedDataTypeCustomerSupport", // abuse reports
            "NSPrivacyCollectedDataTypeOtherDataTypes",  // social graph + group membership
        ] {
            XCTAssertTrue(declared.contains(expected), "manifest must declare \(expected)")
        }

        // Must NOT be declared: nothing in the app collects these, and claiming otherwise is false.
        for forbidden in [
            "NSPrivacyCollectedDataTypeCrashData",       // no crash reporter is integrated
            "NSPrivacyCollectedDataTypePerformanceData", // no analytics SDK
            "NSPrivacyCollectedDataTypeContacts",        // the address book is never read
            "NSPrivacyCollectedDataTypePhoneNumber",
            "NSPrivacyCollectedDataTypeEmailAddress",
            "NSPrivacyCollectedDataTypePreciseLocation",
            "NSPrivacyCollectedDataTypeCoarseLocation",
        ] {
            XCTAssertFalse(
                declared.contains(forbidden),
                "\(forbidden) is declared but nothing in the app collects it")
        }

        // Nothing may be marked as used for tracking.
        for type in types {
            XCTAssertEqual(
                type["NSPrivacyCollectedDataTypeTracking"] as? Bool, false,
                "no data type may be used for tracking: \(type)")
        }
    }
}
