import XCTest

@testable import NedwonsKit
@testable import NedwonsUI

final class AppConfigTests: XCTestCase {
    /// With no Info.plist config (the test bundle has none) the app falls back to the loopback dev
    /// server, and that dev default is correctly reported as NOT secure — so a device build that
    /// forgot to set a real https `NedwonsServerURL` is detectable rather than silently insecure.
    func testDevFallbackIsLoopbackAndInsecure() {
        XCTAssertEqual(AppConfig.serverURL, AppConfig.devServerURL)
        XCTAssertEqual(AppConfig.devServerURL.scheme, "http")
        XCTAssertFalse(AppConfig.isServerSecure, "the loopback dev default is not https")
    }

    func testNoPinnedLogKeyWithoutConfig() {
        // Absent config ⇒ dev TOFU (nil), not a bogus pinned key.
        XCTAssertNil(AppConfig.pinnedTransparencyLogKey)
    }
}
