import Foundation
import XCTest

@testable import NedwonsUI

/// Item 6: a Release build must refuse to run with development settings. These tests are the
/// enforcement — the validator is a pure function over `BuildSettings`, so every rule is checked
/// here rather than discovered after a TestFlight upload.
final class BuildConfigurationTests: XCTestCase {
    /// A fully, correctly configured production build.
    private func productionSettings() -> BuildSettings {
        BuildSettings(
            channel: .release,
            serverURL: URL(string: "https://relay.nedwons.app")!,
            transparencyKeyHex: String(repeating: "ab", count: 65),
            bundleID: "app.nedwons.demo",
            appGroup: "group.app.nedwons.demo",
            keychainAccessGroupSuffix: "app.nedwons.shared",
            teamIdentifierPrefix: "ABCDE12345",
            apsEnvironment: "production",
            appAttestEnvironment: "production",
            apnsTopic: "app.nedwons.demo")
    }

    func testACorrectlyConfiguredReleaseBuildHasNoFaults() {
        XCTAssertEqual(BuildConfiguration.faults(in: productionSettings()), [])
    }

    /// The headline rule: a shipped build must never point at the developer's own machine.
    func testReleasePointingAtLocalhostIsRejected() {
        for host in ["http://127.0.0.1:8097", "http://localhost:8097", "https://localhost:8443"] {
            var settings = productionSettings()
            settings.serverURL = URL(string: host)!
            let faults = BuildConfiguration.faults(in: settings)
            XCTAssertTrue(
                faults.contains(where: {
                    if case .serverURLIsLocalhost = $0 { return true }
                    return false
                }),
                "\(host) is unreachable from a device and must fail validation")
        }
    }

    func testReleaseOverPlainHTTPIsRejected() {
        var settings = productionSettings()
        settings.serverURL = URL(string: "http://relay.nedwons.app")!
        XCTAssertTrue(
            BuildConfiguration.faults(in: settings).contains(
                .serverURLNotHTTPS("http://relay.nedwons.app")))
    }

    func testReleaseWithoutAServerURLIsRejected() {
        var settings = productionSettings()
        settings.serverURL = nil
        XCTAssertTrue(BuildConfiguration.faults(in: settings).contains(.serverURLMissing))
    }

    /// Without a pinned key the client trusts the first log key it is handed — which is the
    /// substitution key transparency exists to detect.
    func testReleaseWithoutATransparencyKeyIsRejected() {
        var settings = productionSettings()
        settings.transparencyKeyHex = nil
        XCTAssertTrue(BuildConfiguration.faults(in: settings).contains(.transparencyKeyMissing))
    }

    /// A malformed key is silently ignored at runtime, so it is a fault in EVERY channel.
    func testMalformedTransparencyKeyIsRejectedInEveryChannel() {
        for channel in [BuildChannel.debug, .staging, .release] {
            var settings = productionSettings()
            settings.channel = channel
            settings.transparencyKeyHex = "not-hex-at-all"
            XCTAssertTrue(
                BuildConfiguration.faults(in: settings).contains(.transparencyKeyMalformed),
                "\(channel) must reject a malformed pinned key")
        }
    }

    /// Development entitlements are the classic thing left behind. A development aps-environment
    /// means every push goes to the sandbox gateway and silently never arrives.
    func testReleaseWithDevelopmentEntitlementsIsRejected() {
        var settings = productionSettings()
        settings.apsEnvironment = "development"
        settings.appAttestEnvironment = "development"
        let faults = BuildConfiguration.faults(in: settings)
        XCTAssertTrue(faults.contains(.developmentPushEntitlement("development")))
        XCTAssertTrue(faults.contains(.developmentAppAttestEntitlement("development")))
    }

    /// The app group roots the store the extension opens; a mismatch means the two targets read
    /// different containers while both appear to work.
    func testAppGroupMustBelongToTheBundle() {
        var settings = productionSettings()
        settings.appGroup = "group.app.nedwons.other"
        XCTAssertTrue(
            BuildConfiguration.faults(in: settings).contains(
                .appGroupDoesNotMatchBundle(
                    appGroup: "group.app.nedwons.other", bundleID: "app.nedwons.demo")))
    }

    /// The APNs topic IS the bundle id; a mismatch addresses every push to an app that is not there.
    func testApnsTopicMustMatchTheBundleID() {
        var settings = productionSettings()
        settings.apnsTopic = "app.nedwons.staging"
        XCTAssertTrue(
            BuildConfiguration.faults(in: settings).contains(
                .apnsTopicMismatch(topic: "app.nedwons.staging", bundleID: "app.nedwons.demo")))
    }

    /// Without these the extension reads its own private Keychain and every push degrades to a
    /// generic wake — the failure that is invisible in the Simulator.
    func testShippedBuildsRequireTheSharedGroups() {
        for channel in [BuildChannel.staging, .release] {
            var settings = productionSettings()
            settings.channel = channel
            settings.appGroup = nil
            settings.keychainAccessGroupSuffix = nil
            settings.teamIdentifierPrefix = nil
            let faults = BuildConfiguration.faults(in: settings)
            XCTAssertTrue(faults.contains(.appGroupMissing), "\(channel)")
            XCTAssertTrue(faults.contains(.keychainAccessGroupMissing), "\(channel)")
            XCTAssertTrue(faults.contains(.teamIdentifierPrefixMissing), "\(channel)")
        }
    }

    /// The other half of the contract: development must stay convenient. A Debug build talking to
    /// loopback with no pinned key and no provisioned groups is CORRECT, and must not be flagged —
    /// a validator that cried wolf in Debug would simply be switched off.
    func testDebugAgainstLoopbackIsPerfectlyValid() {
        let settings = BuildSettings(
            channel: .debug,
            serverURL: URL(string: "http://127.0.0.1:8097")!,
            transparencyKeyHex: nil,
            bundleID: "app.nedwons.demo",
            appGroup: nil,
            keychainAccessGroupSuffix: nil,
            teamIdentifierPrefix: nil,
            apsEnvironment: "development",
            appAttestEnvironment: "development",
            apnsTopic: nil)
        XCTAssertEqual(BuildConfiguration.faults(in: settings), [])
    }

    /// Staging is signed and runs on real devices, so it gets the transport and identifier rules —
    /// but not the pinned-key rule, since staging runs its own log.
    func testStagingRequiresHTTPSButNotAPinnedKey() {
        var settings = productionSettings()
        settings.channel = .staging
        settings.transparencyKeyHex = nil
        XCTAssertEqual(BuildConfiguration.faults(in: settings), [])

        settings.serverURL = URL(string: "http://staging.nedwons.app")!
        XCTAssertTrue(
            BuildConfiguration.faults(in: settings).contains(
                .serverURLNotHTTPS("http://staging.nedwons.app")))
    }

    /// An unset channel must default to Debug. Defaulting to Release would make an unconfigured
    /// build terminate at launch; defaulting to Debug makes it merely permissive, which is the
    /// right direction for a value that is missing by accident.
    func testAnUnsetChannelDefaultsToDebug() {
        XCTAssertEqual(BuildChannel.current(bundle: Bundle(for: Self.self)), .debug)
    }
}
