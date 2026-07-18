import XCTest

@testable import SentinelKit

final class AppAttestTests: XCTestCase {
    /// Off real hardware (the test host / Simulator / macOS), App Attest is unsupported and the
    /// operations fail closed with `.unsupported` — never a silent success that would let an
    /// emulator masquerade as a genuine device.
    func testUnsupportedOffDeviceAndFailsClosed() async {
        let attest = AppAttestation()
        XCTAssertFalse(attest.isSupported, "App Attest is unavailable on the test host")

        do {
            _ = try await attest.generateKey()
            XCTFail("generateKey must throw off real hardware")
        } catch let e as AppAttestError {
            XCTAssertEqual(e, .unsupported)
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        do {
            _ = try await attest.attestKey("k", challenge: Data("nonce".utf8))
            XCTFail("attestKey must throw off real hardware")
        } catch let e as AppAttestError {
            XCTAssertEqual(e, .unsupported)
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        do {
            _ = try await attest.generateAssertion("k", clientData: Data("req".utf8))
            XCTFail("generateAssertion must throw off real hardware")
        } catch let e as AppAttestError {
            XCTAssertEqual(e, .unsupported)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
}
