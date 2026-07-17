import CryptoKit
import XCTest

@testable import SentinelKit

/// Guards Gate 0 finding R-G0-2: the app must enroll a device key once and reload the *same* key
/// for later logins (device binding, INV-2), and must fail closed on hardware-less devices rather
/// than silently downgrade. The Secure Enclave availability is injected so these run on any host.
final class DeviceIdentityTests: XCTestCase {
    /// The exact bug that existed before: a fresh key per launch. Enrolling then reloading must
    /// yield the SAME public key, and a signature from the reloaded key must verify against it.
    func testSoftwareEnrollReloadIsTheSameKey() throws {
        let store = InMemoryDeviceKeyStore()
        let identity = DeviceIdentity(store: store, secureEnclaveAvailable: false)

        let enrolled = try identity.provision(policy: .allowSoftwareFallback)
        XCTAssertEqual(enrolled.assurance, .software)

        let reloaded = try XCTUnwrap(identity.loadEnrolled())
        XCTAssertEqual(reloaded.assurance, .software)
        XCTAssertEqual(
            enrolled.signer.publicKeyX963, reloaded.signer.publicKeyX963,
            "reloaded key must equal the enrolled key — otherwise login signs a different key (INV-2)"
        )

        // A signature from the reloaded key verifies under the enrolled public key.
        let message = Data("device-binding".utf8)
        let signature = try reloaded.signer.sign(message)
        let publicKey = try P256.Signing.PublicKey(x963Representation: enrolled.signer.publicKeyX963)
        let ecdsa = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        XCTAssertTrue(publicKey.isValidSignature(ecdsa, for: message))
    }

    /// Fail closed: no Secure Enclave + requireHardware ⇒ refuse to enroll (no silent software key).
    func testRequireHardwareFailsClosedWithoutEnclave() {
        let identity = DeviceIdentity(store: InMemoryDeviceKeyStore(), secureEnclaveAvailable: false)
        XCTAssertThrowsError(try identity.provision(policy: .requireHardware)) { error in
            XCTAssertEqual(error as? DeviceIdentityError, .secureHardwareUnavailable)
        }
    }

    /// A device that never enrolled has no key to load (caller should register or recover).
    func testLoadEnrolledIsNilBeforeProvisioning() throws {
        let identity = DeviceIdentity(store: InMemoryDeviceKeyStore(), secureEnclaveAvailable: false)
        XCTAssertNil(try identity.loadEnrolled())
    }

    /// Reset forgets the enrolled key.
    func testResetForgetsTheKey() throws {
        let store = InMemoryDeviceKeyStore()
        let identity = DeviceIdentity(store: store, secureEnclaveAvailable: false)
        _ = try identity.provision(policy: .allowSoftwareFallback)
        XCTAssertNotNil(try identity.loadEnrolled())
        try identity.reset()
        XCTAssertNil(try identity.loadEnrolled())
    }
}
