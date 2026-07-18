import CryptoKit
import XCTest

@testable import SentinelKit

final class SenderCertificateTests: XCTestCase {
    /// The Swift encoder must reproduce the Rust golden byte-for-byte (ADR-0012): a Rust-signed
    /// sender certificate must verify in the Swift recipient.
    func testMatchesRustGoldenVector() {
        let hex = Hex.encode(SenderCertificate.sampleVectorInput().canonicalBytes())
        let expected =
            "0000001b6170702e73656e74696e656c2e73656e6465722d636572742e763100000010a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a100000010b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b20000004104000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f000000006553f100"
        XCTAssertEqual(hex, expected)
    }

    /// A genuinely-signed certificate verifies before expiry, fails after, and a wrong key fails —
    /// the recipient's sealed-sender check.
    func testVerifyRespectsSignatureAndExpiry() throws {
        let certKey = P256.Signing.PrivateKey()
        let cert = SenderCertificate(
            accountID: Data(repeating: 0x01, count: 16),
            deviceID: Data(repeating: 0x02, count: 16),
            senderPublicKeyX963: P256.Signing.PrivateKey().publicKey.x963Representation,
            expiresAt: 1_000)
        let signature = try certKey.signature(for: cert.canonicalBytes()).rawRepresentation
        let certPub = certKey.publicKey.x963Representation

        XCTAssertTrue(cert.verify(signature: signature, certPublicKeyX963: certPub, now: 999))
        XCTAssertFalse(
            cert.verify(signature: signature, certPublicKeyX963: certPub, now: 1_001),
            "expired certificate is rejected")
        XCTAssertFalse(
            cert.verify(
                signature: signature,
                certPublicKeyX963: P256.Signing.PrivateKey().publicKey.x963Representation,
                now: 999),
            "a different cert key does not verify")
    }
}
