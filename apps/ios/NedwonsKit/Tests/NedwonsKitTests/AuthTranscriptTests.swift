import CryptoKit
import XCTest
@testable import NedwonsKit

final class AuthTranscriptTests: XCTestCase {
    /// The Swift encoder must reproduce the shared vector byte-for-byte
    /// (contracts/test-vectors/auth-transcript-login.hex), the same value the Rust golden
    /// test pins. This is the cross-platform interoperability guarantee for the transcript.
    func testMatchesSharedVector() {
        let fixedPublicKey = Data([0x04]) + Data((0 ..< 64).map { UInt8($0) })
        let input = AuthTranscript.sampleLoginVectorInput(publicKey: fixedPublicKey)
        let hex = Hex.encode(AuthTranscript.encode(input))

        let expected = [
            "000000136170702e6e6564776f6e732e617574682e7631000102000000100011223344",
            "5566778899aabbccddeeff000000100102030405060708090a0b0c0d0e0f100000004104",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223",
            "2425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0000002000010203",
            "0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000000003b9aca00",
            "00000010f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        ].joined()

        XCTAssertEqual(hex, expected)
    }

    /// A signature over a transcript verifies, and any tamper invalidates it. Proves the
    /// client signing path (CryptoKit P-256 / SHA-256, raw 64-byte signature) is coherent.
    func testSignVerifyRoundTrip() throws {
        let signer = SoftwareDeviceSigner()
        let input = AuthTranscript.sampleLoginVectorInput(publicKey: signer.publicKeyX963)
        let message = AuthTranscript.encode(input)
        let rawSignature = try signer.sign(message)

        let publicKey = try P256.Signing.PublicKey(x963Representation: signer.publicKeyX963)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: rawSignature)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))

        var tampered = message
        tampered[0] ^= 0xFF
        XCTAssertFalse(publicKey.isValidSignature(signature, for: tampered))
    }

    func testHexRoundTrip() {
        let data = Data([0x00, 0x04, 0xAB, 0xFF, 0x10])
        XCTAssertEqual(Hex.decode(Hex.encode(data)), data)
        XCTAssertNil(Hex.decode("xyz"))
        XCTAssertNil(Hex.decode("abc")) // odd length
    }
}
