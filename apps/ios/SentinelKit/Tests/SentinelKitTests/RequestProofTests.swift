import CryptoKit
import XCTest

@testable import SentinelKit

final class RequestProofTests: XCTestCase {
    /// The Swift request-proof encoder must reproduce the Rust golden byte-for-byte, so the device
    /// signs exactly what the server verifies (ADR-0011).
    func testProofMatchesRustGoldenVector() {
        let hex = Hex.encode(RequestProof.sampleVectorInput().canonicalBytes())
        let expected =
            "000000146170702e73656e74696e656c2e64706f702e7631000100000004504f53540000001f2f76312f636f6e766572736174696f6e732f616162622f6d65737361676573000000200707070707070707070707070707070707070707070707070707070707070707000000006553f1000000001009090909090909090909090909090909"
        XCTAssertEqual(hex, expected)
    }

    /// A generated proof header parses and its signature verifies over the canonical bytes — the
    /// same check the server performs with `verify_p256`.
    func testProofHeaderSignsAndVerifies() throws {
        let signer = SoftwareDeviceSigner()
        let token = Data((0..<32).map { UInt8($0) })
        let nonce = Data(repeating: 0xAB, count: 16)
        let ts: UInt64 = 1_700_000_500
        let header = try RequestProof.header(
            signer: signer, accessToken: token, method: "GET", path: "/v1/inbox",
            timestamp: ts, nonce: nonce)

        XCTAssertTrue(header.hasPrefix("v1;ts=1700000500;nonce=\(Hex.encode(nonce));sig="))

        // Reconstruct the signed bytes and verify the signature the header carries.
        let sigHex = String(header.split(separator: ";").first { $0.hasPrefix("sig=") }!.dropFirst(4))
        let signature = Hex.decode(String(sigHex))!
        let expected = RequestProof(
            method: "GET", path: "/v1/inbox",
            accessTokenHash: Data(SHA256.hash(data: token)), timestamp: ts, nonce: nonce
        ).canonicalBytes()

        let key = try P256.Signing.PublicKey(x963Representation: signer.publicKeyX963)
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        XCTAssertTrue(key.isValidSignature(sig, for: expected))
    }
}
