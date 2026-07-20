import CryptoKit
import XCTest

@testable import NedwonsKit

final class MembershipTests: XCTestCase {
    /// The Swift manifest encoder must reproduce the shared vector byte-for-byte
    /// (contracts/test-vectors/membership-manifest-add.hex), the same bytes the Rust golden test
    /// pins. This is the cross-platform interoperability guarantee for ADR-0010 membership.
    func testManifestMatchesSharedVector() {
        let hex = Hex.encode(MembershipManifest.sampleAddVectorInput().canonicalBytes())
        // Byte-identical to the Rust golden + contracts/test-vectors/membership-manifest-add.hex.
        let expected =
            "000000196170702e6e6564776f6e732e6d656d626572736869702e76310100000010070707070707070707070707070707070000000000000004000000000000000500000020090909090909090909090909090909090909090909090909090909090909090900000010010101010101010101010101010101010000000100000010aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000010bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00000000000000100202020202020202020202020202020200000000000003e8"
        XCTAssertEqual(hex, expected)
    }

    /// The recipient's `MembershipEvent.verifyManifestSignature` accepts a genuine device signature
    /// over the exact stored manifest bytes and rejects a wrong key — the check the app runs
    /// against the actor's transparency-logged key before merging a commit.
    func testMembershipEventSignatureVerification() throws {
        let signer = SoftwareDeviceSigner()
        let manifest = MembershipManifest.sampleAddVectorInput()
        let manifestBytes = manifest.canonicalBytes()
        let signature = try signer.sign(manifestBytes)

        let json: [String: Any] = [
            "control_type": 1, "prev_epoch": 4, "next_epoch": 5,
            "commit_hash": Hex.encode(manifest.commitHash),
            "actor_device": Hex.encode(manifest.actorDevice),
            "actor_account": Hex.encode(Data(repeating: 0x33, count: 16)),
            "added": [[
                "account_id": Hex.encode(manifest.added[0].account),
                "device_id": Hex.encode(manifest.added[0].device),
            ]],
            "removed": [String](),
            "idempotency_key": Hex.encode(manifest.idempotencyKey),
            "expires_at": 1000,
            "manifest": Hex.encode(manifestBytes),
            "signature": Hex.encode(signature),
        ]
        let data = try JSONSerialization.data(withJSONObject: json)
        let event = try JSONDecoder().decode(MembershipEvent.self, from: data)

        XCTAssertEqual(event.actorAccount, Hex.encode(Data(repeating: 0x33, count: 16)))
        XCTAssertTrue(event.verifyManifestSignature(deviceKeyX963: signer.publicKeyX963))
        // A different key must not verify (the anti-substitution property).
        XCTAssertFalse(
            event.verifyManifestSignature(deviceKeyX963: SoftwareDeviceSigner().publicKeyX963))
    }

    /// A device signature over the manifest verifies (CryptoKit P-256, raw 64-byte), and any field
    /// change invalidates it — the same signer path the backend verifies with `verify_p256`.
    func testManifestSignVerifyRoundTrip() throws {
        let signer = SoftwareDeviceSigner()
        let manifest = MembershipManifest.sampleAddVectorInput()
        let message = manifest.canonicalBytes()
        let rawSignature = try signer.sign(message)

        let publicKey = try P256.Signing.PublicKey(x963Representation: signer.publicKeyX963)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: rawSignature)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))

        var tampered = message
        tampered[tampered.count - 1] ^= 0xFF  // flip a byte of expires_at
        XCTAssertFalse(publicKey.isValidSignature(signature, for: tampered))
    }
}
