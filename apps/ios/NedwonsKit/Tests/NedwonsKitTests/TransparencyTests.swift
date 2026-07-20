import CryptoKit
import XCTest

@testable import NedwonsKit

/// The Swift RFC 6962 verifier must agree with the Rust log byte for byte. The strongest check is
/// the live smoke (Rust generates proofs, Swift verifies); here we unit-test the verifier on
/// hand-built trees and pin the canonical STH encoding.
final class TransparencyTests: XCTestCase {
    private func leaf(_ s: String) -> Data { Transparency.hashLeaf(Data(s.utf8)) }

    func testInclusionTwoLeafTree() {
        let l0 = leaf("a")
        let l1 = leaf("b")
        let root = Transparency.hashNode(l0, l1)
        XCTAssertTrue(Transparency.verifyInclusion(leaf: l0, index: 0, treeSize: 2, proof: [l1], root: root))
        XCTAssertTrue(Transparency.verifyInclusion(leaf: l1, index: 1, treeSize: 2, proof: [l0], root: root))
        // Wrong root / wrong sibling → reject.
        var badRoot = root
        badRoot[badRoot.startIndex] ^= 0xff
        XCTAssertFalse(Transparency.verifyInclusion(leaf: l0, index: 0, treeSize: 2, proof: [l1], root: badRoot))
        XCTAssertFalse(Transparency.verifyInclusion(leaf: l0, index: 0, treeSize: 2, proof: [l0], root: root))
    }

    func testInclusionFourLeafTree() {
        let l = (0..<4).map { leaf("leaf-\($0)") }
        let left = Transparency.hashNode(l[0], l[1])
        let right = Transparency.hashNode(l[2], l[3])
        let root = Transparency.hashNode(left, right)
        // Proof for index 0 is [l1, right]; for index 2 is [l3, left].
        XCTAssertTrue(
            Transparency.verifyInclusion(leaf: l[0], index: 0, treeSize: 4, proof: [l[1], right], root: root))
        XCTAssertTrue(
            Transparency.verifyInclusion(leaf: l[2], index: 2, treeSize: 4, proof: [l[3], left], root: root))
        // A shuffled proof must fail.
        XCTAssertFalse(
            Transparency.verifyInclusion(leaf: l[0], index: 0, treeSize: 4, proof: [right, l[1]], root: root))
    }

    func testSTHEncodingIsCanonical() {
        let root = Data(repeating: 0xab, count: 32)
        let a = Transparency.encodeSTH(treeSize: 5, root: root, timestamp: 1_700_000_000)
        // Domain length prefix (27) + domain, matching the Rust encoder.
        XCTAssertEqual(Array(a.prefix(8)), [0, 0, 0, 0, 0, 0, 0, 27])
        XCTAssertEqual(a[a.index(a.startIndex, offsetBy: 8)...].prefix(27), Data("nedwons-transparency-sth-v1".utf8))
        XCTAssertEqual(a, Transparency.encodeSTH(treeSize: 5, root: root, timestamp: 1_700_000_000))
        XCTAssertNotEqual(a, Transparency.encodeSTH(treeSize: 6, root: root, timestamp: 1_700_000_000))
    }

    /// The account view decodes `revoked_at` (present on revocation leaves, absent on bindings) and
    /// `revocationLeaves(in:)` extracts exactly the revocations (ADR-0013 Slice 3, R-201).
    func testRevocationLeafExtraction() throws {
        let json = """
        {
          "tree_size": 3,
          "bindings": [
            {"leaf_index": 0, "device_id": "aa", "public_key": "04ab", "entry": "01", "proof": []},
            {"leaf_index": 1, "device_id": "bb", "public_key": "04cd", "entry": "02", "proof": ["ff"]},
            {"leaf_index": 2, "device_id": "bb", "public_key": "", "entry": "03", "proof": ["ee"], "revoked_at": 1700000000}
          ]
        }
        """
        let view = try JSONDecoder().decode(
            TransparencyAccountView.self, from: Data(json.utf8))

        // Bindings decode with nil revokedAt; the revocation carries its timestamp.
        XCTAssertNil(view.bindings[0].revokedAt)
        XCTAssertNil(view.bindings[1].revokedAt)
        XCTAssertEqual(view.bindings[2].revokedAt, 1_700_000_000)

        let revocations = NedwonsClient.revocationLeaves(in: view)
        XCTAssertEqual(
            revocations,
            [LoggedRevocation(deviceID: "bb", revokedAt: 1_700_000_000, leafIndex: 2)])
    }
}
