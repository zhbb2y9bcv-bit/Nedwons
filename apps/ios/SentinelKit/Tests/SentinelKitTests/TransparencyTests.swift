import CryptoKit
import XCTest

@testable import SentinelKit

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
        // Domain length prefix (28) + domain, matching the Rust encoder.
        XCTAssertEqual(Array(a.prefix(8)), [0, 0, 0, 0, 0, 0, 0, 28])
        XCTAssertEqual(a[a.index(a.startIndex, offsetBy: 8)...].prefix(28), Data("sentinel-transparency-sth-v1".utf8))
        XCTAssertEqual(a, Transparency.encodeSTH(treeSize: 5, root: root, timestamp: 1_700_000_000))
        XCTAssertNotEqual(a, Transparency.encodeSTH(treeSize: 6, root: root, timestamp: 1_700_000_000))
    }
}
