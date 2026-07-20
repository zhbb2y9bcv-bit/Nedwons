import CryptoKit
import XCTest

@testable import NedwonsKit

final class AtRestKeyTests: XCTestCase {
    func testDerivedKeyIsThirtyTwoBytesAndDeterministic() throws {
        let store = InMemorySecretStore()
        let h = AtRestKeyHierarchy(store: store)
        let k1 = try h.atRestKey(forStore: "conversation-A")
        let k2 = try h.atRestKey(forStore: "conversation-A")
        XCTAssertEqual(k1.count, 32)
        XCTAssertEqual(k1, k2, "same root + store id derives the same key")
    }

    func testDistinctStoresGetIndependentKeys() throws {
        let h = AtRestKeyHierarchy(store: InMemorySecretStore())
        let a = try h.atRestKey(forStore: "A")
        let b = try h.atRestKey(forStore: "B")
        XCTAssertNotEqual(a, b, "per-store info separation yields independent keys")
    }

    func testRootIsCreatedOnceAndReused() throws {
        let store = InMemorySecretStore()
        let h = AtRestKeyHierarchy(store: store)
        _ = try h.atRestKey(forStore: "A")
        let root1 = try XCTUnwrap(store.load(account: "at-rest-root-v1"))
        _ = try h.atRestKey(forStore: "B")
        let root2 = try XCTUnwrap(store.load(account: "at-rest-root-v1"))
        XCTAssertEqual(root1, root2, "the root key is generated once and reused")
        XCTAssertEqual(root1.count, 32)
    }

    func testKeysSurviveAcrossHierarchyInstancesOnTheSameStore() throws {
        // A relaunch: a new hierarchy over the same (Keychain-backed) store derives the same keys.
        let store = InMemorySecretStore()
        let k1 = try AtRestKeyHierarchy(store: store).atRestKey(forStore: "db")
        let k2 = try AtRestKeyHierarchy(store: store).atRestKey(forStore: "db")
        XCTAssertEqual(k1, k2)
    }

    func testWipingTheRootMakesKeysUnderivableThenRegenerates() throws {
        let store = InMemorySecretStore()
        let h = AtRestKeyHierarchy(store: store)
        let before = try h.atRestKey(forStore: "db")
        try h.wipeRoot()
        XCTAssertNil(try store.load(account: "at-rest-root-v1"), "root gone after wipe")
        // A fresh root is generated on next use → a DIFFERENT key (old blobs are now unreadable).
        let after = try h.atRestKey(forStore: "db")
        XCTAssertNotEqual(before, after)
    }

    func testMatchesAKnownHkdfVector() throws {
        // Pin the derivation so an accidental scheme change is caught. Root = 32 zero bytes.
        let store = InMemorySecretStore()
        try store.save(Data(repeating: 0, count: 32), account: "at-rest-root-v1", accessible: "" as CFString)
        let key = try AtRestKeyHierarchy(store: store).atRestKey(forStore: "vector")
        let expected = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(repeating: 0, count: 32)),
            info: Data("app.nedwons.at-rest.v1:vector".utf8),
            outputByteCount: 32
        ).withUnsafeBytes { Data($0) }
        XCTAssertEqual(key, expected)
    }
}
