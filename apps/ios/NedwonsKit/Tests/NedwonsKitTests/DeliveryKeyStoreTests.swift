import XCTest

@testable import NedwonsKit

final class DeliveryKeyStoreTests: XCTestCase {
    private func store() -> (DeliveryKeyStore, URL) {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("dak-\(UUID().uuidString).bin")
        return (DeliveryKeyStore(fileURL: url, atRestKey: Data(repeating: 7, count: 32)), url)
    }

    /// Our own K_r is generated once and then stable — a new one every launch would silently
    /// revoke every contact we had granted.
    func testOwnKeyIsGeneratedOnceAndPersists() {
        let (s, url) = store()
        let first = s.mineOrCreate()
        XCTAssertEqual(first.key.count, DeliveryAccessKey.keyLength)
        XCTAssertEqual(s.mineOrCreate(), first, "stable within a session")

        let reopened = DeliveryKeyStore(fileURL: url, atRestKey: Data(repeating: 7, count: 32))
        XCTAssertEqual(reopened.mineOrCreate(), first, "and across a relaunch")
    }

    /// The blob on disk must be ciphertext: K_r is a capability to deliver into our inbox.
    func testKeyMaterialIsNotStoredInPlaintext() {
        let (s, url) = store()
        let mine = s.mineOrCreate()
        let onDisk = try! Data(contentsOf: url)
        XCTAssertFalse(
            onDisk.range(of: mine.key) != nil, "K_r must not appear in the at-rest blob")
        // A wrong at-rest key yields nothing rather than garbage.
        let hostile = DeliveryKeyStore(fileURL: url, atRestKey: Data(repeating: 9, count: 32))
        XCTAssertNotEqual(hostile.mineOrCreate(), mine)
    }

    func testGrantsAreStoredAndRetrievedPerContact() {
        let (s, _) = store()
        let grant = DeliveryGrant(keyHex: String(repeating: "ab", count: 32), deviceIDs: ["d1", "d2"])
        s.storeGrant(grant, from: "peer-1")

        XCTAssertEqual(s.grant(from: "peer-1"), grant)
        XCTAssertNil(s.grant(from: "peer-2"))
        XCTAssertEqual(s.grantedKeys(), ["peer-1"])
        XCTAssertEqual(s.grant(from: "peer-1")?.key?.key.count, DeliveryAccessKey.keyLength)
    }

    /// Blocking forgets a contact's grant, so we stop being able to seal to them.
    func testForgettingAGrantRemovesTheAbilityToSealToThem() {
        let (s, _) = store()
        s.storeGrant(DeliveryGrant(keyHex: String(repeating: "cd", count: 32), deviceIDs: []), from: "peer-1")
        s.forgetGrant(from: "peer-1")
        XCTAssertNil(s.grant(from: "peer-1"))
        XCTAssertTrue(s.grantedKeys().isEmpty)
    }

    /// Rotating our key invalidates every previous grant, so everyone must be re-granted — that is
    /// what actually revokes a blocked contact at the relay.
    func testRotationClearsWhoWeHaveGranted() {
        let (s, _) = store()
        _ = s.mineOrCreate()
        s.markGranted(to: "peer-1")
        s.markGranted(to: "peer-2")
        XCTAssertTrue(s.hasGranted(to: "peer-1"))

        let fresh = DeliveryAccessKey.generate()
        s.rotateMine(to: fresh)
        XCTAssertEqual(s.mineOrCreate(), fresh)
        XCTAssertFalse(s.hasGranted(to: "peer-1"), "a rotation re-grants everyone")
        XCTAssertFalse(s.hasGranted(to: "peer-2"))
    }

    func testEraseRemovesEverything() {
        let (s, url) = store()
        _ = s.mineOrCreate()
        s.storeGrant(DeliveryGrant(keyHex: String(repeating: "ef", count: 32), deviceIDs: []), from: "p")
        s.eraseAll()
        XCTAssertTrue(s.grantedKeys().isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
    }
}
