import Foundation
import XCTest

@testable import NedwonsKit
@testable import NedwonsUI

/// Verified-peer state: local, per-account, survives relaunch, cleared from view (not from disk)
/// on sign-out. The number/QR math itself is covered in NedwonsKitTests/SafetyNumberTests.
@MainActor
final class VerificationModelTests: XCTestCase {
    private func session(account: String) -> NedwonsClient.Session {
        NedwonsClient.Session(
            accountID: account, deviceID: "device-1", accessToken: "token",
            accessExpiresAt: .max, refreshToken: "refresh", refreshExpiresAt: .max)
    }

    private func model(store: MemoryVerifiedPeersStore, account: String) -> AppModel {
        let model = AppModel(baseURL: URL(string: "http://127.0.0.1:1")!)
        model.verifiedPeersStore = store
        model.session = session(account: account)
        return model
    }

    func testVerificationPersistsThroughTheStore() {
        let store = MemoryVerifiedPeersStore()
        let model = model(store: store, account: "alice")

        XCTAssertFalse(model.isPeerVerified("bob"))
        model.setPeerVerified("bob", true)
        XCTAssertTrue(model.isPeerVerified("bob"))
        XCTAssertEqual(store.byAccount["alice"], ["bob"])

        // A fresh model (relaunch) loads the same judgment back.
        let relaunched = self.model(store: store, account: "alice")
        relaunched.loadVerifiedPeers()
        XCTAssertTrue(relaunched.isPeerVerified("bob"))

        model.setPeerVerified("bob", false)
        XCTAssertFalse(model.isPeerVerified("bob"))
        XCTAssertEqual(store.byAccount["alice"], [])
    }

    func testVerificationIsScopedPerAccount() {
        let store = MemoryVerifiedPeersStore()
        let alice = model(store: store, account: "alice")
        alice.setPeerVerified("bob", true)

        let carol = model(store: store, account: "carol")
        carol.loadVerifiedPeers()
        XCTAssertFalse(carol.isPeerVerified("bob"), "another account's judgments must not leak in")
    }

    func testSignOutClearsThePublishedSetButKeepsTheStore() {
        let store = MemoryVerifiedPeersStore()
        let model = model(store: store, account: "alice")
        model.setPeerVerified("bob", true)

        model.signOut()
        XCTAssertFalse(model.isPeerVerified("bob"))
        XCTAssertEqual(store.byAccount["alice"], ["bob"], "the persisted judgment survives sign-out")
    }
}
