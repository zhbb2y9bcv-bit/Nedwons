import CryptoKit
import Foundation
import NedwonsKit
import NedwonsUI
import XCTest

@testable import NedwonsAppKit

/// Real multi-device over the V27 setup queue, with the REAL MLS core end to end: a second
/// device of the same account is admitted to the account's conversations by a reconcile pass
/// (run by the account's own primary, or by any other member — whoever syncs first), and an
/// invite joiner's encryption completes with nobody tapping anything.
@MainActor
final class MultiDeviceTests: XCTestCase {
    private let conv = "c0" + String(repeating: "4", count: 30)

    /// Alice's phone creates a group with bob; alice's TABLET links later and starts receiving —
    /// including its own account's messages sent from the phone (device-level fan-out).
    func testLinkedSiblingDeviceJoinsTheConversation() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        // Same FIRST character ⇒ same account id under the Participant convention; different
        // last character ⇒ its own device id. This is alice's tablet.
        let tablet = Participant("alicx", relay: relay)
        XCTAssertEqual(tablet.accountID, alice.accountID, "sibling shares the account")
        XCTAssertNotEqual(tablet.deviceID, alice.deviceID)

        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        _ = try await bob.coordinator.syncOnce()

        // The tablet links (self-group register seeds it into the account's conversations,
        // queued for setup — modeled by the test hook) and publishes prekeys.
        await tablet.coordinator.ensureKeyPackages()
        relay.queueSetup(conversation: conv, account: alice.accountID, device: tablet.deviceID)

        // The PHONE's ordinary sync sets its sibling up; the tablet redeems the Welcome.
        await alice.coordinator.reconcileSetup()
        XCTAssertEqual(relay.pendingSetupCount, 0)
        _ = try await tablet.coordinator.syncOnce()

        // Now the tablet is a full participant: bob's message reaches BOTH of alice's devices,
        // and the phone's own send reaches the tablet (fan-out excludes only the sender device).
        // Bob merges the add-tablet commit first — a message he sent at the PRE-add epoch would
        // be, correctly and forever, unreadable by the tablet (pre-join history).
        _ = try await bob.coordinator.syncOnce()
        await bob.model.sendMessage("hello alices", to: conv)
        _ = try await alice.coordinator.syncOnce()
        _ = try await tablet.coordinator.syncOnce()
        XCTAssertEqual(alice.texts(in: conv).map(\.0), ["hello alices"])
        XCTAssertEqual(tablet.texts(in: conv).map(\.0), ["hello alices"])

        await alice.model.sendMessage("from my phone", to: conv)
        _ = try await tablet.coordinator.syncOnce()
        XCTAssertEqual(
            tablet.texts(in: conv).map(\.0), ["hello alices", "from my phone"],
            "the account's own other device carries the conversation too")
        // The tablet shows the account's message as INBOUND (sent elsewhere) — honest per-device
        // state; cross-device outbound merging is a display concern tracked separately.
    }

    /// An invite joiner is admitted by whichever member syncs first — the "Finish encryption
    /// setup" button's job, automated. Group name included, so their list shows the real title.
    func testInviteJoinerIsSetUpAutomaticallyOnMemberSync() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        let joiner = Participant("carol", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        _ = try await bob.coordinator.syncOnce()
        _ = await alice.coordinator.renameGroupIgnoringErrors(conv, to: "book club")
        _ = try await bob.coordinator.syncOnce()

        // The joiner accepts an invite link (server queues them) and has prekeys published.
        await joiner.coordinator.ensureKeyPackages()
        relay.queueSetup(conversation: conv, account: joiner.accountID, device: joiner.deviceID)

        // BOB — not the inviter — happens to sync first; his device completes the setup.
        await bob.coordinator.reconcileSetup()
        XCTAssertEqual(relay.pendingSetupCount, 0)
        _ = try await joiner.coordinator.syncOnce()

        // Alice merges bob's add-commit before sending, so her message is at the joiner's epoch.
        _ = try await alice.coordinator.syncOnce()
        await alice.model.sendMessage("welcome!", to: conv)
        _ = try await joiner.coordinator.syncOnce()
        XCTAssertEqual(joiner.texts(in: conv).map(\.0), ["welcome!"])
        XCTAssertEqual(
            joiner.model.groupNames[conv], "book club",
            "the E2EE group name was re-sent to the newcomer")
    }

    /// Two set-up members race to reconcile the same target: the claim lets exactly one perform
    /// the add — no double Welcome, no forked group.
    func testReconcileClaimPreventsDoubleAdds() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        // NOTE the Participant naming convention: device id = last letter — "dave" would collide
        // with "alicE"'s device. "frank" is collision-free.
        let carol = Participant("frank", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        _ = try await bob.coordinator.syncOnce()

        await carol.coordinator.ensureKeyPackages()
        let published = try await relay.availableKeyPackages(accessToken: "frank")
        relay.queueSetup(conversation: conv, account: carol.accountID, device: carol.deviceID)

        // Both members reconcile back to back. The second finds nothing left to do.
        await alice.coordinator.reconcileSetup()
        await bob.coordinator.reconcileSetup()
        XCTAssertEqual(relay.pendingSetupCount, 0)
        let remaining = try await relay.availableKeyPackages(accessToken: "frank")
        XCTAssertEqual(published - remaining, 1, "exactly one prekey consumed — one add, not two")

        _ = try await carol.coordinator.syncOnce()
        await alice.model.sendMessage("no forks here", to: conv)
        XCTAssertNil(alice.model.banner, "send must not fail: \(alice.model.banner ?? "")")
        XCTAssertEqual(alice.texts(in: conv).map(\.0), ["no forks here"], "sender's own log")
        _ = try await carol.coordinator.syncOnce()
        _ = try await bob.coordinator.syncOnce()
        XCTAssertEqual(carol.texts(in: conv).map(\.0), ["no forks here"])
        XCTAssertEqual(bob.texts(in: conv).map(\.0), ["no forks here"])
    }
}

extension ConversationCoordinator {
    /// Rename without failing the test on transient outbox retries — the assertions read state.
    fileprivate func renameGroupIgnoringErrors(_ conversationID: String, to name: String) async
        -> Bool
    {
        do {
            try await renameGroup(conversationID, to: name)
            return true
        } catch {
            return false
        }
    }
}
