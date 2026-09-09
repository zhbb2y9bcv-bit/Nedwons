import CryptoKit
import Foundation
import NedwonsKit
import NedwonsUI
import XCTest

@testable import NedwonsAppKit

/// Arc 6 over the REAL core + in-memory relay: disappearing timers, delete-for-everyone,
/// forwarding, and on-device search, driven exactly the way the UI drives them (model actions
/// wired by `attach`).
@MainActor
final class MessageToolsTests: XCTestCase {
    private let conv = "c0" + String(repeating: "2", count: 30)
    private let conv2 = "c0" + String(repeating: "3", count: 30)

    private func pairedConversation() async throws -> (InMemoryRelay, Participant, Participant) {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        _ = try await bob.coordinator.syncOnce()
        return (relay, alice, bob)
    }

    func testDisappearingTimerTravelsAndPublishes() async throws {
        let (_, alice, bob) = try await pairedConversation()

        await alice.model.setDisappearTimer(3600, in: conv)
        XCTAssertEqual(alice.model.disappearTimer(for: conv), 3600, "sender applies on send")
        _ = try await bob.coordinator.syncOnce()
        XCTAssertEqual(bob.model.disappearTimer(for: conv), 3600, "receiver learns from ciphertext")

        await alice.model.setDisappearTimer(0, in: conv)
        _ = try await bob.coordinator.syncOnce()
        XCTAssertEqual(bob.model.disappearTimer(for: conv), 0)
    }

    func testDeleteForEveryoneTombstonesBothSides() async throws {
        let (_, alice, bob) = try await pairedConversation()

        await alice.model.sendMessage("wrong chat, sorry", to: conv)
        _ = try await bob.coordinator.syncOnce()
        let line = try XCTUnwrap(alice.model.threadLines[conv]?.last)
        XCTAssertFalse(line.deleted)

        await alice.model.deleteForEveryone(line, in: conv)
        let mine = try XCTUnwrap(alice.model.threadLines[conv]?.first { $0.id == line.id })
        XCTAssertTrue(mine.deleted)
        XCTAssertNil(mine.quotableText, "a deleted message quotes as nothing")

        _ = try await bob.coordinator.syncOnce()
        let theirs = try XCTUnwrap(
            bob.model.threadLines[conv]?.first { $0.messageID == line.messageID })
        XCTAssertTrue(theirs.deleted, "the author's retraction reached the recipient")
        XCTAssertTrue(
            bob.texts(in: conv).allSatisfy { $0.0.isEmpty },
            "the words are gone from the thread — only the tombstone row remains")
    }

    func testForwardCarriesTextToAnotherConversation() async throws {
        let (relay, alice, bob) = try await pairedConversation()
        // A second conversation between the same two people.
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv2, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv2, memberAccountIDs: [bob.accountID])
        _ = try await bob.coordinator.syncOnce()

        await alice.model.sendMessage("worth passing on", to: conv)
        _ = try await bob.coordinator.syncOnce()
        let original = try XCTUnwrap(bob.model.threadLines[conv]?.last)

        // Bob forwards Alice's message into the second conversation.
        await bob.model.forward(original, from: conv, to: conv2)
        _ = try await alice.coordinator.syncOnce()
        XCTAssertEqual(alice.texts(in: conv2).map(\.0), ["worth passing on"])
        XCTAssertEqual(
            alice.texts(in: conv2).map(\.1), [false],
            "forwarded by bob, so it arrives as bob's message")
    }

    func testSearchFindsAcrossConversationsAndSkipsDeleted() async throws {
        let (relay, alice, bob) = try await pairedConversation()
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv2, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv2, memberAccountIDs: [bob.accountID])

        await alice.model.sendMessage("the eagle lands at noon", to: conv)
        await alice.model.sendMessage("no eagles here", to: conv2)
        await alice.model.sendMessage("unrelated", to: conv)

        alice.model.searchMessages("EAGLE")
        XCTAssertEqual(alice.model.messageSearchHits.count, 2, "case-insensitive, cross-conversation")
        XCTAssertEqual(alice.model.messageSearchHits.map(\.mine), [true, true])

        // A deleted message stops matching.
        let line = try XCTUnwrap(
            alice.model.threadLines[conv]?.first { $0.quotableText?.contains("eagle") == true })
        await alice.model.deleteForEveryone(line, in: conv)
        alice.model.searchMessages("eagle")
        XCTAssertEqual(alice.model.messageSearchHits.count, 1)

        alice.model.searchMessages("   ")
        XCTAssertEqual(alice.model.messageSearchHits.count, 0, "blank query matches nothing")
    }
}
