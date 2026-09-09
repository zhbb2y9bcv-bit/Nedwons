import Foundation
import MlsFfi
import NedwonsKit
import NedwonsUI
import XCTest

@testable import NedwonsAppKit

/// An in-memory relay with the semantics the pipeline depends on: per-account prekey queues,
/// per-device inboxes with monotonically increasing ids, fan-out to the conversation's OTHER member
/// devices, targeted delivery, idempotency-key dedup, at-least-once ack, plus switches to fail or
/// refuse sends. It never reads a ciphertext.
final class InMemoryRelay: ConversationRelay, @unchecked Sendable {
    struct Device { let accountID: String; let deviceID: String }

    private let lock = NSLock()
    /// `NSLock.lock()` is forbidden in async contexts; the scoped form is not, and nothing here
    /// suspends while holding it.
    private func sync<T>(_ body: () throws -> T) rethrows -> T { try lock.withLock(body) }
    private var devices: [String: Device] = [:]  // token → device
    private var prekeys: [String: [(device: String, keyPackage: Data)]] = [:]  // account → queue
    private var members: [String: Set<String>] = [:]  // conversation → device ids
    private var inboxes: [String: [(id: Int, conversation: String, sender: String, ciphertext: Data)]] = [:]
    private var nextID = 1
    private var seenKeys: Set<String> = []
    var failSends = false
    var refuseSendsWith: String?  // an `{"error": code}` body → 403
    private(set) var deliveries = 0

    /// Bootstrap itself fans out a growth commit, so tests that count what THEY sent zero the
    /// counter once setup is done.
    func resetCounters() { sync { deliveries = 0 } }

    func register(token: String, accountID: String, deviceID: String) {
        lock.lock(); defer { lock.unlock() }
        devices[token] = Device(accountID: accountID, deviceID: deviceID)
    }

    /// What `POST /v1/groups` does server-side: routing membership for every member device.
    func createConversation(_ id: String, memberDevices: [String]) {
        lock.lock(); defer { lock.unlock() }
        members[id] = Set(memberDevices)
    }

    private func device(_ token: String) throws -> Device {
        guard let d = devices[token] else { throw NedwonsClient.ClientError.http(status: 401, body: #"{"error":"denied"}"#) }
        return d
    }

    private func enqueue(to device: String, conversation: String, sender: String, ciphertext: Data) {
        inboxes[device, default: []].append((nextID, conversation, sender, ciphertext))
        nextID += 1
    }

    func publishKeyPackage(accessToken: String, keyPackage: Data) async throws {
        try sync {
            let d = try device(accessToken)
            prekeys[d.accountID, default: []].append((d.deviceID, keyPackage))
        }
    }

    func availableKeyPackages(accessToken: String) async throws -> Int {
        try sync {
            return prekeys[try device(accessToken).accountID]?.count ?? 0
        }
    }

    func claimKeyPackage(accessToken: String, accountID: String) async throws -> ClaimedKeyPackage {
        try sync {
            _ = try device(accessToken)
            guard var queue = prekeys[accountID], !queue.isEmpty else {
                throw NedwonsClient.ClientError.http(status: 404, body: #"{"error":"no_key_package"}"#)
            }
            let claimed = queue.removeFirst()
            prekeys[accountID] = queue
            return ClaimedKeyPackage(deviceID: claimed.device, keyPackage: Hex.encode(claimed.keyPackage))
        }
    }

    func sendWelcome(
        accessToken: String, conversationID: String, recipientDevice: String, ciphertext: Data,
        idempotencyKey: Data
    ) async throws {
        try sync {
            let d = try device(accessToken)
            guard seenKeys.insert("\(d.deviceID)/\(recipientDevice)/\(Hex.encode(idempotencyKey))").inserted else { return }
            enqueue(to: recipientDevice, conversation: conversationID, sender: d.deviceID, ciphertext: ciphertext)
        }
    }

    func sendMessage(
        accessToken: String, conversationID: String, ciphertext: Data, idempotencyKey: Data
    ) async throws -> Int {
        try sync {
            let d = try device(accessToken)
            if failSends { throw NedwonsClient.ClientError.transport("simulated outage") }
            if let code = refuseSendsWith {
                throw NedwonsClient.ClientError.http(status: 403, body: #"{"error":"\#(code)"}"#)
            }
            guard members[conversationID]?.contains(d.deviceID) == true else {
                throw NedwonsClient.ClientError.http(status: 403, body: #"{"error":"forbidden"}"#)
            }
            guard seenKeys.insert("\(d.deviceID)/*/\(Hex.encode(idempotencyKey))").inserted else { return 0 }
            var count = 0
            for recipient in members[conversationID]!.sorted() where recipient != d.deviceID {
                enqueue(to: recipient, conversation: conversationID, sender: d.deviceID, ciphertext: ciphertext)
                count += 1
            }
            deliveries += count
            return count
        }
    }

    /// The blob store: opaque bytes keyed by id, exactly what the real relay holds.
    private var blobs: [String: Data] = [:]
    /// Serve these bytes for the next download, whatever was uploaded — the relay swapping objects.
    var substituteBlob: Data?
    var failUploads = false

    func uploadAttachment(accessToken: String, conversationID: String, ciphertext: Data) async throws
        -> String
    {
        try sync {
            let d = try device(accessToken)
            if failUploads { throw NedwonsClient.ClientError.transport("simulated outage") }
            guard members[conversationID]?.contains(d.deviceID) == true else {
                throw NedwonsClient.ClientError.http(status: 403, body: #"{"error":"forbidden"}"#)
            }
            let id = (0..<16).map { _ in String(format: "%02x", Int.random(in: 0...255)) }.joined()
            blobs[id] = ciphertext
            return id
        }
    }

    func downloadAttachment(accessToken: String, blobID: String) async throws -> Data {
        try sync {
            _ = try device(accessToken)
            if let substitute = substituteBlob { return substitute }
            guard let bytes = blobs[blobID] else {
                throw NedwonsClient.ClientError.http(status: 410, body: #"{"error":"gone"}"#)
            }
            return bytes
        }
    }

    /// What the relay is holding for a blob — used to prove it is not the file.
    func storedBlob(_ id: String) -> Data? { sync { blobs[id] } }
    var blobCount: Int { sync { blobs.count } }

    func fetchInbox(accessToken: String, waitSeconds: Int) async throws -> [InboxEnvelope] {
        try sync {
            let d = try device(accessToken)
            let rows = (inboxes[d.deviceID] ?? []).map { row -> [String: Any] in
                [
                    "id": row.id, "conversation_id": row.conversation, "sender_device": row.sender,
                    "ciphertext": Hex.encode(row.ciphertext), "sealed": false, "self_group": false,
                ]
            }
            let data = try JSONSerialization.data(withJSONObject: rows)
            return try JSONDecoder().decode([InboxEnvelope].self, from: data)
        }
    }

    func ackInbox(accessToken: String, ids: [Int]) async throws {
        try sync {
            let d = try device(accessToken)
            inboxes[d.deviceID]?.removeAll { ids.contains($0.id) }
        }
    }

    func pending(deviceID: String) -> Int {
        lock.lock(); defer { lock.unlock() }
        return inboxes[deviceID]?.count ?? 0
    }
}

/// One participant: a model with a session, and a coordinator over its own store directory.
@MainActor
private struct Participant {
    let name: String
    let accountID: String
    let deviceID: String
    let model: AppModel
    var coordinator: ConversationCoordinator
    let directory: URL

    init(_ name: String, relay: InMemoryRelay, directory: URL? = nil) {
        self.name = name
        accountID = String(repeating: name.first!.lowercased(), count: 32)
        deviceID = String(repeating: name.last!.lowercased(), count: 32)
        model = AppModel(client: NedwonsClient(baseURL: URL(string: "http://127.0.0.1:1")!))
        model.session = NedwonsClient.Session(
            accountID: accountID, deviceID: deviceID, accessToken: name, accessExpiresAt: 1 << 40,
            refreshToken: "r", refreshExpiresAt: 1 << 40)
        self.directory = directory ?? FileManager.default.temporaryDirectory
            .appendingPathComponent("coord-\(name)-\(UUID().uuidString)", isDirectory: true)
        relay.register(token: name, accountID: accountID, deviceID: deviceID)
        coordinator = Self.makeCoordinator(model: model, relay: relay, directory: self.directory)
    }

    static func makeCoordinator(model: AppModel, relay: InMemoryRelay, directory: URL) -> ConversationCoordinator {
        let c = ConversationCoordinator(
            model: model, relay: relay, storeDirectory: directory,
            keyProvider: { storeID in Data(SHA256.hash(data: Data(storeID.utf8))) },
            minimumKeyPackages: 2)
        c.attach(aliasStore: nil)
        return c
    }

    /// "Relaunch": a fresh coordinator over the same directory, the previous one discarded.
    mutating func relaunch(relay: InMemoryRelay) {
        coordinator.stop()
        coordinator = Self.makeCoordinator(model: model, relay: relay, directory: directory)
    }

    func texts(in conversation: String) -> [(String, Bool)] {
        (model.threadLines[conversation] ?? []).compactMap { line in
            if case .text(let t) = line.kind { return (t, line.mine) }
            return nil
        }
    }
}

import CryptoKit

/// The pipeline end to end over the REAL MLS core with an in-memory relay: bootstrap, send,
/// receive, group commits, retry, relaunch, and a persisted lobby redeeming a Welcome.
@MainActor
final class ConversationCoordinatorTests: XCTestCase {
    private let conv = "c0" + String(repeating: "1", count: 30)

    /// Bob publishes prekeys; Alice creates the conversation (relay routing + MLS bootstrap); a
    /// message each way decrypts on the other side, rendered as thread lines.
    func testDirectMessageRoundTrip() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        let available1 = try await relay.availableKeyPackages(accessToken: "bob")
        XCTAssertEqual(available1, 2)
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        relay.resetCounters()

        await alice.model.sendMessage("hi bob", to: conv)
        XCTAssertNil(alice.model.banner)
        XCTAssertEqual(alice.texts(in: conv).map(\.0), ["hi bob"])

        // Welcome, the growth commit (for the epoch Bob joins at — undecryptable by him and
        // discarded), and the message.
        let processed = try await bob.coordinator.syncOnce()
        XCTAssertEqual(processed, 3)
        XCTAssertEqual(bob.texts(in: conv).map(\.0), ["hi bob"])
        XCTAssertEqual(bob.texts(in: conv).map(\.1), [false])
        XCTAssertEqual(relay.pending(deviceID: bob.deviceID), 0, "acked after processing")

        await bob.model.sendMessage("hi alice", to: conv)
        _ = try await alice.coordinator.syncOnce()
        XCTAssertEqual(alice.texts(in: conv).map(\.0), ["hi bob", "hi alice"])
        XCTAssertEqual(alice.texts(in: conv).map(\.1), [true, false])
        XCTAssertEqual(bob.model.localPreview(for: conv), "hi alice")
        // Joining consumed one of Bob's lobby identities; the pool was topped back up.
        let available2 = try await relay.availableKeyPackages(accessToken: "bob")
        XCTAssertEqual(available2, 2)
    }

    /// A three-member group: earlier members receive each later add's commit (targeted), so every
    /// member ends at the same epoch and any member's message decrypts everywhere.
    func testGroupCommitsReachEarlierMembers() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        let carol = Participant("carol", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        await carol.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID, carol.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID, carol.accountID])

        _ = try await bob.coordinator.syncOnce()  // Welcome (epoch 1) + Carol's add commit (→ epoch 2)
        _ = try await carol.coordinator.syncOnce()  // Welcome at epoch 2

        await carol.model.sendMessage("hello all", to: conv)
        _ = try await alice.coordinator.syncOnce()
        _ = try await bob.coordinator.syncOnce()
        XCTAssertEqual(alice.texts(in: conv).map(\.0), ["hello all"])
        XCTAssertEqual(bob.texts(in: conv).map(\.0), ["hello all"])

        await bob.model.sendMessage("hey", to: conv)
        _ = try await carol.coordinator.syncOnce()
        XCTAssertEqual(carol.texts(in: conv).map(\.0), ["hello all", "hey"])
    }

    /// An upload that fails leaves the message durably unsent and visible; the retry replays the
    /// cached ciphertext under the same idempotency key, so it is delivered exactly once.
    func testFailedUploadIsRetriedOnceWithTheSameKey() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        relay.resetCounters()

        relay.failSends = true
        await alice.model.sendMessage("queued", to: conv)
        XCTAssertEqual(alice.model.banner, "Couldn't send that message. It stays queued and will retry.")
        // Still in the thread — as sending, not delivered — so the user sees it is being retried.
        XCTAssertEqual(alice.texts(in: conv).map(\.0), ["queued"])
        XCTAssertEqual(alice.model.threadLines[conv]?.first?.isPending, true)
        XCTAssertEqual(relay.deliveries, 0)

        relay.failSends = false
        await alice.coordinator.retryUnsent()
        await alice.coordinator.retryUnsent()  // a second pass finds nothing unsent
        XCTAssertEqual(relay.deliveries, 1, "delivered exactly once")
        _ = try await bob.coordinator.syncOnce()
        XCTAssertEqual(bob.texts(in: conv).map(\.0), ["queued"])
    }

    /// The unsent set is durable: after a relaunch, `prepare` resumes the interrupted upload.
    func testUnsentMessageSurvivesRelaunch() async throws {
        let relay = InMemoryRelay()
        var alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        relay.resetCounters()

        relay.failSends = true
        await alice.model.sendMessage("from before the crash", to: conv)
        relay.failSends = false

        alice.relaunch(relay: relay)
        alice.model.threadLines = [:]
        await alice.coordinator.prepare()
        XCTAssertEqual(alice.texts(in: conv).map(\.0), ["from before the crash"], "history re-rendered")
        XCTAssertEqual(relay.deliveries, 1)
        _ = try await bob.coordinator.syncOnce()
        XCTAssertEqual(bob.texts(in: conv).map(\.0), ["from before the crash"])
    }

    /// The common case: someone creates a group for you while your app is closed. The prekey was
    /// published by an earlier launch; the persisted lobby identity redeems the Welcome after a
    /// relaunch, and the history renders.
    func testWelcomeAfterRelaunchJoinsFromPersistedLobby() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        var bob = Participant("bob", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        bob.relaunch(relay: relay)  // Bob's process dies; only disk remains

        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        relay.resetCounters()
        await alice.model.sendMessage("welcome back", to: conv)

        _ = try await bob.coordinator.syncOnce()
        XCTAssertEqual(bob.texts(in: conv).map(\.0), ["welcome back"])

        // And once more across a relaunch: the joined store reopens Active with its history.
        bob.relaunch(relay: relay)
        bob.model.threadLines = [:]
        await bob.coordinator.prepare()
        XCTAssertEqual(bob.texts(in: conv).map(\.0), ["welcome back"])
    }

    /// A moderation refusal is not a transient failure: the message stays unsent, the retry pass
    /// leaves it alone while the composer is locked, and it goes out once the lock lifts.
    func testMuteRefusalHoldsTheMessageUntilUnmuted() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        relay.resetCounters()

        relay.refuseSendsWith = "muted"
        await alice.model.sendMessage("too soon", to: conv)
        XCTAssertEqual(relay.deliveries, 0)
        // Emulate the panel having loaded the mute (the model's real refresh can't reach a
        // server here): a locked composer means the retry pass must skip this conversation.
        alice.model.groupStates[conv] = GroupState(
            conversationID: conv, isAdmin: false, canSend: false,
            members: [GroupMember(accountID: alice.accountID, username: "alice", muted: true)])
        relay.refuseSendsWith = nil
        await alice.coordinator.retryUnsent()
        XCTAssertEqual(relay.deliveries, 0, "not retried while muted")

        alice.model.groupStates[conv] = nil  // unmuted (panel reloaded)
        await alice.coordinator.retryUnsent()
        XCTAssertEqual(relay.deliveries, 1)
        _ = try await bob.coordinator.syncOnce()
        XCTAssertEqual(bob.texts(in: conv).map(\.0), ["too soon"])
    }

    /// A member with no prekey cannot be added; the group still forms with everyone else and the
    /// failure names who was left out.
    func testBootstrapReportsMembersWithoutPrekeys() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        let carol = Participant("carol", relay: relay)  // never publishes
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID, carol.deviceID])
        do {
            try await alice.coordinator.bootstrap(
                conversationID: conv, memberAccountIDs: [bob.accountID, carol.accountID])
            XCTFail("expected a partial-setup error")
        } catch let ConversationCoordinator.CoordinatorError.membersNotSetUp(failed) {
            XCTAssertEqual(failed, [carol.accountID])
        }
        await alice.model.sendMessage("still works for bob", to: conv)
        _ = try await bob.coordinator.syncOnce()
        XCTAssertEqual(bob.texts(in: conv).map(\.0), ["still works for bob"])
    }

    /// A rename reaches the other side through the ordinary message path, titles both clients, and
    /// nothing about the name exists outside the ciphertext — the relay only ever saw envelopes.
    func testGroupRenamePropagatesAndTitlesBothSides() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        relay.resetCounters()
        _ = try await bob.coordinator.syncOnce()

        let renamed = await alice.model.renameGroup(conv, to: "  Weekend Trip  ")
        XCTAssertTrue(renamed)
        XCTAssertEqual(alice.model.groupName(for: conv), "Weekend Trip", "trimmed before sending")
        XCTAssertEqual(alice.model.banner, "Group renamed.")

        _ = try await bob.coordinator.syncOnce()
        XCTAssertEqual(bob.model.groupName(for: conv), "Weekend Trip")
        // A rename is not a chat message on either side.
        XCTAssertTrue(bob.texts(in: conv).isEmpty)
        XCTAssertTrue(alice.texts(in: conv).isEmpty)
        // The list title follows the name; without one it describes the group instead.
        let chat = ChatSummary(conversationID: conv, memberCount: 3)
        XCTAssertEqual(bob.model.conversationTitle(for: chat), "Weekend Trip")
        XCTAssertEqual(
            bob.model.conversationTitle(for: ChatSummary(conversationID: "other", memberCount: 3)),
            "Group · 3 people")

        // A name no client could render safely never reaches the relay.
        let before = relay.deliveries
        let refused = await alice.model.renameGroup(conv, to: "bad\u{202E}name")
        XCTAssertFalse(refused)
        XCTAssertEqual(relay.deliveries, before, "refused locally, nothing sent")
        XCTAssertEqual(alice.model.groupName(for: conv), "Weekend Trip", "unchanged")
    }

    /// Unread counts come from decrypted local state, are cleared by opening the thread, and never
    /// count your own messages.
    func testUnreadCountsClearOnOpen() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        _ = try await bob.coordinator.syncOnce()

        await alice.model.sendMessage("one", to: conv)
        await alice.model.sendMessage("two", to: conv)
        XCTAssertEqual(alice.model.unreadCount(for: conv), 0, "your own messages are never unread")

        _ = try await bob.coordinator.syncOnce()
        XCTAssertEqual(bob.model.unreadCount(for: conv), 2)

        // Opening the conversation marks it read; the count stays cleared across a relaunch.
        await bob.model.markConversationRead(conv)
        XCTAssertEqual(bob.model.unreadCount(for: conv), 0)
        var bobAgain = bob
        bobAgain.relaunch(relay: relay)
        await bobAgain.coordinator.prepare()
        XCTAssertEqual(bobAgain.model.unreadCount(for: conv), 0)

        await alice.model.sendMessage("three", to: conv)
        _ = try await bobAgain.coordinator.syncOnce()
        XCTAssertEqual(bobAgain.model.unreadCount(for: conv), 1)
    }

    /// A message carries the time this device saw it, and is `pending` until the relay accepts it —
    /// so a failed send renders as sending rather than looking delivered.
    func testThreadLinesCarryTimeAndPendingState() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])

        relay.failSends = true
        await alice.model.sendMessage("stuck", to: conv)
        let pending = try XCTUnwrap(alice.model.threadLines[conv]?.first)
        XCTAssertTrue(pending.isPending, "a failed send shows as sending, not delivered")
        XCTAssertNotNil(pending.timestamp)
        XCTAssertEqual(alice.model.localLastActivity(for: conv), pending.timestamp)

        relay.failSends = false
        await alice.coordinator.retryUnsent()
        XCTAssertEqual(alice.model.threadLines[conv]?.first?.isPending, false, "accepted ⇒ delivered")

        _ = try await bob.coordinator.syncOnce()
        let received = try XCTUnwrap(bob.model.threadLines[conv]?.first)
        XCTAssertFalse(received.isPending, "inbound is never pending")
        XCTAssertNotNil(received.timestamp)
    }

    /// Adding someone to an EXISTING group must add them to the MLS group too, not only to relay
    /// routing — otherwise they are sent ciphertext they hold no key for. They also learn the
    /// group's name, which exists only inside the ciphertext.
    func testAddingToAnExistingGroupJoinsTheMlsGroupAndSharesTheName() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        let carol = Participant("carol", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        await carol.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        _ = try await bob.coordinator.syncOnce()
        _ = await alice.model.renameGroup(conv, to: "Book Club")
        _ = try await bob.coordinator.syncOnce()

        // Carol joins an established group.
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID, carol.deviceID])
        try await alice.coordinator.addMembers(to: conv, memberAccountIDs: [carol.accountID])
        _ = try await carol.coordinator.syncOnce()
        XCTAssertEqual(carol.model.groupName(for: conv), "Book Club", "the newcomer learns the name")

        // Everyone can now decrypt everyone: the growth commit reached the earlier members.
        await carol.model.sendMessage("hello from carol", to: conv)
        _ = try await alice.coordinator.syncOnce()
        _ = try await bob.coordinator.syncOnce()
        XCTAssertEqual(alice.texts(in: conv).map(\.0).last, "hello from carol")
        XCTAssertEqual(bob.texts(in: conv).map(\.0).last, "hello from carol")
        await bob.model.sendMessage("welcome carol", to: conv)
        _ = try await carol.coordinator.syncOnce()
        XCTAssertEqual(carol.texts(in: conv).map(\.0).last, "welcome carol")
    }

    /// A photo end to end: encrypted on the sender's device, stored by the relay as bytes it cannot
    /// read, and opened by the recipient with a key that only ever travelled inside an MLS message.
    func testAttachmentRoundTripKeepsTheFileFromTheRelay() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        _ = try await bob.coordinator.syncOnce()

        let file = Data("pretend PNG bytes".utf8) + Data(repeating: 0xAB, count: 4096)
        try await alice.coordinator.sendAttachment(
            file, mime: "image/png", filename: "beach.png", caption: "look", to: conv)

        // The sender's thread shows the file, and the relay holds something that is not it.
        let sent = try XCTUnwrap(alice.model.threadLines[conv]?.last)
        guard case .attachment(let mineLine) = sent.kind else {
            return XCTFail("expected an attachment line, got \(sent.kind)")
        }
        XCTAssertEqual(mineLine.filename, "beach.png")
        XCTAssertEqual(mineLine.caption, "look")
        XCTAssertEqual(mineLine.size, UInt64(file.count))
        let stored = try XCTUnwrap(relay.storedBlob(mineLine.blobID))
        XCTAssertNotEqual(stored, file, "the relay must never hold the file itself")
        XCTAssertEqual(alice.model.localPreview(for: conv), "beach.png · look")

        // The recipient sees it, downloads on demand, and decrypts it.
        _ = try await bob.coordinator.syncOnce()
        let received = try XCTUnwrap(bob.model.threadLines[conv]?.last)
        guard case .attachment(let theirs) = received.kind else {
            return XCTFail("expected an attachment line")
        }
        XCTAssertEqual(theirs.blobID, mineLine.blobID)
        XCTAssertEqual(bob.model.attachmentState(theirs.blobID), .notLoaded, "nothing downloads unasked")
        await bob.model.loadAttachment(theirs)
        XCTAssertEqual(bob.model.attachmentState(theirs.blobID), .loaded(file))
    }

    /// A relay that serves different (perfectly valid) bytes under the same id is caught by the
    /// digest, before decryption — and the user is told, rather than shown nothing.
    func testSubstitutedBlobIsRefused() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        _ = try await bob.coordinator.syncOnce()
        try await alice.coordinator.sendAttachment(
            Data("the real file".utf8), mime: "image/png", filename: "a.png", caption: "", to: conv)
        _ = try await bob.coordinator.syncOnce()
        guard case .attachment(let line)? = bob.model.threadLines[conv]?.last?.kind else {
            return XCTFail("expected an attachment")
        }

        // Someone else's valid ciphertext, served under our id.
        let other = try sealAttachment(plaintext: Data("a different file".utf8))
        relay.substituteBlob = other.ciphertext
        await bob.model.loadAttachment(line)
        guard case .failed(let reason) = bob.model.attachmentState(line.blobID) else {
            return XCTFail("a substituted blob must not be accepted")
        }
        XCTAssertEqual(reason, "Couldn't download — tap to retry")

        // With the real bytes back, the retry works.
        relay.substituteBlob = nil
        await bob.model.loadAttachment(line)
        XCTAssertEqual(bob.model.attachmentState(line.blobID), .loaded(Data("the real file".utf8)))
    }

    /// A failed upload sends no message: better a file that never arrived than a permanently broken
    /// bubble pointing at bytes the relay does not have.
    func testFailedUploadSendsNoMessage() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        let linesBefore = alice.model.threadLines[conv]?.count ?? 0

        relay.failUploads = true
        await alice.model.sendAttachment(
            Data("nope".utf8), mime: "image/png", filename: "a.png", caption: "", to: conv)
        XCTAssertEqual(alice.model.banner, "Couldn't send that file.")
        XCTAssertEqual(alice.model.threadLines[conv]?.count ?? 0, linesBefore, "no message was created")
        XCTAssertEqual(relay.blobCount, 0)
    }

    /// A reply points at the original and the UI resolves the quote locally; a reaction is
    /// attributed to whoever sent it and toggles; both sides agree.
    func testRepliesAndReactionsRoundTrip() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        _ = try await bob.coordinator.syncOnce()

        await alice.model.sendMessage("dinner at 8?", to: conv)
        _ = try await bob.coordinator.syncOnce()
        let original = try XCTUnwrap(bob.model.threadLines[conv]?.last)
        XCTAssertFalse(original.messageID.isEmpty, "a message can be referred to")

        // Reply through the model's compose path: a draft, then a send.
        bob.model.startReply(to: original, in: conv)
        XCTAssertEqual(bob.model.replyDrafts[conv]?.messageID, original.messageID)
        await bob.model.sendMessageOrReply("works for me", to: conv)
        XCTAssertNil(bob.model.replyDrafts[conv], "sending clears the draft")
        _ = try await alice.coordinator.syncOnce()
        let reply = try XCTUnwrap(alice.model.threadLines[conv]?.last)
        XCTAssertEqual(reply.replyTo, original.messageID)
        // Alice resolves the quote from her own copy — the reply carried no text of it.
        let quoted = alice.model.threadLines[conv]?.first { $0.messageID == reply.replyTo }
        XCTAssertEqual(quoted?.quotableText, "dinner at 8?")

        // React, and see it attributed and toggleable on both sides.
        await bob.model.toggleReaction("👍", on: original, in: conv)
        let bobsView = try XCTUnwrap(bob.model.threadLines[conv]?.first { $0.messageID == original.messageID })
        XCTAssertEqual(bobsView.reactions, [ReactionSummary(emoji: "👍", count: 1, includesMe: true)])
        _ = try await alice.coordinator.syncOnce()
        let alicesView = try XCTUnwrap(alice.model.threadLines[conv]?.first { $0.messageID == original.messageID })
        XCTAssertEqual(
            alicesView.reactions, [ReactionSummary(emoji: "👍", count: 1, includesMe: false)],
            "Alice sees Bob's reaction as his, not hers")

        // Tapping the same emoji takes it back.
        await bob.model.toggleReaction("👍", on: bobsView, in: conv)
        _ = try await alice.coordinator.syncOnce()
        let cleared = try XCTUnwrap(alice.model.threadLines[conv]?.first { $0.messageID == original.messageID })
        XCTAssertTrue(cleared.reactions.isEmpty)
    }

    /// Delivery receipts are sent when a message decrypts; read receipts only when the user opens
    /// the conversation. The sender sees one tick, then two.
    func testReceiptsFollowDeliveryThenReading() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        _ = try await bob.coordinator.syncOnce()

        await alice.model.sendMessage("are you there?", to: conv)
        XCTAssertEqual(alice.model.threadLines[conv]?.last?.deliveredCount, 0, "nothing yet")

        // Bob's sync decrypts it and acknowledges delivery.
        _ = try await bob.coordinator.syncOnce()
        print("DBG bob err:", String(describing: bob.coordinator.lastSyncError))
        _ = try await alice.coordinator.syncOnce()
        print("DBG alice lines:", alice.model.threadLines[conv]?.map { ($0.messageID, $0.deliveredCount) } ?? [])
        var mine = try XCTUnwrap(alice.model.threadLines[conv]?.last)
        XCTAssertEqual(mine.deliveredCount, 1)
        XCTAssertEqual(mine.readCount, 0, "delivered is not read")

        // Bob opens the conversation: now it is read.
        await bob.model.markConversationRead(conv)
        _ = try await alice.coordinator.syncOnce()
        mine = try XCTUnwrap(alice.model.threadLines[conv]?.last)
        XCTAssertEqual(mine.readCount, 1)

        // A second sync does not re-acknowledge the same message.
        let before = relay.deliveries
        _ = try await bob.coordinator.syncOnce()
        await bob.model.markConversationRead(conv)
        XCTAssertEqual(relay.deliveries, before, "one receipt per message, not per sync")
    }

    /// Receipts are a privacy choice: with them off, this device tells nobody what it has seen and
    /// everything else still works.
    func testReceiptsCanBeTurnedOff() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        bob.coordinator.sendReceipts = false
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        _ = try await bob.coordinator.syncOnce()

        await alice.model.sendMessage("hello?", to: conv)
        _ = try await bob.coordinator.syncOnce()
        await bob.model.markConversationRead(conv)
        _ = try await alice.coordinator.syncOnce()
        let mine = try XCTUnwrap(alice.model.threadLines[conv]?.last)
        XCTAssertEqual(mine.deliveredCount, 0)
        XCTAssertEqual(mine.readCount, 0)
        // The message itself still arrived.
        XCTAssertEqual(bob.texts(in: conv).map(\.0), ["hello?"])
    }

    /// Typing is throttled — a sentence must not become one envelope per keystroke — and the
    /// recipient sees who is typing without anything being logged.
    func testTypingIsThrottledAndEphemeral() async throws {
        let relay = InMemoryRelay()
        let alice = Participant("alice", relay: relay)
        let bob = Participant("bob", relay: relay)
        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [alice.deviceID, bob.deviceID])
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        _ = try await bob.coordinator.syncOnce()
        relay.resetCounters()

        // Ten "keystrokes" produce ONE typing message.
        for _ in 0..<10 {
            await bob.model.setTyping(true, in: conv)
        }
        XCTAssertEqual(relay.deliveries, 1, "throttled, not one per keystroke")

        _ = try await alice.coordinator.syncOnce()
        XCTAssertEqual(alice.model.typingBy[conv]?.count, 1, "Alice sees someone typing")
        XCTAssertTrue(alice.texts(in: conv).isEmpty, "typing is not a message")
        XCTAssertEqual(alice.model.unreadCount(for: conv), 0)

        // Clearing the field always sends the stop, so the indicator cannot stick.
        await bob.model.setTyping(false, in: conv)
        _ = try await alice.coordinator.syncOnce()
        XCTAssertNil(alice.model.typingBy[conv])
    }

    func testIdempotencyKeyIsDeterministicPerMessage() {
        let a = ConversationCoordinator.idempotencyKey(conversationID: conv, localID: 1)
        XCTAssertEqual(a, ConversationCoordinator.idempotencyKey(conversationID: conv, localID: 1))
        XCTAssertNotEqual(a, ConversationCoordinator.idempotencyKey(conversationID: conv, localID: 2))
        XCTAssertEqual(a.count, 16)
    }
}
