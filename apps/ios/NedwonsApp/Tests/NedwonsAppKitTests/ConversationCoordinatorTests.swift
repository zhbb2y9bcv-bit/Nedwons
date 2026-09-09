import Foundation
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

        await alice.model.sendMessage("hi bob", to: conv)
        XCTAssertNil(alice.model.banner)
        XCTAssertEqual(alice.texts(in: conv).map(\.0), ["hi bob"])

        let processed = try await bob.coordinator.syncOnce()
        XCTAssertEqual(processed, 2, "the Welcome and the message")
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

        relay.failSends = true
        await alice.model.sendMessage("queued", to: conv)
        XCTAssertEqual(alice.model.banner, "Couldn't send that message. It stays queued and will retry.")
        // The core logs a message once the relay has accepted it; until then it lives in the
        // durable outbox, not the thread.
        XCTAssertEqual(alice.texts(in: conv).map(\.0), [])
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

    func testIdempotencyKeyIsDeterministicPerMessage() {
        let a = ConversationCoordinator.idempotencyKey(conversationID: conv, localID: 1)
        XCTAssertEqual(a, ConversationCoordinator.idempotencyKey(conversationID: conv, localID: 1))
        XCTAssertNotEqual(a, ConversationCoordinator.idempotencyKey(conversationID: conv, localID: 2))
        XCTAssertEqual(a.count, 16)
    }
}
