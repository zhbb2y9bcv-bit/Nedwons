import MlsFfi
import XCTest

@testable import NedwonsPush

/// The multi-store push decode (roadmap step 5, software half): the extension resolves each
/// envelope's conversation to its own encrypted store through the shared index, decrypts with the
/// REAL core, and reports exactly which envelopes it durably processed — the only ones that may be
/// acked. Everything it cannot serve stays queued for the app.
final class SharedPushStoreTests: XCTestCase {
    private let key = Data(repeating: 7, count: 32)
    private func tmp(_ t: String) -> String {
        NSTemporaryDirectory() + "shared-push-\(t)-\(UUID().uuidString)"
    }

    private func pair(_ tag: String) throws -> (alice: MlsClient, bob: MlsClient) {
        let alice = try MlsClient.createGroup(
            identity: Data("alice".utf8), dbPath: tmp("\(tag)-a"), atRestKey: key)
        let bob = try MlsClient.newJoiner(
            identity: Data("bob".utf8), dbPath: tmp("\(tag)-b"), atRestKey: key)
        let add = try alice.addMember(keyPackage: try bob.keyPackage())
        try bob.joinGroup(welcome: add.welcome)
        return (alice, bob)
    }

    /// Two conversations, each in its own store — the decode routes envelopes to the right one and
    /// acks both; the newest overall message is what gets shown.
    func testRoutesEnvelopesToTheirConversationsStore() throws {
        let (alice1, bob1) = try pair("one")
        let (alice2, bob2) = try pair("two")
        let e1 = try alice1.encrypt(localId: try alice1.enqueue(plaintext: Data("in chat one".utf8)))
        let e2 = try alice2.encrypt(localId: try alice2.enqueue(plaintext: Data("in chat two".utf8)))

        let clients = ["conv-1": bob1, "conv-2": bob2]
        let outcome = PushInboxDecoder.decode(
            envelopes: [
                PushEnvelope(id: 1, ciphertext: e1, conversationID: "conv-1"),
                PushEnvelope(id: 2, ciphertext: e2, conversationID: "conv-2"),
            ]
        ) { clients[$0] }

        XCTAssertEqual(outcome.content?.body, "in chat two", "newest across conversations wins")
        XCTAssertEqual(outcome.processedIDs.sorted(), [1, 2])
    }

    /// What the extension cannot serve is NOT acked: a conversation with no store here, a sealed
    /// envelope, and a self-group envelope all stay queued for the app.
    func testOnlyDurablyProcessedEnvelopesAreAcked() throws {
        let (alice, bob) = try pair("ack")
        let good = try alice.encrypt(localId: try alice.enqueue(plaintext: Data("hello".utf8)))
        let stray = Data([0xDE, 0xAD])

        let outcome = PushInboxDecoder.decode(
            envelopes: [
                PushEnvelope(id: 1, ciphertext: good, conversationID: "known"),
                PushEnvelope(id: 2, ciphertext: good, conversationID: "unknown"),
                PushEnvelope(id: 3, ciphertext: stray, sealed: true, conversationID: nil),
                PushEnvelope(id: 4, ciphertext: stray, selfGroup: true, conversationID: nil),
                // Garbage for a known conversation: processInbound throws → skipped, not acked.
                PushEnvelope(id: 5, ciphertext: stray, conversationID: "known"),
            ]
        ) { $0 == "known" ? bob : nil }

        XCTAssertEqual(outcome.processedIDs, [1], "acking anything else would lose mail")
        XCTAssertEqual(outcome.content?.body, "hello")
    }

    /// The shared index round-trips through the layout's paths, and the store path convention
    /// matches what the coordinator writes (`store-<id>` under the store directory).
    func testLayoutPathsAndIndexRoundTrip() throws {
        let dir = URL(fileURLWithPath: tmp("layout"), isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var index = MlsStoreIndex()
        index.conversations["conv"] = "abc123"
        index.lobbies = ["lobby1"]
        try index.save(to: SharedStoreLayout.indexURL(storeDirectory: dir))
        let loaded = MlsStoreIndex.load(from: SharedStoreLayout.indexURL(storeDirectory: dir))
        XCTAssertEqual(loaded, index)
        XCTAssertTrue(
            SharedStoreLayout.storePath(storeDirectory: dir, storeID: "abc123")
                .hasSuffix("/store-abc123"))
        XCTAssertEqual(
            SharedStoreLayout.lockURL(storeDirectory: dir).lastPathComponent, "store.lock")
    }

    /// The cross-process lock is exclusive: while held, a non-blocking acquire fails; released, it
    /// succeeds. (Two descriptors in one process model two processes — flock is per-open-file.)
    func testStoreLockExcludes() throws {
        let url = URL(fileURLWithPath: tmp("lock"))
        let held = StoreLock.acquire(at: url)
        XCTAssertNotNil(held)
        XCTAssertNil(StoreLock.tryAcquire(at: url), "held elsewhere → the extension backs off")
        held?.release()
        let retaken = StoreLock.tryAcquire(at: url)
        XCTAssertNotNil(retaken, "released → free to take")
        retaken?.release()
    }

    /// An unconfigured build (no NedwonsAppGroup key) resolves no app group — the entire shared
    /// path degrades to `nil` and both sides keep their pre-provisioning behavior.
    func testUnprovisionedBuildHasNoAppGroup() {
        XCTAssertNil(SharedStoreLayout.configuredAppGroup(bundle: Bundle(for: Self.self)))
    }
}
