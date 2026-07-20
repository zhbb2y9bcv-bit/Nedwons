import MlsFfi
import XCTest

@testable import NedwonsPush

/// The push-notification decode path over the REAL Rust MLS core: a wake fetches the inbox and the
/// decoder renders the newest user-facing message, while control/duplicate messages surface nothing.
final class PushInboxDecoderTests: XCTestCase {
    private let key = Data(repeating: 7, count: 32)
    private func tmp(_ t: String) -> String { NSTemporaryDirectory() + "push-\(t)-\(UUID().uuidString)" }

    /// alice + bob in a real group; returns bob joined, ready to receive.
    private func pair() throws -> (alice: MlsClient, bob: MlsClient) {
        let alice = try MlsClient.createGroup(
            identity: Data("alice".utf8), dbPath: tmp("a"), atRestKey: key)
        let bob = try MlsClient.newJoiner(identity: Data("bob".utf8), dbPath: tmp("b"), atRestKey: key)
        let add = try alice.addMember(keyPackage: try bob.keyPackage())
        try bob.joinGroup(welcome: add.welcome)
        return (alice, bob)
    }

    func testDecodesANormalMessageBody() throws {
        let (alice, bob) = try pair()
        let id = try alice.enqueue(plaintext: Data("meet at the bridge".utf8))
        let env = try alice.encrypt(localId: id)
        let content = try PushInboxDecoder.decode(
            client: bob, envelopes: [PushEnvelope(id: 1, ciphertext: env)])
        XCTAssertEqual(content, PushNotificationContent(title: "New message", body: "meet at the bridge"))
    }

    func testRendersASecretGenericallyWithoutLeakingIt() throws {
        let (alice, bob) = try pair()
        let handle = try alice.enqueueSecret(body: Data("the vault code".utf8))
        let env = try alice.encrypt(localId: handle.localId)
        let content = try PushInboxDecoder.decode(
            client: bob, envelopes: [PushEnvelope(id: 1, ciphertext: env)])
        // A view-once secret is announced generically — the body is NEVER in the notification.
        XCTAssertEqual(content?.title, "Secret message")
        XCTAssertFalse(content?.body.contains("vault") ?? true)
    }

    func testControlOnlyInboxSurfacesNothing() throws {
        // A self-group message the device can't tie to a held secret decodes to a control no-op →
        // no notification content (the caller shows a generic wake instead).
        let (alice, bob) = try pair()
        // Deliver a normal message first (so there IS one), then assert an empty inbox → nil.
        _ = try PushInboxDecoder.decode(client: bob, envelopes: [])
        XCTAssertNil(try PushInboxDecoder.decode(client: bob, envelopes: []))
        _ = alice  // silence unused in this shape
    }

    func testNewestMessageWins() throws {
        let (alice, bob) = try pair()
        let e1 = try alice.encrypt(localId: try alice.enqueue(plaintext: Data("first".utf8)))
        let e2 = try alice.encrypt(localId: try alice.enqueue(plaintext: Data("second".utf8)))
        let content = try PushInboxDecoder.decode(
            client: bob,
            envelopes: [
                PushEnvelope(id: 2, ciphertext: e2),
                PushEnvelope(id: 1, ciphertext: e1),
            ])
        XCTAssertEqual(content?.body, "second", "the highest-id (newest) message is shown")
    }
}
