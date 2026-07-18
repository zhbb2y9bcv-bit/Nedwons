import XCTest

@testable import MlsFfi

/// Proves the *generated Swift bindings* drive the *real Rust MLS core* across the UniFFI boundary
/// (ADR-0007). On the host these link the macOS slice of MlsFfi.xcframework; the same source runs
/// against the simulator/device slices in an Xcode test host. No MLS logic lives in Swift — every
/// call marshals into `mls-core`.
final class MlsFfiBridgeTests: XCTestCase {
    let key = Data(repeating: 7, count: 32)

    private func tmp(_ tag: String) -> String {
        NSTemporaryDirectory() + "mls-\(tag)-\(UUID().uuidString)"
    }

    /// Alice creates a group, Bob joins via key-package → welcome. Returns both live clients.
    private func twoParty() throws -> (MlsClient, MlsClient) {
        let alice = try MlsClient.createGroup(
            identity: Data("alice-device".utf8), dbPath: tmp("alice"), atRestKey: key)
        let bob = try MlsClient.newJoiner(
            identity: Data("bob-device".utf8), dbPath: tmp("bob"), atRestKey: key)
        let kp = try bob.keyPackage()
        let add = try alice.addMember(keyPackage: kp)
        try bob.joinGroup(welcome: add.welcome)
        return (alice, bob)
    }

    func testTwoClientsExchangeRealMlsMessage() throws {
        let (alice, bob) = try twoParty()
        XCTAssertEqual(try alice.epoch(), try bob.epoch())

        let id = try alice.enqueue(plaintext: Data("hello from swift".utf8))
        let envelope = try alice.encrypt(localId: id)
        try alice.markSent(localId: id)

        guard case let .application(plaintext) = try bob.processInbound(
            envelopeId: 1, ciphertext: envelope)
        else { return XCTFail("expected application message") }
        XCTAssertEqual(String(decoding: plaintext, as: UTF8.self), "hello from swift")
        XCTAssertEqual(try alice.messages().count, 1)
        XCTAssertEqual(try bob.messages().count, 1)
    }

    func testRetryEncryptIsIdempotent() throws {
        let (alice, _) = try twoParty()
        let id = try alice.enqueue(plaintext: Data("once".utf8))
        let epoch = try alice.epoch()
        let first = try alice.encrypt(localId: id)
        let second = try alice.encrypt(localId: id)
        XCTAssertEqual(first, second, "retry must return the cached ciphertext")
        XCTAssertEqual(try alice.epoch(), epoch, "encrypt must not advance the ratchet")
    }

    func testDuplicateInboundIsNoOp() throws {
        let (alice, bob) = try twoParty()
        let id = try alice.enqueue(plaintext: Data("dup".utf8))
        let env = try alice.encrypt(localId: id)
        if case .application = try bob.processInbound(envelopeId: 7, ciphertext: env) {} else {
            return XCTFail("expected application")
        }
        if case .duplicate = try bob.processInbound(envelopeId: 7, ciphertext: env) {} else {
            return XCTFail("expected duplicate")
        }
        XCTAssertEqual(try bob.messages().count, 1)
    }

    func testRelaunchReopensDurableState() throws {
        let aPath = tmp("alice")
        let bob = try MlsClient.newJoiner(
            identity: Data("bob".utf8), dbPath: tmp("bob"), atRestKey: key)
        let alice = try MlsClient.createGroup(
            identity: Data("alice".utf8), dbPath: aPath, atRestKey: key)
        let add = try alice.addMember(keyPackage: try bob.keyPackage())
        try bob.joinGroup(welcome: add.welcome)

        let id = try alice.enqueue(plaintext: Data("before".utf8))
        _ = try alice.encrypt(localId: id)
        let epoch = try alice.epoch()

        alice.close()  // simulate app teardown
        let alice2 = try MlsClient.open(dbPath: aPath, atRestKey: key)
        XCTAssertEqual(try alice2.epoch(), epoch, "epoch restored from encrypted journal")

        let id2 = try alice2.enqueue(plaintext: Data("after".utf8))
        let env2 = try alice2.encrypt(localId: id2)
        guard case let .application(pt) = try bob.processInbound(envelopeId: 2, ciphertext: env2)
        else { return XCTFail("expected application after relaunch") }
        XCTAssertEqual(String(decoding: pt, as: UTF8.self), "after")
    }

    func testUseAfterCloseThrows() throws {
        let alice = try MlsClient.createGroup(
            identity: Data("a".utf8), dbPath: tmp("a"), atRestKey: key)
        alice.close()
        alice.close()  // idempotent
        XCTAssertThrowsError(try alice.epoch()) { error in
            XCTAssertEqual(error as? MlsClientError, .Closed)
        }
    }

    func testBoundedInputRejected() throws {
        let alice = try MlsClient.createGroup(
            identity: Data("a".utf8), dbPath: tmp("a"), atRestKey: key)
        XCTAssertThrowsError(try alice.enqueue(plaintext: Data(count: 64 * 1024 + 1))) { error in
            XCTAssertEqual(error as? MlsClientError, .InputTooLarge)
        }
    }

    func testBadKeyLengthRejected() throws {
        XCTAssertThrowsError(
            try MlsClient.createGroup(
                identity: Data("a".utf8), dbPath: tmp("a"), atRestKey: Data(count: 16))
        ) { error in
            XCTAssertEqual(error as? MlsClientError, .BadKeyLength)
        }
    }

    func testMessagePaginationAcrossTheBoundary() throws {
        let (alice, _) = try twoParty()
        for i in 0..<5 {
            let id = try alice.enqueue(plaintext: Data([UInt8(i)]))
            _ = try alice.encrypt(localId: id)
        }
        XCTAssertEqual(try alice.messageCount(), 5)
        let page = try alice.messagesPage(offset: 1, limit: 2)
        XCTAssertEqual(page.count, 2)
        XCTAssertEqual(page[0].plaintext, Data([1]))
        XCTAssertEqual(page[1].plaintext, Data([2]))
        XCTAssertEqual(try alice.messagesPage(offset: 99, limit: 10).count, 0)
    }

    func testCapabilitiesReportPinnedContract() {
        let c = capabilities()
        XCTAssertEqual(c.protocol, "MLS 1.0 (RFC 9420)")
        XCTAssertEqual(c.ciphersuite, "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
        XCTAssertEqual(c.storageFormatVersion, 1)
        XCTAssertEqual(c.maxPlaintext, 64 * 1024)
        XCTAssertFalse(bindingVersion().isEmpty)
    }
}
