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

    func testStagedCommitProposerAndRecipient() throws {
        let (alice, bob) = try twoParty()
        let epoch = try alice.epoch()
        let carol = try MlsClient.newJoiner(
            identity: Data("carol-device".utf8), dbPath: tmp("carol"), atRestKey: key)

        // Stage adding carol — the epoch must NOT advance until the server confirms.
        _ = try alice.stageAdd(keyPackage: try carol.keyPackage())
        XCTAssertEqual(try alice.epoch(), epoch, "staging must not advance the epoch")

        // Simulate the server rejecting (stale epoch): discard; state unchanged.
        try alice.clearStaged()
        XCTAssertEqual(try alice.epoch(), epoch)

        // Rebuild; server accepts: merge.
        let staged = try alice.stageAdd(keyPackage: try carol.keyPackage())
        try alice.mergeStaged()
        XCTAssertEqual(try alice.epoch(), epoch + 1)

        // Recipient bob verifies the commit against the honest manifest delta, then merges.
        try bob.processCommit(
            envelope: staged.commit, nextEpoch: epoch + 1,
            added: [Data("carol-device".utf8)], removed: [])
        XCTAssertEqual(try bob.epoch(), try alice.epoch())

        // A lying manifest is refused and bob does not advance.
        let mallory = try MlsClient.newJoiner(
            identity: Data("mallory".utf8), dbPath: tmp("mallory"), atRestKey: key)
        let staged2 = try alice.stageAdd(keyPackage: try mallory.keyPackage())
        try alice.mergeStaged()
        let bobEpoch = try bob.epoch()
        XCTAssertThrowsError(
            try bob.processCommit(
                envelope: staged2.commit, nextEpoch: bobEpoch + 1,
                added: [Data("someone-else".utf8)], removed: [])
        ) { error in XCTAssertEqual(error as? MlsClientError, .InvalidMessage) }
        XCTAssertEqual(try bob.epoch(), bobEpoch, "state must not follow a lie")
    }

    func testCapabilitiesReportPinnedContract() {
        let c = capabilities()
        XCTAssertEqual(c.protocol, "MLS 1.0 (RFC 9420)")
        XCTAssertEqual(c.ciphersuite, "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        XCTAssertEqual(c.storageFormatVersion, 1)
        XCTAssertEqual(c.maxPlaintext, 64 * 1024)
        XCTAssertFalse(bindingVersion().isEmpty)
    }
}

extension MlsFfiBridgeTests {
    /// The secret-message (view-once) flow across the generated Swift bindings: Alice sends a secret
    /// through the real MLS path, Bob receives a sealed placeholder, reveals it once (3s countdown +
    /// 10s window), it expires into the tombstone, and reopen after reveal fails closed. Normal
    /// messaging keeps working alongside. `nowMs` is supplied deterministically (no real waiting).
    func testSecretMessageFlowThroughBindings() throws {
        let (alice, bob) = try twoParty()

        // Send a secret. The relay only ever sees the opaque envelope.
        let handle = try alice.enqueueSecret(body: Data("eyes only".utf8))
        let envelope = try alice.encrypt(localId: handle.localId)
        try alice.markSent(localId: handle.localId)
        XCTAssertFalse(
            envelope.range(of: Data("eyes only".utf8)) != nil,
            "plaintext must not appear in the ciphertext")

        // Bob receives a SEALED placeholder — no body delivered.
        guard case let .secretSealed(sid) = try bob.processInbound(envelopeId: 1, ciphertext: envelope)
        else { return XCTFail("expected a sealed secret") }
        XCTAssertEqual(sid, handle.secretId)
        XCTAssertEqual(try bob.secretPhase(secretId: sid, nowMs: 0), .sealed)
        XCTAssertNil(try bob.secretVisibleBody(secretId: sid, nowMs: 0))

        // Reveal: 3s countdown then a 10s window, then tombstone at exactly 13s.
        try bob.beginSecretReveal(secretId: sid, nowMs: 0)
        XCTAssertEqual(try bob.secretPhase(secretId: sid, nowMs: 2_999), .countdown)
        XCTAssertEqual(try bob.secretPhase(secretId: sid, nowMs: 3_000), .visible)
        XCTAssertEqual(
            try bob.secretVisibleBody(secretId: sid, nowMs: 3_000).map { String(decoding: $0, as: UTF8.self) },
            "eyes only")
        XCTAssertEqual(try bob.secretPhase(secretId: sid, nowMs: 13_000), .consumed)
        XCTAssertNil(try bob.secretVisibleBody(secretId: sid, nowMs: 13_000))
        XCTAssertEqual(secretTombstoneText(), "a secret message has been sent")

        // A double reveal is refused; a normal message still flows during the secret's life.
        XCTAssertThrowsError(try bob.beginSecretReveal(secretId: sid, nowMs: 1_000))
        let nid = try alice.enqueue(plaintext: Data("normal still works".utf8))
        let nenv = try alice.encrypt(localId: nid)
        guard case let .application(pt) = try bob.processInbound(envelopeId: 2, ciphertext: nenv)
        else { return XCTFail("normal delivery must keep working") }
        XCTAssertEqual(String(decoding: pt, as: UTF8.self), "normal still works")
    }

    /// Crash after reveal begins → fail closed on relaunch (the plaintext is never re-viewable).
    func testSecretFailsClosedAfterReopen() throws {
        let bPath = tmp("bob")
        let alice = try MlsClient.createGroup(
            identity: Data("alice".utf8), dbPath: tmp("alice"), atRestKey: key)
        let bob = try MlsClient.newJoiner(
            identity: Data("bob".utf8), dbPath: bPath, atRestKey: key)
        let add = try alice.addMember(keyPackage: try bob.keyPackage())
        try bob.joinGroup(welcome: add.welcome)

        let handle = try alice.enqueueSecret(body: Data("burn".utf8))
        let env = try alice.encrypt(localId: handle.localId)
        _ = try bob.processInbound(envelopeId: 1, ciphertext: env)
        try bob.beginSecretReveal(secretId: handle.secretId, nowMs: 0)
        XCTAssertEqual(try bob.secretPhase(secretId: handle.secretId, nowMs: 3_000), .visible)

        bob.close()  // "crash"
        let bob2 = try MlsClient.open(dbPath: bPath, atRestKey: key)
        XCTAssertEqual(try bob2.secretPhase(secretId: handle.secretId, nowMs: 3_500), .consumed)
        XCTAssertNil(try bob2.secretVisibleBody(secretId: handle.secretId, nowMs: 3_500))
    }

    /// Hostile secret ids never crash the binding; they surface as typed errors / unknown.
    func testHostileSecretIdIsTypedError() throws {
        let (_, bob) = try twoParty()
        for bad in [Data(), Data(repeating: 0, count: 15), Data(repeating: 0, count: 17)] {
            XCTAssertThrowsError(try bob.beginSecretReveal(secretId: bad, nowMs: 0))
        }
        XCTAssertEqual(try bob.secretPhase(secretId: Data(repeating: 0xAB, count: 16), nowMs: 0), .unknown)
    }
}
