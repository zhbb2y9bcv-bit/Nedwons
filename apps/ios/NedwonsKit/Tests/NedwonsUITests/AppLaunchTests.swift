import XCTest

@testable import NedwonsKit
@testable import NedwonsUI

/// In-memory `SecretStore` so launch behaviour is testable without a device Keychain.
final class FakeSecretStore: SecretStore, @unchecked Sendable {
    private var items: [String: Data] = [:]
    private let lock = NSLock()

    func save(_ data: Data, account: String, accessible: CFString) throws {
        lock.lock(); defer { lock.unlock() }
        items[account] = data
    }
    func load(account: String) throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        return items[account]
    }
    func delete(account: String) throws {
        lock.lock(); defer { lock.unlock() }
        items.removeValue(forKey: account)
    }
    var isEmpty: Bool {
        lock.lock(); defer { lock.unlock() }
        return items.isEmpty
    }
}

private func sampleSession(account: String = "acct-1") -> NedwonsClient.Session {
    NedwonsClient.Session(
        accountID: account,
        deviceID: "device-1",
        accessToken: "access",
        accessExpiresAt: 9_999_999_999,
        refreshToken: "refresh",
        refreshExpiresAt: 9_999_999_999)
}

final class SessionStoreTests: XCTestCase {
    func testRoundTripPreservesEveryField() throws {
        let store = SessionStore(store: FakeSecretStore())
        let session = sampleSession()
        try store.save(session)
        XCTAssertEqual(store.load(), session)
    }

    func testMissingSessionLoadsAsNil() {
        XCTAssertNil(SessionStore(store: FakeSecretStore()).load())
    }

    /// A corrupt blob must read as "no session" rather than throwing, so a bad write can never
    /// wedge the app at launch.
    func testCorruptBlobIsTreatedAsNoSession() throws {
        let backing = FakeSecretStore()
        try backing.save(Data("not json".utf8), account: "session-v1", accessible: "" as CFString)
        XCTAssertNil(SessionStore(store: backing).load())
    }

    func testClearRemovesTheSession() throws {
        let backing = FakeSecretStore()
        let store = SessionStore(store: backing)
        try store.save(sampleSession())
        store.clear()
        XCTAssertNil(store.load())
        XCTAssertTrue(backing.isEmpty)
    }
}

@MainActor
final class AppLaunchTests: XCTestCase {
    private func model(sessionStore: SessionStore) -> AppModel {
        AppModel(
            baseURL: URL(string: "http://127.0.0.1:1")!,
            deviceIdentity: DeviceIdentity(
                store: InMemoryDeviceKeyStore(), secureEnclaveAvailable: false),
            sessionStore: sessionStore)
    }

    /// Fresh install: no stored session ⇒ authentication, never a conversation.
    func testFreshInstallLandsOnAuthentication() async {
        let m = model(sessionStore: SessionStore(store: FakeSecretStore()))
        await m.restoreSession()
        XCTAssertEqual(m.phase, .unauthenticated)
        XCTAssertFalse(m.isLoggedIn)
    }

    /// The root starts in `.booting` so no protected screen can render before validation resolves.
    func testInitialPhaseIsBootingBeforeRestore() {
        let m = model(sessionStore: SessionStore(store: FakeSecretStore()))
        XCTAssertEqual(m.phase, .booting)
        XCTAssertFalse(m.isLoggedIn)
    }

    /// A stored session whose device key is absent from this device must NOT resume: device binding
    /// is re-checked at launch rather than trusted from the stored blob (INV-2).
    func testStoredSessionWithoutDeviceKeyDoesNotResume() async throws {
        let backing = FakeSecretStore()
        let store = SessionStore(store: backing)
        try store.save(sampleSession())
        let m = model(sessionStore: store)
        await m.restoreSession()
        XCTAssertEqual(m.phase, .unauthenticated)
        XCTAssertFalse(m.isLoggedIn)
        XCTAssertNil(store.load(), "an unusable session must be discarded, not kept")
    }

    /// Launch must not create a conversation or touch secret state.
    func testLaunchCreatesNoConversationAndNoSecretState() async {
        let m = model(sessionStore: SessionStore(store: FakeSecretStore()))
        await m.restoreSession()
        XCTAssertTrue(m.conversations.isEmpty)
        XCTAssertTrue(m.visibleConversations.isEmpty)
        XCTAssertTrue(m.threadLines.isEmpty)
        XCTAssertTrue(m.localThreads.isEmpty)
    }

    /// Launch performs no automatic send: without an injected action, nothing can be sent, and the
    /// action is never invoked during restore.
    func testLaunchPerformsNoAutomaticSend() async {
        let m = model(sessionStore: SessionStore(store: FakeSecretStore()))
        var sends = 0
        m.sendMessageAction = { _, _ in sends += 1 }
        await m.restoreSession()
        XCTAssertEqual(sends, 0)
    }

    /// Launch never begins a secret reveal.
    func testLaunchNeverRevealsASecret() async {
        let m = model(sessionStore: SessionStore(store: FakeSecretStore()))
        var reveals = 0
        m.revealSecret = { _ in reveals += 1 }
        await m.restoreSession()
        XCTAssertEqual(reveals, 0)
    }

    func testSignOutClearsStoredSessionAndReturnsToAuth() throws {
        let backing = FakeSecretStore()
        let store = SessionStore(store: backing)
        try store.save(sampleSession())
        let m = model(sessionStore: store)
        m.signOut()
        XCTAssertEqual(m.phase, .unauthenticated)
        XCTAssertNil(store.load())
    }
}
