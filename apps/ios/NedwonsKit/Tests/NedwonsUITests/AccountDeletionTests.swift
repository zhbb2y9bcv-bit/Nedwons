import XCTest

@testable import NedwonsKit
@testable import NedwonsUI

/// In-app account deletion (App Store requirement) and, more importantly, the LOCAL erasure that
/// no server can perform for us.
///
/// The server-side sweep is covered by `services/api/tests/account_deletion.rs`. What only the
/// client can prove is that aliases, the enrolled device key, the session and the MLS store are
/// actually gone afterwards — those never leave the device, so if deletion misses them a "deleted"
/// account leaves its contact names and ratchet state sitting in the container.
final class AccountDeletionLocalWipeTests: XCTestCase {
    private func tempAliasStore() -> (ContactAliasStore, URL) {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("del-alias-\(UUID().uuidString).bin")
        return (ContactAliasStore(fileURL: url, atRestKey: Data(repeating: 4, count: 32)), url)
    }

    func testErasingAliasesRemovesBothTheCacheAndTheFile() {
        let (store, url) = tempAliasStore()
        store.setAlias("Mum", for: "acct-1")
        store.setAlias("Work", for: "acct-2")
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: url.path), "precondition: the file exists")

        store.eraseAll()

        XCTAssertNil(store.alias(for: "acct-1"), "the in-memory cache must be cleared")
        XCTAssertNil(store.alias(for: "acct-2"))
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: url.path),
            "the encrypted alias file must be removed, not just emptied")
        // Reopening the same path must not resurrect anything.
        let reopened = ContactAliasStore(fileURL: url, atRestKey: Data(repeating: 4, count: 32))
        XCTAssertNil(reopened.alias(for: "acct-1"))
    }

    /// Deletion must destroy the enrolled device key. Leaving it behind would let the device keep
    /// signing for an account that no longer exists, and would make a re-registration silently
    /// reuse the old identity.
    func testDeviceKeyIsDestroyed() throws {
        let store = InMemoryDeviceKeyStore()
        let identity = DeviceIdentity(store: store, secureEnclaveAvailable: false)
        _ = try identity.provision(policy: .allowSoftwareFallback)
        XCTAssertNotNil(try identity.loadEnrolled(), "precondition: a key is enrolled")

        try identity.reset()

        XCTAssertNil(try identity.loadEnrolled(), "the enrolled key must be gone after deletion")
    }
}

@MainActor
final class AccountDeletionModelTests: XCTestCase {
    private func model(sessionStore: SessionStore) -> AppModel {
        AppModel(
            baseURL: URL(string: "http://127.0.0.1:1")!,
            deviceIdentity: DeviceIdentity(
                store: InMemoryDeviceKeyStore(), secureEnclaveAvailable: false),
            sessionStore: sessionStore)
    }

    /// Deletion must not touch local state when the caller is not signed in — there is nothing to
    /// authorize the request with, so wiping would destroy data for no reason.
    func testDeletingWhileSignedOutFailsAndWipesNothing() async {
        let backing = FakeSecretStore()
        let m = model(sessionStore: SessionStore(store: backing))
        var wiped = false
        m.wipeAllLocalDataAction = { wiped = true }

        let failure = await m.deleteAccount(password: "anything")

        XCTAssertNotNil(failure, "deleting while signed out must report a failure")
        XCTAssertFalse(wiped, "nothing may be erased when the request was never made")
    }

    /// A refused deletion (wrong password, server down) must leave the account usable. Wiping
    /// first and asking questions later would strand the user: the account would still exist on
    /// the server, but this device could no longer authenticate to delete it.
    func testARefusedDeletionLeavesLocalStateIntact() async {
        let backing = FakeSecretStore()
        let store = SessionStore(store: backing)
        let session = NedwonsClient.Session(
            accountID: "acct-1",
            deviceID: "device-1",
            accessToken: "access",
            accessExpiresAt: 9_999_999_999,
            refreshToken: "refresh",
            refreshExpiresAt: 9_999_999_999)
        try? store.save(session)

        let m = model(sessionStore: store)
        m.session = session
        var wiped = false
        m.wipeAllLocalDataAction = { wiped = true }

        // The base URL points at a closed port, so the request cannot succeed.
        let failure = await m.deleteAccount(password: "wrong")

        XCTAssertNotNil(failure, "a refused deletion must report a failure")
        XCTAssertFalse(wiped, "local data must survive a refused deletion")
        XCTAssertNotNil(store.load(), "the session must survive so the user can retry")
    }
}

/// Settings actions that guard against destroying your own access.
@MainActor
final class SettingsActionTests: XCTestCase {
    private func signedInModel() -> (AppModel, NedwonsClient.Session) {
        let session = NedwonsClient.Session(
            accountID: "acct-1",
            deviceID: "device-current",
            accessToken: "access",
            accessExpiresAt: 9_999_999_999,
            refreshToken: "refresh",
            refreshExpiresAt: 9_999_999_999)
        let m = AppModel(
            baseURL: URL(string: "http://127.0.0.1:1")!,
            deviceIdentity: DeviceIdentity(
                store: InMemoryDeviceKeyStore(), secureEnclaveAvailable: false),
            sessionStore: SessionStore(store: FakeSecretStore()))
        m.session = session
        return (m, session)
    }

    /// Revoking the device you are holding would end your own session through a control labelled
    /// "device management" — a confusing way to lose access. It must be refused with an
    /// explanation, not silently attempted.
    func testRevokingTheCurrentDeviceIsRefusedWithAnExplanation() async {
        let (m, session) = signedInModel()
        await m.revokeDevice(session.deviceID)
        XCTAssertNotNil(m.banner, "the refusal must be explained to the user")
        XCTAssertTrue(
            m.banner?.contains("Sign out") ?? false,
            "the message should point at the control that actually does this: \(m.banner ?? "nil")")
    }

    /// Another device is a legitimate target, so it must NOT hit the same guard. The request then
    /// fails on transport (the base URL is a closed port), which is the expected outcome here —
    /// what matters is that it was attempted rather than refused locally.
    func testRevokingAnotherDeviceIsNotBlockedByTheGuard() async {
        let (m, _) = signedInModel()
        await m.revokeDevice("device-other")
        XCTAssertFalse(
            m.banner?.contains("Sign out") ?? false,
            "a different device must not trip the current-device guard")
    }

    func testRecoveryAndPasswordChangeRequireASession() async {
        let m = AppModel(
            baseURL: URL(string: "http://127.0.0.1:1")!,
            deviceIdentity: DeviceIdentity(
                store: InMemoryDeviceKeyStore(), secureEnclaveAvailable: false),
            sessionStore: SessionStore(store: FakeSecretStore()))
        let recovery = await m.setRecoverySecret("a long enough phrase")
        let password = await m.changePassword(current: "old", new: "a new long password")
        XCTAssertNotNil(recovery, "setting recovery while signed out must fail")
        XCTAssertNotNil(password, "changing the password while signed out must fail")
    }
}
