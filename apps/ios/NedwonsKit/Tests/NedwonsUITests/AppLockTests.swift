import XCTest

@testable import NedwonsKit
@testable import NedwonsUI

/// A scripted owner-check so the app-lock state machine can be tested without hardware.
private final class StubAppLock: AppLockAuthenticating, @unchecked Sendable {
    var available: Bool
    var willSucceed: Bool
    private(set) var prompts = 0

    init(available: Bool = true, willSucceed: Bool = true) {
        self.available = available
        self.willSucceed = willSucceed
    }

    var isAvailable: Bool { available }
    var biometryName: String { "Face ID" }
    func authenticate(reason: String) async -> Bool {
        prompts += 1
        return willSucceed
    }
}

@MainActor
final class AppLockTests: XCTestCase {
    private func model(_ auth: StubAppLock) -> AppModel {
        let m = AppModel(
            baseURL: URL(string: "http://127.0.0.1:1")!,
            deviceIdentity: DeviceIdentity(
                store: InMemoryDeviceKeyStore(), secureEnclaveAvailable: false),
            sessionStore: SessionStore(store: FakeSecretStore()))
        m.appLockAuthenticator = auth
        // A fresh model in a test may have inherited a persisted default; normalize to off.
        m.appLockEnabled = false
        m.isLocked = false
        return m
    }

    func testEnablingRequiresAndPassesTheOwnerCheck() async {
        let auth = StubAppLock(willSucceed: true)
        let m = model(auth)
        let changed = await m.setAppLock(true)
        XCTAssertTrue(changed)
        XCTAssertTrue(m.appLockEnabled)
        XCTAssertFalse(m.isLocked, "just authenticated, so the app is open right now")
        XCTAssertEqual(auth.prompts, 1)
    }

    func testEnablingIsRefusedIfTheOwnerCheckFails() async {
        let auth = StubAppLock(willSucceed: false)
        let m = model(auth)
        let changed = await m.setAppLock(true)
        XCTAssertFalse(changed)
        XCTAssertFalse(m.appLockEnabled, "a failed check must not turn the lock on")
    }

    func testEnablingIsRefusedWhenNoOwnerCheckIsAvailable() async {
        let auth = StubAppLock(available: false)
        let m = model(auth)
        let changed = await m.setAppLock(true)
        XCTAssertFalse(changed)
        XCTAssertFalse(m.appLockEnabled)
        XCTAssertEqual(auth.prompts, 0, "we never even prompt when the device can't authenticate")
    }

    func testBackgroundingLocksOnlyWhenEnabled() {
        let m = model(StubAppLock())
        m.lockIfEnabled()
        XCTAssertFalse(m.isLocked, "disabled: backgrounding does not lock")

        m.appLockEnabled = true
        m.lockIfEnabled()
        XCTAssertTrue(m.isLocked, "enabled: backgrounding locks")
    }

    func testUnlockClearsTheLockOnSuccessAndKeepsItOnFailure() async {
        let auth = StubAppLock(willSucceed: false)
        let m = model(auth)
        m.appLockEnabled = true
        m.isLocked = true

        await m.unlock()
        XCTAssertTrue(m.isLocked, "a failed unlock stays locked")

        auth.willSucceed = true
        await m.unlock()
        XCTAssertFalse(m.isLocked, "a passed unlock opens the app")
    }

    func testDisablingAlsoRequiresTheOwnerCheck() async {
        let auth = StubAppLock(willSucceed: false)
        let m = model(auth)
        m.appLockEnabled = true

        let changedWhileFailing = await m.setAppLock(false)
        XCTAssertFalse(changedWhileFailing)
        XCTAssertTrue(m.appLockEnabled, "can't disable the lock without passing the check")

        auth.willSucceed = true
        let changed = await m.setAppLock(false)
        XCTAssertTrue(changed)
        XCTAssertFalse(m.appLockEnabled)
    }
}
