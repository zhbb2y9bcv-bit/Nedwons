import Foundation
import Security

/// Persists the signed-in session so a relaunch resumes instead of forcing a fresh registration.
/// Only the tokens and the immutable identifiers are stored — never the password. The device key
/// itself stays in `DeviceIdentity`; this store holds no key material, so a restored session is
/// still worthless without the enrolled device key (INV-2).
public struct SessionStore: Sendable {
    private let store: SecretStore
    private let account: String

    public init(store: SecretStore, account: String = "session-v1") {
        self.store = store
        self.account = account
    }

    public init(service: String = "app.nedwons.session") {
        self.init(store: KeychainStore(service: service))
    }

    /// Codable mirror of `NedwonsClient.Session` (which stays a plain value type in the client).
    private struct Persisted: Codable {
        let accountID: String
        let deviceID: String
        let accessToken: String
        let accessExpiresAt: UInt64
        let refreshToken: String
        let refreshExpiresAt: UInt64
    }

    public func save(_ session: NedwonsClient.Session) throws {
        let data = try JSONEncoder().encode(
            Persisted(
                accountID: session.accountID,
                deviceID: session.deviceID,
                accessToken: session.accessToken,
                accessExpiresAt: session.accessExpiresAt,
                refreshToken: session.refreshToken,
                refreshExpiresAt: session.refreshExpiresAt
            ))
        // Device-only + non-syncable: a session must never ride an iCloud backup to another device.
        try store.save(data, account: account, accessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
    }

    /// `nil` when absent or unreadable. A corrupt blob is treated as "no session" rather than an
    /// error, so a bad write can never wedge the app at launch.
    public func load() -> NedwonsClient.Session? {
        guard let data = try? store.load(account: account),
            let p = try? JSONDecoder().decode(Persisted.self, from: data)
        else { return nil }
        return NedwonsClient.Session(
            accountID: p.accountID,
            deviceID: p.deviceID,
            accessToken: p.accessToken,
            accessExpiresAt: p.accessExpiresAt,
            refreshToken: p.refreshToken,
            refreshExpiresAt: p.refreshExpiresAt
        )
    }

    public func clear() {
        try? store.delete(account: account)
    }
}
