import Foundation
import Security

/// Keychain wrapper for the small sensitive blobs: the Enclave key's encrypted
/// `dataRepresentation`, the local DB wrapping key, and the refresh token. Defaults to
/// `WhenUnlockedThisDeviceOnly`, so items stay out of backups and never leave the originating
/// device. Passwords are never stored.
///
/// This type type-checks with `swift build`; its runtime behavior depends on a real
/// Keychain and is validated on device (RISK_REGISTER R-101).
public struct KeychainStore: Sendable {
    public let service: String
    /// The shared Keychain access group, or `nil` for the app's private default group.
    ///
    /// EXPLICIT, never inferred. An app and its Notification Service Extension have different
    /// bundle identifiers and therefore different default access groups, so a `KeychainStore` with
    /// no group reads a DIFFERENT keychain in each target. The extension would find no session, and
    /// every push would silently degrade to the generic wake — on device only, since the failure is
    /// invisible until both targets are really signed and installed.
    ///
    /// Passing the group explicitly makes that sharing a declared property of the call site rather
    /// than an accident of entitlement ordering.
    public let accessGroup: String?

    public init(service: String, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    /// The query attributes identifying an item: service, account, and the access group when one
    /// is configured.
    ///
    /// The group is OMITTED rather than set to nil when absent. `kSecAttrAccessGroup` present with
    /// an empty or unentitled value fails the query outright (`errSecMissingEntitlement`), which in
    /// the Simulator — where keychain groups are not enforced the same way — turns into a confusing
    /// "works here, fails on device" difference.
    func baseQuery(account: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    public enum KeychainError: Error, Equatable {
        case unexpectedStatus(OSStatus)
    }

    /// Insert or replace the item for `account`.
    ///
    /// Update-then-add, NOT delete-then-add. The rotating refresh token is written through here,
    /// and delete-then-add has a window in which the item does not exist at all: a crash, a jetsam
    /// kill, or the device locking between the two calls leaves NO session, which signs the user
    /// out and — because the rotated token is then lost while the server has already retired the
    /// old one — cannot be recovered by retrying. `SecItemUpdate` replaces the value in place, so
    /// a reader sees either the old blob or the new one and never absence.
    ///
    /// `kSecAttrAccessible` is part of the update, so a protection-class change still takes effect.
    /// Only when no item exists yet (`errSecItemNotFound`) does this add one.
    public func save(
        _ data: Data,
        account: String,
        accessible: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ) throws {
        let base = baseQuery(account: account)
        let updateStatus = SecItemUpdate(
            base as CFDictionary,
            [
                kSecValueData as String: data,
                kSecAttrAccessible as String: accessible,
            ] as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        guard updateStatus == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(updateStatus)
        }

        var addQuery = base
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = accessible

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    /// Load the item for `account`, or `nil` if absent.
    public func load(account: String) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
        return item as? Data
    }

    /// Remove the item for `account` (idempotent).
    public func delete(account: String) throws {
        let query = baseQuery(account: account)
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
}
