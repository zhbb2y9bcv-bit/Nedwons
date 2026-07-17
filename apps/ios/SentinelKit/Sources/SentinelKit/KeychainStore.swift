import Foundation
import Security

/// Thin wrapper over the Keychain for the small, sensitive blobs the client persists: the
/// Secure Enclave key's encrypted `dataRepresentation`, the local DB wrapping key, and the
/// refresh token. Items default to `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` so they
/// are not included in backups and never leave the originating device (SECURITY.md,
/// CRYPTOGRAPHY.md §5). Passwords are never stored.
///
/// This type type-checks with `swift build`; its runtime behavior depends on a real
/// Keychain and is validated on device (RISK_REGISTER R-101).
public struct KeychainStore: Sendable {
    public let service: String

    public init(service: String) {
        self.service = service
    }

    public enum KeychainError: Error, Equatable {
        case unexpectedStatus(OSStatus)
    }

    /// Insert or replace the item for `account`.
    public func save(
        _ data: Data,
        account: String,
        accessible: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ) throws {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        // Replace semantics: delete any prior item, then add with the desired protection.
        SecItemDelete(base as CFDictionary)

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
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
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
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
}
