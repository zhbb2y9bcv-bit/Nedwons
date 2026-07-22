import CryptoKit
import Foundation
import Security

/// Abstracted so the at-rest key hierarchy is testable without a device Keychain.
public protocol SecretStore: Sendable {
    func save(_ data: Data, account: String, accessible: CFString) throws
    func load(account: String) throws -> Data?
    func delete(account: String) throws
}

// `KeychainStore.save` already matches this signature, so the conformance needs no body.
extension KeychainStore: SecretStore {}

/// The on-device **at-rest key hierarchy** (CRYPTOGRAPHY.md §5). The key sealing the durable MLS
/// store is neither hard-coded nor caller-supplied: it is HKDF-derived from one random root held in
/// the Keychain (device-only, non-syncable, non-backed-up), with a per-store `info` label so stores
/// get independent keys. Wiping the root on logout makes every derived blob unreadable.
///
/// The root never leaves the Keychain, so without device unlock the blobs stay opaque. Binding the
/// root to the Secure Enclave — unextractable even with the Keychain unlocked — is tracked in R-101.
public struct AtRestKeyHierarchy: Sendable {
    private let store: SecretStore
    private let rootAccount: String

    public init(store: SecretStore, rootAccount: String = "at-rest-root-v1") {
        self.store = store
        self.rootAccount = rootAccount
    }

    /// `afterFirstUnlockThisDeviceOnly` lets the Notification Service Extension open the store
    /// after first unlock while keeping it device-bound and out of backups. Computed, not stored,
    /// because `CFString` is non-Sendable.
    private static var rootAccessible: CFString { kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly }

    /// HKDF domain separation: bump on any change to the derivation scheme.
    private static let infoPrefix = "app.nedwons.at-rest.v1:"

    /// Deterministic for a given root + `storeID`, and independent across `storeID`s.
    public func atRestKey(forStore storeID: String) throws -> Data {
        let root = try loadOrCreateRoot()
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: root),
            info: Data((Self.infoPrefix + storeID).utf8),
            outputByteCount: 32)
        return derived.withUnsafeBytes { Data($0) }
    }

    /// Logout/wipe: every derived key becomes underivable, so the stores can never be opened again.
    public func wipeRoot() throws {
        try store.delete(account: rootAccount)
    }

    /// Generates + persists a fresh random root on first use. Idempotent.
    private func loadOrCreateRoot() throws -> Data {
        if let existing = try store.load(account: rootAccount) {
            return existing
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw AtRestKeyError.randomFailure(status) }
        let root = Data(bytes)
        try store.save(root, account: rootAccount, accessible: Self.rootAccessible)
        return root
    }
}

public enum AtRestKeyError: Error, Equatable {
    case randomFailure(OSStatus)
}

/// For tests and non-Keychain contexts such as a CLI harness. NOT for production: it provides no
/// at-rest protection of its own.
public final class InMemorySecretStore: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]

    public init() {}

    public func save(_ data: Data, account: String, accessible: CFString) throws {
        lock.lock()
        defer { lock.unlock() }
        items[account] = data
    }

    public func load(account: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return items[account]
    }

    public func delete(account: String) throws {
        lock.lock()
        defer { lock.unlock() }
        items[account] = nil
    }
}
