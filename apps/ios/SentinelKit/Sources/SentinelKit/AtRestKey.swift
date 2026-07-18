import CryptoKit
import Foundation
import Security

/// A small secret store (the Keychain in production) abstracted so the at-rest key hierarchy is
/// testable without a device Keychain. `KeychainStore` conforms directly; `InMemorySecretStore` is
/// the test double.
public protocol SecretStore: Sendable {
    func save(_ data: Data, account: String, accessible: CFString) throws
    func load(account: String) throws -> Data?
    func delete(account: String) throws
}

// `KeychainStore.save` already has this exact signature (its `accessible` default is irrelevant to
// conformance), so this is a zero-body conformance.
extension KeychainStore: SecretStore {}

/// The on-device **at-rest key hierarchy** (CRYPTOGRAPHY.md §5). The durable MLS store
/// (`FileJournal`, which holds ratchet secrets + decrypted messages) is sealed with a 32-byte key.
/// That key is NOT hard-coded and NOT supplied by the caller: it is **HKDF-derived** from a single
/// random **root key** held in the Keychain (device-only, non-syncable, non-backed-up), with a
/// per-store `info` label so distinct stores get independent keys. Rotating or wiping the root
/// (e.g. on logout) makes every derived blob unreadable.
///
/// Threat model: the root never leaves the Keychain; an attacker without device unlock cannot read
/// it, so the at-rest blobs are opaque. (Binding the root to the Secure Enclave — so it cannot be
/// extracted even with the unlocked Keychain — is the hardware upgrade tracked under R-101.)
public struct AtRestKeyHierarchy: Sendable {
    private let store: SecretStore
    private let rootAccount: String

    public init(store: SecretStore, rootAccount: String = "at-rest-root-v1") {
        self.store = store
        self.rootAccount = rootAccount
    }

    /// Availability of the root key. `afterFirstUnlockThisDeviceOnly` lets a background fetch /
    /// Notification Service Extension open the store after the first unlock, while keeping it
    /// device-bound and out of backups. (CFString is non-Sendable, so this is a computed constant,
    /// not a stored field.)
    private static var rootAccessible: CFString { kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly }

    /// HKDF domain separation: bump on any change to the derivation scheme.
    private static let infoPrefix = "app.sentinel.at-rest.v1:"

    /// The 32-byte at-rest key for `storeID` (e.g. a conversation/database id). Deterministic for a
    /// given root + `storeID`, and independent across `storeID`s.
    public func atRestKey(forStore storeID: String) throws -> Data {
        let root = try loadOrCreateRoot()
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: root),
            info: Data((Self.infoPrefix + storeID).utf8),
            outputByteCount: 32)
        return derived.withUnsafeBytes { Data($0) }
    }

    /// Forget the root key (logout / wipe): every derived at-rest key becomes underivable, so the
    /// encrypted stores can never be opened again.
    public func wipeRoot() throws {
        try store.delete(account: rootAccount)
    }

    /// Load the root key, generating + persisting a fresh random one on first use (idempotent).
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

/// In-memory `SecretStore` for tests (and for non-Keychain contexts like a CLI harness). Not for
/// production — it provides no at-rest protection of its own.
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
