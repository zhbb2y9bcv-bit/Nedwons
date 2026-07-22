import CryptoKit
import Foundation

/// The **single place** deciding hardware-vs-software; the app never constructs a `DeviceSigner`
/// directly (R-G0-2). Registration enrolls the Enclave key when the hardware exists and login
/// reloads that **same enrolled key** — signing a fresh key each time would silently break device
/// binding (INV-2).
///
/// A device without an Enclave is handled by an **explicit** policy (ADR-0002, ADR-0008): fail
/// closed, or an acknowledged lower-assurance software fallback — never a silent downgrade.

public enum DeviceAssurance: String, Sendable, Equatable {
    /// Non-exportable key generated in the Secure Enclave.
    case hardware
    /// The device lacks a usable Enclave. Lower assurance; surfaced to the user.
    case software
}

public enum DeviceProvisionPolicy: Sendable, Equatable {
    /// If the Enclave is unavailable, refuse to enroll — no session is possible.
    case requireHardware
    /// The caller MUST have obtained the user's acknowledgement first; this is never silent.
    case allowSoftwareFallback
}

public enum DeviceIdentityError: Error, Equatable {
    /// `requireHardware` policy on a device without a usable Secure Enclave.
    case secureHardwareUnavailable
    /// Persisted key material is present but malformed/unreadable.
    case corruptKeyMaterial
    /// Backing storage (Keychain) failed.
    case storage
}

/// A ready-to-use signer plus the assurance level it was provisioned/loaded at.
public struct EnrolledSigner: Sendable {
    public let signer: any DeviceSigner
    public let assurance: DeviceAssurance
}

/// Abstracts the sensitive-blob store so provisioning logic is unit-testable without a Keychain.
public protocol DeviceKeyStore: Sendable {
    func save(_ data: Data) throws
    func load() throws -> Data?
    func remove() throws
}

/// Keychain-backed store (production). The persisted blob is either the Enclave key's opaque,
/// device-bound `dataRepresentation` (useless off-device) or, on the software path, the raw key.
/// `ThisDeviceOnly` accessibility keeps it out of backups and off other devices.
public struct KeychainDeviceKeyStore: DeviceKeyStore {
    private let keychain: KeychainStore
    private let account: String

    public init(service: String = "tech.nedwons.device", account: String = "device-identity-key") {
        keychain = KeychainStore(service: service)
        self.account = account
    }

    public func save(_ data: Data) throws {
        do { try keychain.save(data, account: account) } catch { throw DeviceIdentityError.storage }
    }

    public func load() throws -> Data? {
        do { return try keychain.load(account: account) } catch { throw DeviceIdentityError.storage }
    }

    public func remove() throws {
        do { try keychain.delete(account: account) } catch { throw DeviceIdentityError.storage }
    }
}

public struct DeviceIdentity: Sendable {
    private let store: any DeviceKeyStore
    private let secureEnclaveAvailable: Bool

    /// A 1-byte tag prefixes the stored blob so we know how to reconstruct the signer.
    private static let tagHardware: UInt8 = 0x01
    private static let tagSoftware: UInt8 = 0x00

    /// - Parameter secureEnclaveAvailable: defaults to the real hardware check; injectable so the
    ///   fail-closed and fallback branches can be tested on any host.
    public init(
        store: any DeviceKeyStore = KeychainDeviceKeyStore(),
        secureEnclaveAvailable: Bool = SecureEnclave.isAvailable
    ) {
        self.store = store
        self.secureEnclaveAvailable = secureEnclaveAvailable
    }

    /// Enroll a fresh device key and persist it. Called once, at registration.
    public func provision(policy: DeviceProvisionPolicy) throws -> EnrolledSigner {
        if secureEnclaveAvailable {
            // No biometric/user-presence access control on the possession key: refresh must work
            // in the background. Local app-unlock is a separate layer (ADR-0002, roadmap Gate 1).
            let signer = try SecureEnclaveDeviceSigner()
            try store.save(tagged(Self.tagHardware, signer.dataRepresentation))
            return EnrolledSigner(signer: signer, assurance: .hardware)
        }
        switch policy {
        case .requireHardware:
            throw DeviceIdentityError.secureHardwareUnavailable
        case .allowSoftwareFallback:
            let signer = SoftwareDeviceSigner()
            try store.save(tagged(Self.tagSoftware, signer.rawRepresentation))
            return EnrolledSigner(signer: signer, assurance: .software)
        }
    }

    /// Reload the previously enrolled key so login/refresh sign with the *same* key. `nil` if this
    /// device has never enrolled (the caller should then register or recover).
    public func loadEnrolled() throws -> EnrolledSigner? {
        guard let blob = try store.load() else { return nil }
        guard let (tag, body) = untag(blob) else { throw DeviceIdentityError.corruptKeyMaterial }
        switch tag {
        case Self.tagHardware:
            guard let signer = try? SecureEnclaveDeviceSigner(dataRepresentation: body) else {
                throw DeviceIdentityError.corruptKeyMaterial
            }
            return EnrolledSigner(signer: signer, assurance: .hardware)
        case Self.tagSoftware:
            guard let signer = try? SoftwareDeviceSigner(rawRepresentation: body) else {
                throw DeviceIdentityError.corruptKeyMaterial
            }
            return EnrolledSigner(signer: signer, assurance: .software)
        default:
            throw DeviceIdentityError.corruptKeyMaterial
        }
    }

    /// Forget the enrolled key (e.g. to re-enroll after revocation). Idempotent.
    public func reset() throws { try store.remove() }

    private func tagged(_ tag: UInt8, _ body: Data) -> Data {
        var out = Data([tag])
        out.append(body)
        return out
    }

    private func untag(_ blob: Data) -> (UInt8, Data)? {
        guard let tag = blob.first else { return nil }
        return (tag, blob.dropFirst())
    }
}

/// In-memory store for tests (no Keychain).
public final class InMemoryDeviceKeyStore: DeviceKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    public init() {}
    public func save(_ data: Data) throws { lock.lock(); defer { lock.unlock() }; self.data = data }
    public func load() throws -> Data? { lock.lock(); defer { lock.unlock() }; return data }
    public func remove() throws { lock.lock(); defer { lock.unlock() }; data = nil }
}
