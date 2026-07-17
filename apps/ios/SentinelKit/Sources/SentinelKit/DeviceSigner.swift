import CryptoKit
import Foundation

/// Abstraction over the device proof-of-possession key (ADR-0002). The app uses the Secure
/// Enclave implementation so the private key is non-exportable (INV-3); tests and the
/// interop tool use the software implementation, which is also the documented fallback for
/// devices without a usable Secure Enclave (never a silent downgrade — the app records which
/// path was used and treats software-backed keys as a distinct, lower assurance level).
public protocol DeviceSigner: Sendable {
    /// SEC1 uncompressed (x9.63) public key, accepted by the Rust backend's
    /// `verify_p256` / `VerifyingKey::from_sec1_bytes`.
    var publicKeyX963: Data { get }
    /// ECDSA-P256 signature over SHA-256(message), 64-byte raw `r‖s` form, matching the
    /// backend's `Signature::from_slice`.
    func sign(_ message: Data) throws -> Data
}

/// In-memory P-256 signer. Portable (works in `swift test`/CI and on devices without a
/// Secure Enclave). The key is NOT hardware-protected.
public struct SoftwareDeviceSigner: DeviceSigner {
    private let privateKey: P256.Signing.PrivateKey

    public init() {
        privateKey = P256.Signing.PrivateKey()
    }

    /// Reconstruct from a stored raw private key (e.g. a Keychain item). Only for the
    /// software fallback path; hardware keys are never exportable.
    public init(rawRepresentation: Data) throws {
        privateKey = try P256.Signing.PrivateKey(rawRepresentation: rawRepresentation)
    }

    public var publicKeyX963: Data { privateKey.publicKey.x963Representation }

    /// Raw private-key bytes, for persisting the **software fallback** key so the same key is
    /// reused across launches (login must sign with the *enrolled* key — INV-2). Hardware keys
    /// are never exportable and expose no equivalent; this exists only on the software path.
    public var rawRepresentation: Data { privateKey.rawRepresentation }

    public func sign(_ message: Data) throws -> Data {
        try privateKey.signature(for: message).rawRepresentation
    }
}

#if canImport(CryptoKit)
    /// Secure Enclave signer: the private key is generated in and never leaves the Enclave.
    /// The app persists only the encrypted `dataRepresentation` blob (in the Keychain,
    /// `ThisDeviceOnly`) and reloads the key handle from it. Signing may require user
    /// presence/biometrics depending on the access control supplied at creation.
    @available(iOS 13.0, macOS 10.15, *)
    public struct SecureEnclaveDeviceSigner: DeviceSigner {
        private let privateKey: SecureEnclave.P256.Signing.PrivateKey

        /// Generate a fresh non-exportable Enclave key. `accessControl` should typically
        /// require the device passcode and, where appropriate, biometry
        /// (`.privateKeyUsage`, `.userPresence`). When `nil`, CryptoKit's default access
        /// control is used. Throws on devices without a usable Secure Enclave — callers must
        /// fall back explicitly, never silently.
        public init(accessControl: SecAccessControl? = nil) throws {
            if let accessControl {
                privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
            } else {
                privateKey = try SecureEnclave.P256.Signing.PrivateKey()
            }
        }

        /// Reload a previously created Enclave key from its encrypted blob.
        public init(dataRepresentation: Data) throws {
            privateKey = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: dataRepresentation
            )
        }

        /// Encrypted, Enclave-bound blob to persist in the Keychain. This is NOT the private
        /// key and is useless off the originating device.
        public var dataRepresentation: Data { privateKey.dataRepresentation }

        public var publicKeyX963: Data { privateKey.publicKey.x963Representation }

        public func sign(_ message: Data) throws -> Data {
            try privateKey.signature(for: message).rawRepresentation
        }
    }
#endif
