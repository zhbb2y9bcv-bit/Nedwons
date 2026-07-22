import CryptoKit
import Foundation

/// The device proof-of-possession key (ADR-0002). The app uses the Secure Enclave so the private
/// key is non-exportable (INV-3); the software implementation serves tests and devices without a
/// usable Enclave — never a silent downgrade, since the app records which path was used and treats
/// software keys as a distinct, lower assurance level.
public protocol DeviceSigner: Sendable {
    /// SEC1 uncompressed (x9.63), as the backend's `VerifyingKey::from_sec1_bytes` expects.
    var publicKeyX963: Data { get }
    /// ECDSA-P256 over SHA-256(message), 64-byte raw `r‖s`, as `Signature::from_slice` expects.
    func sign(_ message: Data) throws -> Data
}

/// Portable (CI, devices without an Enclave). The key is NOT hardware-protected.
public struct SoftwareDeviceSigner: DeviceSigner {
    private let privateKey: P256.Signing.PrivateKey

    public init() {
        privateKey = P256.Signing.PrivateKey()
    }

    /// Software fallback only; hardware keys are never exportable.
    public init(rawRepresentation: Data) throws {
        privateKey = try P256.Signing.PrivateKey(rawRepresentation: rawRepresentation)
    }

    public var publicKeyX963: Data { privateKey.publicKey.x963Representation }

    /// Persists the **software fallback** key so launches reuse it — login must sign with the
    /// *enrolled* key (INV-2). Hardware keys expose no equivalent.
    public var rawRepresentation: Data { privateKey.rawRepresentation }

    public func sign(_ message: Data) throws -> Data {
        try privateKey.signature(for: message).rawRepresentation
    }
}

#if canImport(CryptoKit)
    /// The private key is generated in and never leaves the Enclave; only the encrypted
    /// `dataRepresentation` blob is persisted (Keychain, `ThisDeviceOnly`). Signing may require
    /// user presence, depending on the access control supplied at creation.
    @available(iOS 13.0, macOS 10.15, *)
    public struct SecureEnclaveDeviceSigner: DeviceSigner {
        private let privateKey: SecureEnclave.P256.Signing.PrivateKey

        /// `accessControl` should typically require the passcode and, where appropriate, biometry;
        /// `nil` uses CryptoKit's default. Throws on devices without a usable Enclave — callers
        /// must fall back explicitly, never silently.
        public init(accessControl: SecAccessControl? = nil) throws {
            if let accessControl {
                privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
            } else {
                privateKey = try SecureEnclave.P256.Signing.PrivateKey()
            }
        }

        public init(dataRepresentation: Data) throws {
            privateKey = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: dataRepresentation
            )
        }

        /// NOT the private key: an Enclave-bound blob, useless off the originating device.
        public var dataRepresentation: Data { privateKey.dataRepresentation }

        public var publicKeyX963: Data { privateKey.publicKey.x963Representation }

        public func sign(_ message: Data) throws -> Data {
            try privateKey.signature(for: message).rawRepresentation
        }
    }
#endif
