import CryptoKit
import Foundation

#if canImport(DeviceCheck)
    import DeviceCheck
#endif

/// Apple **App Attest** (`DCAppAttestService`): proves the running client is a genuine, unmodified
/// build of THIS app on real Apple hardware — distinct from the Secure Enclave *device key*
/// (`SecureEnclaveDeviceSigner`), which proves possession of an enrolled signing key. Together they
/// raise the bar against emulators, tampered builds, and key-extraction (R-101 / R-G0-2).
///
/// **Hardware-gated (honest limit).** `isSupported` is false on the Simulator, on macOS, and on a
/// jailbroken device, so `generateKey`/`attestKey`/`generateAssertion` throw `.unsupported` off real
/// hardware. Live attestation needs a physical device + the app's App Attest entitlement + the
/// server-side verification of the attestation object against Apple's App Attest root (a separate
/// backend task; see docs/APP_ATTEST.md). This wrapper compiles and is unit-tested everywhere; only
/// the live path is device-bound.
public struct AppAttestation: Sendable {
    public init() {}

    /// Whether App Attest is available on this device right now (false on Simulator / macOS / a
    /// compromised device).
    public var isSupported: Bool {
        #if canImport(DeviceCheck)
            if #available(iOS 14.0, macOS 11.0, *) {
                return DCAppAttestService.shared.isSupported
            }
        #endif
        return false
    }

    /// Generate a fresh hardware attestation key; returns its opaque key id. The private key never
    /// leaves the Secure Enclave. Throws `.unsupported` off real hardware.
    public func generateKey() async throws -> String {
        #if canImport(DeviceCheck)
            if #available(iOS 14.0, macOS 11.0, *), DCAppAttestService.shared.isSupported {
                return try await DCAppAttestService.shared.generateKey()
            }
        #endif
        throw AppAttestError.unsupported
    }

    /// Attest `keyId` over a server-issued `challenge`. Returns the CBOR attestation object the
    /// server verifies against Apple's App Attest root (binding the key + app id + a genuine device).
    public func attestKey(_ keyId: String, challenge: Data) async throws -> Data {
        #if canImport(DeviceCheck)
            if #available(iOS 14.0, macOS 11.0, *), DCAppAttestService.shared.isSupported {
                let hash = Data(SHA256.hash(data: challenge))
                return try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: hash)
            }
        #endif
        throw AppAttestError.unsupported
    }

    /// Produce an assertion over `clientData` (e.g. a later authenticated request), proving continued
    /// possession of the attested key without re-attesting.
    public func generateAssertion(_ keyId: String, clientData: Data) async throws -> Data {
        #if canImport(DeviceCheck)
            if #available(iOS 14.0, macOS 11.0, *), DCAppAttestService.shared.isSupported {
                let hash = Data(SHA256.hash(data: clientData))
                return try await DCAppAttestService.shared.generateAssertion(
                    keyId, clientDataHash: hash)
            }
        #endif
        throw AppAttestError.unsupported
    }
}

public enum AppAttestError: Error, Equatable {
    /// App Attest is not available here (Simulator / macOS / compromised device / missing entitlement).
    case unsupported
}
