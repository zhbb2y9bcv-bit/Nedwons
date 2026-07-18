import CryptoKit
import Foundation

/// Sealed-sender **sender certificate** verifier (ADR-0012, R-204). The recipient of a sealed-sender
/// message extracts this certificate from the (E2EE) payload and verifies it under the **pinned**
/// sender-certificate public key, learning the sender the relay never saw. The encoder reproduces
/// `auth_core::sender_cert::SenderCert::encode` **byte-for-byte** (shared golden vector).
public struct SenderCertificate: Sendable {
    public let accountID: Data  // 16 bytes
    public let deviceID: Data  // 16 bytes
    public let senderPublicKeyX963: Data  // SEC1 P-256
    public let expiresAt: UInt64

    public init(accountID: Data, deviceID: Data, senderPublicKeyX963: Data, expiresAt: UInt64) {
        self.accountID = accountID
        self.deviceID = deviceID
        self.senderPublicKeyX963 = senderPublicKeyX963
        self.expiresAt = expiresAt
    }

    static let domain = Data("app.sentinel.sender-cert.v1".utf8)

    /// The canonical byte string that is signed and verified (matches the Rust encoder).
    public func canonicalBytes() -> Data {
        var out = Data()
        Self.putLengthPrefixed(&out, Self.domain)
        Self.putLengthPrefixed(&out, accountID)
        Self.putLengthPrefixed(&out, deviceID)
        Self.putLengthPrefixed(&out, senderPublicKeyX963)
        withUnsafeBytes(of: expiresAt.bigEndian) { out.append(contentsOf: $0) }
        return out
    }

    /// Verify the certificate's ECDSA-P256 signature under the **pinned** sender-cert public key
    /// (distributed in the app binary, not server-asserted), and that it has not expired at `now`.
    public func verify(signature: Data, certPublicKeyX963: Data, now: UInt64) -> Bool {
        guard now <= expiresAt,
            let key = try? P256.Signing.PublicKey(x963Representation: certPublicKeyX963),
            let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
        else { return false }
        return key.isValidSignature(sig, for: canonicalBytes())
    }

    /// Verify this certificate for **sealed-sender receipt** (ADR-0012 Slice 2). Three checks, all
    /// required: the signature is valid under the recipient's **pinned** sender-cert public key; the
    /// certificate has not expired at `now`; and its bound `senderPublicKeyX963` **equals the key MLS
    /// attributes this message to**. The last check is what ties a relay-invisible sender to the
    /// actual MLS sender — without it, a valid certificate for device A could be wrapped around a
    /// message MLS says came from device B. Fail-closed boolean.
    public func verifySealedSender(
        signature: Data,
        pinnedCertPublicKeyX963: Data,
        mlsSenderPublicKeyX963: Data,
        now: UInt64
    ) -> Bool {
        guard verify(signature: signature, certPublicKeyX963: pinnedCertPublicKeyX963, now: now)
        else { return false }
        // Public keys — a plain equality check is sufficient (no secret-dependent timing).
        return senderPublicKeyX963 == mlsSenderPublicKeyX963
    }

    private static func putLengthPrefixed(_ out: inout Data, _ field: Data) {
        withUnsafeBytes(of: UInt32(field.count).bigEndian) { out.append(contentsOf: $0) }
        out.append(field)
    }

    /// The exact input behind the Rust golden vector, for cross-platform byte-identity testing.
    public static func sampleVectorInput() -> SenderCertificate {
        var pk = Data([0x04])
        pk.append(Data((0..<64).map { UInt8($0) }))
        return SenderCertificate(
            accountID: Data(repeating: 0xA1, count: 16),
            deviceID: Data(repeating: 0xB2, count: 16),
            senderPublicKeyX963: pk,
            expiresAt: 1_700_000_000)
    }
}
