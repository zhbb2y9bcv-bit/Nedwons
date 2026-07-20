import CryptoKit
import Foundation

/// Sealed-sender **delivery access key** (DAK) client half (ADR-0014, R-204).
///
/// The recipient generates a 32-byte random `K_r` on-device, registers only its **verifier**
/// `V_r = SHA-256(K_r)` with the relay (`PUT /v1/delivery-access-key`, authenticated), and
/// distributes `K_r` to approved contacts **only inside the E2EE channel**. A sender presents `K_r`
/// to the unauthenticated sealed-delivery endpoint; the relay compares hashes and stores the
/// envelope with no sender identity.
///
/// Honest limits (mirrors `auth_core::delivery_key` and ADR-0014): the relay learns `K_r` on first
/// presentation, so the DAK gates **spam volume, not sender authenticity** — authenticity is the
/// sender-certificate check (`SenderCertificate.verifySealedSender`). Rotating the key (e.g. when
/// blocking a contact) instantly revokes every old holder at the relay.
public struct DeliveryAccessKey: Sendable, Equatable {
    /// The 32-byte secret `K_r`. Never sent to the relay except inside the sealed-delivery header;
    /// never logged; distributed to contacts only via E2EE.
    public let key: Data

    /// Byte width of `K_r` and of its SHA-256 verifier.
    public static let keyLength = 32

    /// Generate a fresh key from the system CSPRNG.
    public static func generate() -> DeliveryAccessKey {
        DeliveryAccessKey(key: Data((0..<keyLength).map { _ in UInt8.random(in: 0...255) }))
    }

    /// Wrap existing key material (e.g. a `K_r` received from a contact over E2EE). Returns nil
    /// unless it is exactly 32 bytes — a truncated key must never be silently accepted.
    public init?(keyMaterial: Data) {
        guard keyMaterial.count == Self.keyLength else { return nil }
        self.key = keyMaterial
    }

    private init(key: Data) { self.key = key }

    /// The verifier `V_r = SHA-256(K_r)` registered with the relay. Byte-identical to Rust's
    /// `auth_core::delivery_key::verifier` (pinned by the shared SHA-256("") golden vector).
    public var verifier: Data {
        Data(SHA256.hash(data: key))
    }
}
