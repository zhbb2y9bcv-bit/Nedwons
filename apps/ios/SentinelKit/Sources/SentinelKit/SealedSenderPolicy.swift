import Foundation

/// The client-side policy for sealed-sender (ADR-0014 Slice 2c). The relay is sender-blind, so the
/// authenticity + abuse decisions live entirely on the recipient/sender, after E2EE:
///
/// - **K_r distribution.** You share your delivery access key `K_r` with an approved contact only
///   inside the E2EE channel (an `MlsClient.enqueueDeliveryKeyGrant`), so they can send you sealed
///   messages. The relay never sees `K_r`.
/// - **Recipient block-drop.** A sealed envelope carries no sender at the relay; the recipient
///   decrypts it, verifies the embedded sender certificate, and — if that (now-authenticated) sender
///   is blocked — drops it silently ([`shouldDropDecrypted`]).
/// - **Block → rotate → redistribute.** Blocking a contact rotates `K_r` (registering a new verifier
///   revokes the blocked party's copy at the relay) and re-grants the new `K_r` to the remaining
///   approved contacts ([`rotateOnBlock`]).
/// - **Message-request fallback.** You can only send *sealed* to someone whose `K_r` you hold; a
///   first contact / non-contact has none, so the message goes over the normal identified path as a
///   "message request" ([`canSendSealed`]).
public enum SealedSenderPolicy {
    /// Recipient-side block-drop: after decrypting a sealed message and verifying the sender
    /// certificate, drop it iff that authenticated sender is blocked.
    public static func shouldDropDecrypted(
        verifiedSenderAccountID: String, blocked: Set<String>
    ) -> Bool {
        blocked.contains(verifiedSenderAccountID)
    }

    /// Whether a sealed message can be sent to `accountID` — i.e. we hold their `K_r`. If not, the
    /// caller falls back to the identified conversation path (a message request).
    public static func canSendSealed(to accountID: String, grantedKeys: Set<String>) -> Bool {
        grantedKeys.contains(accountID)
    }

    /// The plan produced when blocking `blockedAccount`: a freshly rotated `K_r` (register its
    /// verifier to revoke the blocked party at the relay) and the sorted set of remaining approved
    /// contacts to re-grant the new key to. The blocked account is never in `regrantTo`.
    public static func rotateOnBlock(
        approvedContacts: Set<String>, blocking blockedAccount: String
    ) -> DeliveryKeyRotation {
        let remaining = approvedContacts.subtracting([blockedAccount]).sorted()
        return DeliveryKeyRotation(newKey: DeliveryAccessKey.generate(), regrantTo: remaining)
    }
}

/// The outcome of a block-triggered `K_r` rotation.
public struct DeliveryKeyRotation: Sendable {
    /// The new `K_r` — register its verifier with the relay, then grant it to `regrantTo`.
    public let newKey: DeliveryAccessKey
    /// Account ids to send the new `K_r` to (the remaining approved contacts, sorted).
    public let regrantTo: [String]
}
