//! Sealed-sender **delivery access key** (DAK) primitive (ADR-0014, R-204).
//!
//! Sealed delivery removes the authenticated sender, so the relay needs another gate against
//! anonymous spam. A **recipient** holds a 32-byte random `K_r` and registers only its **verifier**
//! `V_r = SHA-256(K_r)` with the relay; it distributes `K_r` to approved senders *inside the E2EE
//! channel* (the relay never sees `K_r` in transit). To deliver a sealed message a sender presents
//! `K_r`; the relay accepts iff `SHA-256(presented) == V_r`.
//!
//! This module is only that pure check. It is deliberately **honest about its limits** (ADR-0014):
//! on first presentation the relay learns `K_r`, so the DAK gates spam *volume*, not sender
//! *authenticity* — authenticity is backstopped by the sender certificate the recipient verifies
//! ([`crate::sender_cert`]). Storing `V_r` (a hash) rather than `K_r` keeps a DB dump from directly
//! yielding usable delivery keys.
//!
//! Generation of `K_r` happens on the recipient's device (client-side CSPRNG); the server only ever
//! computes/compares verifiers, which is why this module has no RNG.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Length of a delivery access key in bytes.
pub const DAK_LEN: usize = 32;

/// Length of a verifier (`SHA-256` output) in bytes.
pub const VERIFIER_LEN: usize = 32;

/// The verifier `V_r = SHA-256(K_r)` the recipient registers with the relay.
pub fn verifier(dak: &[u8]) -> [u8; VERIFIER_LEN] {
    let digest = Sha256::digest(dak);
    let mut out = [0u8; VERIFIER_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Constant-time check that `presented` is the delivery access key behind `expected_verifier`.
/// Fail-closed: a wrong-length verifier (never a valid `SHA-256`) can never match.
pub fn verify(presented_dak: &[u8], expected_verifier: &[u8]) -> bool {
    if expected_verifier.len() != VERIFIER_LEN {
        return false;
    }
    verifier(presented_dak).ct_eq(expected_verifier).into()
}

/// True if `bytes` is a structurally valid verifier to register (exactly `SHA-256` wide). The relay
/// stores whatever verifier the recipient registers; this only rejects malformed input.
pub fn is_valid_verifier(bytes: &[u8]) -> bool {
    bytes.len() == VERIFIER_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_matches_its_own_key() {
        let dak = [0x42u8; DAK_LEN];
        let v = verifier(&dak);
        assert!(verify(&dak, &v));
    }

    #[test]
    fn a_different_key_does_not_verify() {
        let v = verifier(&[0x01u8; DAK_LEN]);
        assert!(!verify(&[0x02u8; DAK_LEN], &v));
    }

    #[test]
    fn malformed_verifier_is_rejected_not_panicking() {
        let dak = [0x07u8; DAK_LEN];
        assert!(!verify(&dak, &[])); // empty
        assert!(!verify(&dak, &[0u8; 31])); // too short
        assert!(!verify(&dak, &[0u8; 33])); // too long
    }

    #[test]
    fn verifier_is_stable_and_is_plain_sha256() {
        // Pin the exact bytes so the Swift client (which computes V_r = SHA-256(K_r)) agrees.
        let v = verifier(b"");
        let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
        // SHA-256("") — the well-known empty-string digest.
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn validity_check_is_length_exact() {
        assert!(is_valid_verifier(&[0u8; VERIFIER_LEN]));
        assert!(!is_valid_verifier(&[0u8; VERIFIER_LEN - 1]));
        assert!(!is_valid_verifier(&[0u8; VERIFIER_LEN + 1]));
    }
}
