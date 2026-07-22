//! Sealed-sender **delivery access key** (DAK) primitive (ADR-0014, R-204).
//!
//! Sealed delivery removes the authenticated sender, so the relay needs another anti-spam gate. The
//! recipient holds a 32-byte `K_r`, registers only `V_r = SHA-256(K_r)`, and distributes `K_r`
//! inside the E2EE channel; a sender presents `K_r` and the relay accepts iff the hash matches.
//!
//! **Honest limit** (ADR-0014): on first presentation the relay learns `K_r`, so this gates spam
//! *volume*, not sender *authenticity* — authenticity comes from [`crate::sender_cert`]. Storing
//! the hash keeps a DB dump from directly yielding usable delivery keys.
//!
//! `K_r` is generated on the recipient's device, which is why this module needs no RNG.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const DAK_LEN: usize = 32;

/// `SHA-256` output width.
pub const VERIFIER_LEN: usize = 32;

/// `V_r = SHA-256(K_r)`, what the recipient registers with the relay.
pub fn verifier(dak: &[u8]) -> [u8; VERIFIER_LEN] {
    let digest = Sha256::digest(dak);
    let mut out = [0u8; VERIFIER_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Constant-time, to avoid delivery-key timing leaks. Fail-closed: a wrong-length verifier can
/// never match.
pub fn verify(presented_dak: &[u8], expected_verifier: &[u8]) -> bool {
    if expected_verifier.len() != VERIFIER_LEN {
        return false;
    }
    verifier(presented_dak).ct_eq(expected_verifier).into()
}

/// Rejects malformed input only; the relay stores whatever verifier the recipient registers.
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
        // Pinned so the Swift client's V_r computation agrees. This is SHA-256("").
        let v = verifier(b"");
        let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
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
