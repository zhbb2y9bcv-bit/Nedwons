//! Thin adapters over RustCrypto (`p256`, `sha2`) and the platform CSPRNG. No custom cryptography.

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

/// From the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// ECDSA-P256 (SHA-256) with a SEC1 public key. Fail-closed: `false` for a malformed key,
/// malformed signature, or failed verification — never a panic. Only ever touches the *public*
/// key; the production signer is a non-exportable Secure Enclave key.
pub fn verify_p256(public_key_sec1: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let verifying_key = match VerifyingKey::from_sec1_bytes(public_key_sec1) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let signature = match Signature::from_slice(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    verifying_key.verify(message, &signature).is_ok()
}
