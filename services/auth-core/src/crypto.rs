//! Thin adapters over vetted crypto primitives. No custom cryptography lives here — only
//! calls into RustCrypto (`p256`, `sha2`) and the platform CSPRNG (`rand_core::OsRng`).

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

/// Fill an `N`-byte array from the operating system CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Verify an ECDSA-P256 signature (SHA-256) over `message` using a SEC1-encoded public key.
///
/// Returns `false` for any malformed key, malformed signature, or verification failure —
/// this is a fail-closed boolean, never a panic. The client-side signer in production is a
/// non-exportable Secure Enclave key; this function only ever touches the *public* key.
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
