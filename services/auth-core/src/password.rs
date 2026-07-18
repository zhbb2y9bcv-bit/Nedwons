//! Argon2id password hashing (RFC 9106) via the RustCrypto `argon2` crate.
//!
//! Parameters here are a **conservative starting point**, not a production benchmark
//! (RISK_REGISTER R-302): they must be tuned on production hardware and the chosen
//! algorithm/version/parameters recorded (the PHC string stores them, enabling future
//! rehashing). A server-side pepper, if used, must live in a KMS/HSM and never in the DB
//! or repo (R-303) — it is intentionally not wired into this pure slice.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::crypto::random_bytes;
use crate::error::AuthError;

/// OWASP-aligned starting parameters: 19 MiB memory, 2 iterations, 1 lane.
const MEMORY_KIB: u32 = 19_456;
const ITERATIONS: u32 = 2;
const PARALLELISM: u32 = 1;

/// Password policy per **NIST SP 800-63B-4** (the current revision; earlier revisions are
/// superseded): prioritize length, no composition puzzles, no periodic rotation. 800-63B-4
/// verifiers SHALL require ≥ 8 characters and SHOULD require ≥ 15; the product policy here is
/// a 12-character minimum (exceeds the SHALL; blocklist + length carry the strength). The
/// generous maximum supports long passphrases and password managers (Argon2 cost is
/// length-independent after hashing input).
pub const MIN_PASSWORD_CHARS: usize = 12;
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// A small embedded blocklist of the most common passwords/patterns that satisfy the
/// length rule. This is a floor, not the ceiling: production must layer a real compromised-
/// credential list (e.g. a k-anonymity range query) — tracked in RISK_REGISTER R-305.
const COMMON_PASSWORDS: &[&str] = &[
    "password1234",
    "password12345",
    "123456789012",
    "qwertyuiop12",
    "iloveyou1234",
    "adminadmin12",
    "letmeinplease",
    "changemeplease",
    "correcthorsebatterystaple", // famous example phrase — widely guessed
    "welcome12345",
    "sunshine1234",
    "trustno1trustno1",
];

/// Validate a candidate password against the policy. Case-insensitive blocklist match.
pub fn validate_password_policy(password: &str) -> Result<(), AuthError> {
    if password.chars().count() < MIN_PASSWORD_CHARS || password.len() > MAX_PASSWORD_BYTES {
        return Err(AuthError::WeakPassword);
    }
    let lowered = password.to_lowercase();
    if COMMON_PASSWORDS.contains(&lowered.as_str()) {
        return Err(AuthError::WeakPassword);
    }
    Ok(())
}

/// Build the Argon2id hasher with our fixed, recorded parameters.
pub(crate) fn hasher() -> Argon2<'static> {
    // `Params::new` only fails on out-of-range constants; ours are valid, so a failure is a
    // programming error, not a runtime condition.
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, None)
        .expect("static Argon2 parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a password, returning a PHC string (contains algorithm, version, params, salt).
pub(crate) fn hash_password(argon2: &Argon2<'_>, password: &str) -> Result<String, AuthError> {
    // Generate the salt from the OS CSPRNG rather than relying on a specific rand feature
    // wiring, then encode it in PHC base64.
    let salt_bytes = random_bytes::<16>();
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| AuthError::Internal)?;
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| AuthError::Internal)?;
    Ok(hash.to_string())
}

/// Verify `password` against a stored PHC hash. Returns `Ok(true)`/`Ok(false)`; a malformed
/// stored hash is an internal fault (it should never happen for data we wrote).
pub(crate) fn verify_password(
    argon2: &Argon2<'_>,
    password: &str,
    stored_phc: &str,
) -> Result<bool, AuthError> {
    let parsed = PasswordHash::new(stored_phc).map_err(|_| AuthError::Internal)?;
    Ok(argon2.verify_password(password.as_bytes(), &parsed).is_ok())
}

/// A valid PHC hash of a random throwaway password, used to equalize timing on the
/// account-not-found path (enumeration resistance, ABUSE_MODEL.md). We verify the supplied
/// password against this dummy so the not-found branch does the same Argon2 work as the
/// found branch before returning a generic failure.
pub(crate) fn make_dummy_hash(argon2: &Argon2<'_>) -> String {
    let throwaway = random_bytes::<32>();
    let salt_bytes = random_bytes::<16>();
    let salt = SaltString::encode_b64(&salt_bytes).expect("valid salt");
    argon2
        .hash_password(&throwaway, &salt)
        .expect("hashing random bytes cannot fail")
        .to_string()
}
