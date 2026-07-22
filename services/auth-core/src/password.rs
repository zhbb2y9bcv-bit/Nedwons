//! Argon2id password hashing (RFC 9106) via RustCrypto `argon2`.
//!
//! Parameters are a conservative starting point, NOT a production benchmark (R-302): tune on
//! production hardware; the PHC string records them, enabling future rehashing. A pepper, if used,
//! lives in a KMS/HSM — never the DB or repo (R-303).

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::crypto::random_bytes;
use crate::error::AuthError;

/// OWASP-aligned floor (19 MiB, 2 iterations, 1 lane). The operator MUST benchmark on production
/// hardware and raise these so one hash costs ~0.25–0.5 s (R-302, CRYPTOGRAPHY.md); measure with
/// `cargo run --release -p auth-core --example argon2_bench`.
pub const MEMORY_KIB: u32 = 19_456;
pub const ITERATIONS: u32 = 2;
pub const PARALLELISM: u32 = 1;

/// Exposed so a benchmark can measure the exact cost the service uses.
pub fn argon2_params() -> Params {
    Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, None)
        .expect("static Argon2 parameters are valid")
}

/// NIST SP 800-63B-4 policy: length over composition puzzles, no rotation. The 12-char minimum
/// exceeds the SHALL (≥8); blocklist + length carry the strength. The generous maximum supports
/// passphrases and managers.
pub const MIN_PASSWORD_CHARS: usize = 12;
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// A floor, not the ceiling: production layers a real compromised-credential corpus (R-305).
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

/// Case-insensitive blocklist match.
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

pub(crate) fn hasher() -> Argon2<'static> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, None)
        .expect("static Argon2 parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// R-303: Argon2's keyed "secret" as a server-side pepper (KMS/HSM, never the DB), so a
/// database-only compromise cannot offline-crack credentials. The SAME pepper must hash and
/// verify; changing it invalidates all existing hashes.
pub(crate) fn hasher_with_pepper(pepper: &'static [u8]) -> Argon2<'static> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, None)
        .expect("static Argon2 parameters are valid");
    Argon2::new_with_secret(pepper, Algorithm::Argon2id, Version::V0x13, params)
        .expect("pepper length is within Argon2 limits")
}

/// Returns a PHC string (algorithm, version, params, salt).
pub(crate) fn hash_password(argon2: &Argon2<'_>, password: &str) -> Result<String, AuthError> {
    // Salt straight from the OS CSPRNG rather than relying on a specific rand feature wiring.
    let salt_bytes = random_bytes::<16>();
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| AuthError::Internal)?;
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| AuthError::Internal)?;
    Ok(hash.to_string())
}

/// A malformed stored hash is an internal fault — it should never happen for data we wrote.
pub(crate) fn verify_password(
    argon2: &Argon2<'_>,
    password: &str,
    stored_phc: &str,
) -> Result<bool, AuthError> {
    let parsed = PasswordHash::new(stored_phc).map_err(|_| AuthError::Internal)?;
    Ok(argon2.verify_password(password.as_bytes(), &parsed).is_ok())
}

/// Valid hash of a random throwaway password: the not-found branch verifies against it so it does
/// the same Argon2 work as the found branch (enumeration resistance, ABUSE_MODEL.md).
pub(crate) fn make_dummy_hash(argon2: &Argon2<'_>) -> String {
    let throwaway = random_bytes::<32>();
    let salt_bytes = random_bytes::<16>();
    let salt = SaltString::encode_b64(&salt_bytes).expect("valid salt");
    argon2
        .hash_password(&throwaway, &salt)
        .expect("hashing random bytes cannot fail")
        .to_string()
}
