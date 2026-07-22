//! Pure, storage-agnostic security logic for device-bound authentication (ADR-0002, ADR-0006).
//!
//! Deliberately no networking, database, or framework — only the security-critical decisions, so
//! they can be unit-tested in isolation. The backend supplies PostgreSQL [`store`] implementations
//! where the database enforces the atomicity these contracts require.
//!
//! The headline property, proven by `tests/invariants.rs`:
//!
//! > A valid username and password, presented from a device that does not hold the account's
//! > enrolled private device key, cannot create or refresh a session.
//!
//! No custom cryptography: [`crypto`] and [`password`] are thin adapters over `p256`, `sha2`,
//! and `argon2`.

#![forbid(unsafe_code)]

pub mod breach;
pub mod crypto;
pub mod delivery_key;
pub mod error;
pub mod ids;
pub mod membership;
pub mod memstore;
pub mod password;
pub mod request_proof;
pub mod sender_cert;
pub mod service;
pub mod store;
pub mod transcript;
pub mod transparency;

pub use error::{AuthError, Result};
pub use ids::{AccountId, DeviceId, FamilyId, TxnId};
pub use service::{
    normalize_username, refresh_txn_id, AuthService, Config, EnrollChallenge, EnrollRequest,
    LoginChallenge, RecoveryChallenge, RecoveryRequest, RegisterRequest, RegistrationChallenge,
    Session,
};
pub use transcript::{Action, Transcript, DOMAIN, PROTOCOL_VERSION};
