//! Storage seam (ADR-0006). The security logic depends only on these traits; the
//! production backend implements them over PostgreSQL where the database enforces the
//! atomicity these method contracts require. In-memory implementations for tests live in
//! [`crate::memstore`].
//!
//! Each method's doc comment states the atomicity contract the SQL implementation MUST
//! honor. A mismatch there is a critical security bug, not a refactor.

use crate::ids::{AccountId, DeviceId, FamilyId, TxnId};
use crate::transcript::Action;

/// Wall-clock source, injected for testable expiry.
pub trait Clock {
    /// Seconds since the Unix epoch.
    fn now_unix(&self) -> u64;
}

/// A stored account: random internal id, normalized username, Argon2id PHC hash.
#[derive(Clone, Debug)]
pub struct AccountRecord {
    pub account_id: AccountId,
    pub username_normalized: String,
    pub password_phc: String,
}

/// A registered device. The server stores only the **public** key (INV-3); the private key
/// never leaves the Secure Enclave.
#[derive(Clone, Debug)]
pub struct DeviceRecord {
    pub device_id: DeviceId,
    pub account_id: AccountId,
    /// SEC1-encoded P-256 public key.
    pub public_key: Vec<u8>,
    pub revoked: bool,
}

/// A server-issued challenge, bound to account + device + action + expiry, single-use.
#[derive(Clone, Debug)]
pub struct ChallengeRecord {
    pub txn_id: TxnId,
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub action: Action,
    pub nonce: [u8; 32],
    pub expires_at: u64,
}

/// Account + device pair identifying a refresh-token lineage owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountDevice {
    pub account_id: AccountId,
    pub device_id: DeviceId,
}

/// Result of attempting to rotate a refresh token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// The presented token was the family's current token; a new generation was issued.
    Rotated { account: AccountDevice },
    /// The presented token was retired or the family was already revoked — token reuse.
    /// The family is now revoked. Fail closed.
    ReuseDetected,
    /// The token hash is not known.
    Unknown,
}

pub trait CredentialStore {
    /// Create an account. MUST enforce a unique constraint on `username_normalized` and
    /// return `false` if it is already taken (atomic insert-or-reject).
    fn create_account(&self, account: AccountRecord) -> bool;
    fn find_by_username(&self, username_normalized: &str) -> Option<AccountRecord>;
}

pub trait DeviceStore {
    fn create_device(&self, device: DeviceRecord);
    /// The single active (non-revoked) device for an account. v1 is single-active-device
    /// (ADR-0002).
    fn active_device_for_account(&self, account_id: &AccountId) -> Option<DeviceRecord>;
    fn device(&self, device_id: &DeviceId) -> Option<DeviceRecord>;
    /// Mark a device revoked. Future signatures from it MUST fail closed (INV-10).
    fn revoke_device(&self, device_id: &DeviceId);
}

pub trait ChallengeStore {
    /// Persist a challenge.
    fn put(&self, challenge: ChallengeRecord);
    /// **Atomically** consume (remove and return) the challenge for `txn_id`. A second call
    /// for the same `txn_id` MUST return `None`. In SQL: `DELETE ... WHERE txn_id = $1
    /// RETURNING ...`. This single-use property is INV-4 and the whole point of the store.
    fn consume(&self, txn_id: &TxnId) -> Option<ChallengeRecord>;
}

pub trait RefreshStore {
    /// Start a new refresh-token family with `token_hash` as generation 0.
    fn issue(&self, account: AccountDevice, token_hash: [u8; 32], expires_at: u64) -> FamilyId;
    /// Look up the owner of a token hash (current OR retired), used to fetch the device
    /// public key before verifying the refresh signature. Returns `None` if unknown.
    fn owner_of(&self, token_hash: &[u8; 32]) -> Option<AccountDevice>;
    /// **Atomically** rotate: if `old_hash` is the family's current token, install
    /// `new_hash` as the next generation and return `Rotated`. If `old_hash` is retired or
    /// the family is revoked, revoke the family and return `ReuseDetected`. In SQL this is a
    /// compare-and-swap on a generation column inside a transaction.
    fn rotate(
        &self,
        old_hash: &[u8; 32],
        new_hash: [u8; 32],
        new_expires_at: u64,
    ) -> RefreshOutcome;
    /// Revoke the family that owns `token_hash` (logout).
    fn revoke_by_token_hash(&self, token_hash: &[u8; 32]);
    /// Revoke every family belonging to a device (device revocation / INV-10).
    fn revoke_all_for_device(&self, device_id: &DeviceId);
}
