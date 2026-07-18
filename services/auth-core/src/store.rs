//! Storage seam (ADR-0006). The security logic depends only on these traits; the
//! production backend implements them over PostgreSQL where the database enforces the
//! atomicity these method contracts require. In-memory implementations for tests live in
//! [`crate::memstore`].
//!
//! Every method returns `Result<_, StoreError>` because real storage can fail, and the
//! service maps any storage failure to a **fail-closed** denial or internal error — never
//! to an implicit success. Each method's doc comment states the atomicity contract the SQL
//! implementation MUST honor. A mismatch there is a critical security bug, not a refactor.

use crate::ids::{AccountId, DeviceId, FamilyId, TxnId};
use crate::transcript::Action;

/// An opaque storage failure. Carries a message for internal logging only; it is never
/// surfaced to API callers (they see a generic error, INV-8).
#[derive(Debug)]
pub struct StoreError(pub String);

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "store error: {}", self.0)
    }
}
impl std::error::Error for StoreError {}

pub type StoreResult<T> = core::result::Result<T, StoreError>;

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

/// Account + device pair identifying a session owner / refresh-token lineage owner.
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
    /// Create the account AND its first device **in one atomic transaction** — either both
    /// exist afterwards or neither does (no orphaned username squatting on partial
    /// failure). MUST enforce a unique constraint on `username_normalized` and return
    /// `Ok(false)` if it is already taken.
    fn create_account_with_device(
        &self,
        account: AccountRecord,
        device: DeviceRecord,
    ) -> StoreResult<bool>;
    fn find_by_username(&self, username_normalized: &str) -> StoreResult<Option<AccountRecord>>;
    /// Store (or replace) the account's recovery-secret Argon2id hash (ADR-0003). Returns `false`
    /// if the account does not exist. The hash is write-only from the client's view — never read
    /// back except by [`recovery_phc`](Self::recovery_phc) for verification.
    fn set_recovery_phc(&self, account_id: &AccountId, phc: &str) -> StoreResult<bool>;
    /// The account's recovery-secret hash, if one is set. `None` if unset or unknown account.
    fn recovery_phc(&self, account_id: &AccountId) -> StoreResult<Option<String>>;
    /// The unix time until which recovery is locked for this account (`None` if not locked or
    /// unknown). Recovery-attempt throttling, R-304.
    fn recovery_locked_until(&self, account_id: &AccountId) -> StoreResult<Option<u64>>;
    /// Record a failed recovery attempt: increment the counter, and if it reaches `max_failures`
    /// lock recovery until `now + lockout_secs` (resetting the counter). Atomic.
    fn bump_recovery_failure(
        &self,
        account_id: &AccountId,
        max_failures: i32,
        lockout_secs: u64,
        now: u64,
    ) -> StoreResult<()>;
    /// Clear the failure counter + lock (on a successful recovery).
    fn clear_recovery_failures(&self, account_id: &AccountId) -> StoreResult<()>;
}

pub trait DeviceStore {
    /// The account's **primary** active device — the deterministic earliest non-revoked device
    /// (by creation, then id). This is the login/bootstrap target. Since ADR-0008 an account may
    /// hold several non-revoked devices (enrolled via the trusted-device ceremony); this returns
    /// exactly one so login and legacy device resolution stay well-defined.
    fn active_device_for_account(
        &self,
        account_id: &AccountId,
    ) -> StoreResult<Option<DeviceRecord>>;
    fn device(&self, device_id: &DeviceId) -> StoreResult<Option<DeviceRecord>>;
    /// Mark a device revoked. Future signatures from it MUST fail closed (INV-10).
    fn revoke_device(&self, device_id: &DeviceId) -> StoreResult<()>;
    /// Atomically add a device IF the account currently has fewer than `max_active` non-revoked
    /// devices. Returns `true` if added, `false` if at the cap (the count + insert are one
    /// transaction so a race cannot exceed the cap). Used only by the trusted-device enrollment
    /// ceremony (ADR-0008) — never a password-only path.
    fn add_active_device(&self, device: DeviceRecord, max_active: usize) -> StoreResult<bool>;
    /// All of the account's devices (revoked included) for the device-management list, ordered
    /// deterministically (creation, then id).
    fn list_devices(&self, account_id: &AccountId) -> StoreResult<Vec<DeviceRecord>>;
}

pub trait ChallengeStore {
    /// Persist a challenge.
    fn put(&self, challenge: ChallengeRecord) -> StoreResult<()>;
    /// **Atomically** consume (remove and return) the challenge for `txn_id`. A second call
    /// for the same `txn_id` MUST return `Ok(None)`, including under concurrent access. In
    /// SQL: `DELETE ... WHERE txn_id = $1 RETURNING ...`. This single-use property is INV-4
    /// and the whole point of the store.
    fn consume(&self, txn_id: &TxnId) -> StoreResult<Option<ChallengeRecord>>;
}

pub trait RefreshStore {
    /// Start a new refresh-token family with `token_hash` as generation 0.
    fn issue(
        &self,
        account: AccountDevice,
        token_hash: [u8; 32],
        expires_at: u64,
    ) -> StoreResult<FamilyId>;
    /// Look up the owner of a token hash (current OR retired), used to fetch the device
    /// public key before verifying the refresh signature. `Ok(None)` if unknown.
    fn owner_of(&self, token_hash: &[u8; 32]) -> StoreResult<Option<AccountDevice>>;
    /// **Atomically** rotate: if `old_hash` is the family's current token, install
    /// `new_hash` as the next generation and return `Rotated`. If `old_hash` is retired or
    /// the family is revoked, revoke the family and return `ReuseDetected`. Under a
    /// concurrent race on the same `old_hash`, **at most one** caller may observe
    /// `Rotated`. In SQL this is a compare-and-swap on a generation column inside a
    /// transaction.
    fn rotate(
        &self,
        old_hash: &[u8; 32],
        new_hash: [u8; 32],
        new_expires_at: u64,
    ) -> StoreResult<RefreshOutcome>;
    /// Revoke the family that owns `token_hash` (logout).
    fn revoke_by_token_hash(&self, token_hash: &[u8; 32]) -> StoreResult<()>;
    /// Revoke every family belonging to a device (device revocation / INV-10).
    fn revoke_all_for_device(&self, device_id: &DeviceId) -> StoreResult<()>;
}

pub trait SessionStore {
    /// Record a short-lived access token (by hash) for later validation.
    fn put_access(
        &self,
        token_hash: [u8; 32],
        account: AccountDevice,
        expires_at: u64,
    ) -> StoreResult<()>;
    /// Owner and expiry for an access-token hash, or `Ok(None)` if unknown/revoked.
    /// Expiry enforcement is the service's job (it owns the clock).
    fn get_access(&self, token_hash: &[u8; 32]) -> StoreResult<Option<(AccountDevice, u64)>>;
    /// Remove all access tokens for a device (logout / device revocation, INV-10).
    fn revoke_access_for_device(&self, device_id: &DeviceId) -> StoreResult<()>;
}
