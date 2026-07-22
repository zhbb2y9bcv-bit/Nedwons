//! Storage seam (ADR-0006). The service maps any storage failure to a fail-closed denial or
//! internal error — never an implicit success. Each method's doc states the atomicity contract the
//! SQL implementation MUST honor; a mismatch there is a critical security bug, not a refactor.
//! Test implementations live in [`crate::memstore`].

use crate::ids::{AccountId, DeviceId, FamilyId, TxnId};
use crate::transcript::Action;

/// The message is for internal logging only; API callers see a generic error (INV-8).
#[derive(Debug)]
pub struct StoreError(pub String);

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "store error: {}", self.0)
    }
}
impl std::error::Error for StoreError {}

pub type StoreResult<T> = core::result::Result<T, StoreError>;

/// Injected for testable expiry.
pub trait Clock {
    /// Seconds since the Unix epoch.
    fn now_unix(&self) -> u64;
}

#[derive(Clone, Debug)]
pub struct AccountRecord {
    pub account_id: AccountId,
    pub username_normalized: String,
    pub password_phc: String,
}

/// The server stores only the **public** key (INV-3); the private key never leaves the Enclave.
#[derive(Clone, Debug)]
pub struct DeviceRecord {
    pub device_id: DeviceId,
    pub account_id: AccountId,
    /// SEC1-encoded P-256 public key.
    pub public_key: Vec<u8>,
    pub revoked: bool,
}

/// Bound to account + device + action + expiry; single-use.
#[derive(Clone, Debug)]
pub struct ChallengeRecord {
    pub txn_id: TxnId,
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub action: Action,
    pub nonce: [u8; 32],
    pub expires_at: u64,
}

/// Identifies a session / refresh-family owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountDevice {
    pub account_id: AccountId,
    pub device_id: DeviceId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// The token was current; a new generation was issued.
    Rotated {
        account: AccountDevice,
    },
    /// The token was retired or the family already revoked — reuse. The family is now revoked.
    ReuseDetected,
    Unknown,
}

pub trait CredentialStore {
    /// **One atomic transaction** — both exist afterwards or neither (no orphaned username
    /// squatting). MUST enforce unique `username_normalized`, returning `Ok(false)` if taken.
    fn create_account_with_device(
        &self,
        account: AccountRecord,
        device: DeviceRecord,
    ) -> StoreResult<bool>;
    fn find_by_username(&self, username_normalized: &str) -> StoreResult<Option<AccountRecord>>;
    fn find_by_account_id(&self, account_id: &AccountId) -> StoreResult<Option<AccountRecord>>;
    /// Returns `false` if the account does not exist.
    fn update_password_phc(&self, account_id: &AccountId, phc: &str) -> StoreResult<bool>;
    /// Recovery-secret Argon2id hash (ADR-0003). Write-only from the client's view — read back only
    /// by [`recovery_phc`](Self::recovery_phc) for verification. `false` if no such account.
    fn set_recovery_phc(&self, account_id: &AccountId, phc: &str) -> StoreResult<bool>;
    fn recovery_phc(&self, account_id: &AccountId) -> StoreResult<Option<String>>;
    /// R-304 throttling: unix time recovery is locked until (`None` if not locked/unknown).
    fn recovery_locked_until(&self, account_id: &AccountId) -> StoreResult<Option<u64>>;
    /// Atomic: increment the counter; at `max_failures`, lock until `now + lockout_secs` and reset.
    fn bump_recovery_failure(
        &self,
        account_id: &AccountId,
        max_failures: i32,
        lockout_secs: u64,
        now: u64,
    ) -> StoreResult<()>;
    fn clear_recovery_failures(&self, account_id: &AccountId) -> StoreResult<()>;
}

pub trait DeviceStore {
    /// The **primary** active device: deterministic earliest non-revoked (creation, then id).
    /// ADR-0008 allows several non-revoked devices; returning exactly one keeps login and legacy
    /// device resolution well-defined.
    fn active_device_for_account(
        &self,
        account_id: &AccountId,
    ) -> StoreResult<Option<DeviceRecord>>;
    fn device(&self, device_id: &DeviceId) -> StoreResult<Option<DeviceRecord>>;
    /// Future signatures from it MUST fail closed (INV-10).
    fn revoke_device(&self, device_id: &DeviceId) -> StoreResult<()>;
    /// Count + insert are one transaction, so a race cannot exceed `max_active` (`false` at the
    /// cap). Used only by the ADR-0008 enrollment ceremony — never a password-only path.
    fn add_active_device(&self, device: DeviceRecord, max_active: usize) -> StoreResult<bool>;
    /// Revoked included; ordered deterministically (creation, then id).
    fn list_devices(&self, account_id: &AccountId) -> StoreResult<Vec<DeviceRecord>>;
}

pub trait ChallengeStore {
    fn put(&self, challenge: ChallengeRecord) -> StoreResult<()>;
    /// **Atomically** remove and return. A second call for the same `txn_id` MUST return
    /// `Ok(None)`, including under concurrency (SQL: `DELETE ... RETURNING`). Single-use is INV-4
    /// and the whole point of the store.
    fn consume(&self, txn_id: &TxnId) -> StoreResult<Option<ChallengeRecord>>;
}

pub trait RefreshStore {
    /// New family with `token_hash` as generation 0.
    fn issue(
        &self,
        account: AccountDevice,
        token_hash: [u8; 32],
        expires_at: u64,
    ) -> StoreResult<FamilyId>;
    /// Owner of a current OR retired hash — used to fetch the device key before verifying the
    /// refresh signature.
    fn owner_of(&self, token_hash: &[u8; 32]) -> StoreResult<Option<AccountDevice>>;
    /// **Atomic CAS on the generation**: if `old_hash` is current, install `new_hash` →
    /// `Rotated`; if retired or the family is revoked, revoke the family → `ReuseDetected`.
    /// Under a race on the same `old_hash`, **at most one** caller may observe `Rotated`.
    fn rotate(
        &self,
        old_hash: &[u8; 32],
        new_hash: [u8; 32],
        new_expires_at: u64,
    ) -> StoreResult<RefreshOutcome>;
    /// Logout.
    fn revoke_by_token_hash(&self, token_hash: &[u8; 32]) -> StoreResult<()>;
    /// Device revocation (INV-10).
    fn revoke_all_for_device(&self, device_id: &DeviceId) -> StoreResult<()>;
}

pub trait SessionStore {
    fn put_access(
        &self,
        token_hash: [u8; 32],
        account: AccountDevice,
        expires_at: u64,
    ) -> StoreResult<()>;
    /// Expiry enforcement is the service's job (it owns the clock).
    fn get_access(&self, token_hash: &[u8; 32]) -> StoreResult<Option<(AccountDevice, u64)>>;
    /// Logout / device revocation (INV-10).
    fn revoke_access_for_device(&self, device_id: &DeviceId) -> StoreResult<()>;
}
