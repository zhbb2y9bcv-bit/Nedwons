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

/// How well protected a device's proof key is (ADR-0008, pinned down by ADR-0017).
///
/// This is **not** a second authentication factor — the device-key signature remains the only
/// credential (ADR-0002). It classifies *custody* of that key, which decides one thing: whether the
/// device may authorize enrollment of ANOTHER device.
///
/// - `Hardware` — the key is non-exportable in a Secure Enclave. It cannot be exfiltrated **or used**
///   off-device without physical possession and user presence.
/// - `Software` — the key cannot be exfiltrated but CAN be used by whatever runs in its context. A
///   web client's non-extractable WebCrypto key is the motivating case: script injected into the
///   origin (XSS) becomes a signing oracle while the page is open. Letting such a device approve
///   enrollments would turn one XSS into account-wide device injection — ADR-0008's "downgrade via
///   software-signer device" threat.
///
/// [`Default`] is `Software` on purpose: **fail closed.** A code path that forgets to classify a
/// device produces the *less* privileged class, never the more privileged one. This mirrors the
/// `DEFAULT 'software'` on the `devices.assurance` column (migration V21).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Assurance {
    Hardware,
    #[default]
    Software,
}

impl Assurance {
    /// The wire/storage spelling. Kept next to the parser so the two can never drift.
    pub fn as_str(self) -> &'static str {
        match self {
            Assurance::Hardware => "hardware",
            Assurance::Software => "software",
        }
    }

    /// **Fail closed:** anything unrecognized — a value written by a newer version, or a corrupted
    /// row — reads back as `Software`, the less privileged class. Never widen this to a fallible
    /// parse that a caller might `unwrap_or(Hardware)`.
    pub fn from_str_or_software(s: &str) -> Self {
        match s {
            "hardware" => Assurance::Hardware,
            _ => Assurance::Software,
        }
    }
}

/// The server stores only the **public** key (INV-3); the private key never leaves the Enclave.
#[derive(Clone, Debug)]
pub struct DeviceRecord {
    pub device_id: DeviceId,
    pub account_id: AccountId,
    /// SEC1-encoded P-256 public key.
    pub public_key: Vec<u8>,
    pub revoked: bool,
    /// Key-custody class; gates enrollment approval only. See [`Assurance`].
    pub assurance: Assurance,
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
    /// Returns `false` at the cap. Used only by the ADR-0008 enrollment ceremony — never a
    /// password-only path.
    ///
    /// Implementations MUST enforce `max_active` atomically **against concurrent callers for the
    /// same account**. A transaction alone does not achieve this at READ COMMITTED — racers would
    /// each read the same pre-insert count and each insert — so a SQL implementation must
    /// serialize on the account (e.g. `SELECT ... FROM accounts ... FOR UPDATE`). The cap is a
    /// server-side invariant; it must never rely on the client serializing its own requests.
    fn add_active_device(&self, device: DeviceRecord, max_active: usize) -> StoreResult<bool>;
    /// Revoked included; ordered deterministically (creation, then id).
    fn list_devices(&self, account_id: &AccountId) -> StoreResult<Vec<DeviceRecord>>;
    /// Reclassify a device's key custody (ADR-0017).
    ///
    /// Devices are always CREATED as [`Assurance::Software`]; this is the only way to reach
    /// `Hardware`, and the caller must have *proof* — today a cryptographically verified Apple App
    /// Attest attestation, which is exactly a proof of "genuine unmodified app on real Apple
    /// hardware". A self-asserted client claim MUST NOT reach this method: assurance is earned, not
    /// declared, or a web client could simply claim `hardware`.
    fn set_assurance(&self, device_id: &DeviceId, assurance: Assurance) -> StoreResult<()>;
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
