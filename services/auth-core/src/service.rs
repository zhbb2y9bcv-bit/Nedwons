//! The device-bound authentication service (ADR-0002). Orchestrates registration, the
//! two-stage login, device-signed refresh, access-token validation, logout, and revocation
//! over the storage seam.
//!
//! Security posture, enforced below and by tests:
//!  * Username + password alone never create a session (INV-2).
//!  * Every challenge is single-use, expiring, and account/device/action-bound (INV-4).
//!  * All security failures return the generic [`AuthError::Denied`] (fail closed).
//!  * Storage failures never become implicit successes: `StoreError` maps to
//!    [`AuthError::Internal`] (or `Denied` where the safe direction is denial).

use std::sync::Arc;

use argon2::Argon2;

use crate::crypto::{random_bytes, sha256, verify_p256};
use crate::error::{AuthError, Result};
use crate::ids::{AccountId, DeviceId, TxnId};
use crate::password;
use crate::store::{
    AccountDevice, AccountRecord, ChallengeRecord, ChallengeStore, Clock, CredentialStore,
    DeviceRecord, DeviceStore, RefreshOutcome, RefreshStore, SessionStore, StoreError,
};
use crate::transcript::{Action, Transcript};

impl From<StoreError> for AuthError {
    fn from(_: StoreError) -> Self {
        // The message is for source-side logging only; callers get a generic error.
        AuthError::Internal
    }
}

/// Tunable lifetimes. Defaults are conservative starting values.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub challenge_ttl_secs: u64,
    pub access_ttl_secs: u64,
    pub refresh_ttl_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            challenge_ttl_secs: 120,
            access_ttl_secs: 15 * 60,
            refresh_ttl_secs: 30 * 24 * 60 * 60,
        }
    }
}

/// Challenge returned by [`AuthService::register_begin`]. The client signs a `Register`
/// transcript built from these fields plus its new device public key.
#[derive(Clone, Debug)]
pub struct RegistrationChallenge {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub txn_id: TxnId,
    pub nonce: [u8; 32],
    pub expires_at: u64,
}

/// Enrollment payload for [`AuthService::register_finish`].
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    /// SEC1-encoded P-256 public key generated in the device's Secure Enclave.
    pub device_public_key: Vec<u8>,
    pub txn_id: TxnId,
    /// Signature over the `Register` transcript by the device private key.
    pub signature: Vec<u8>,
}

/// Challenge returned by [`AuthService::recover_begin`] — enumeration-resistant (always returned).
/// Carries the reserved NEW device id the recovering device will self-sign for.
pub struct RecoveryChallenge {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub txn_id: TxnId,
    pub nonce: [u8; 32],
    pub expires_at: u64,
}

/// Payload for [`AuthService::recover_finish`]. The `recovery_secret` authorizes (something you
/// know); the `new_device_signature` proves possession of the new device key (self-signed).
pub struct RecoveryRequest {
    pub username: String,
    pub recovery_secret: String,
    pub txn_id: TxnId,
    /// SEC1-encoded P-256 public key of the NEW device.
    pub new_device_public_key: Vec<u8>,
    /// The NEW device's signature over the `DeviceEnroll` transcript (proof of possession).
    pub new_device_signature: Vec<u8>,
}

/// Challenge returned by [`AuthService::enroll_device_begin`] — the reserved id + nonce for the
/// NEW device, which the trusted device signs to authorize (ADR-0008).
pub struct EnrollChallenge {
    /// The reserved id for the new device.
    pub device_id: DeviceId,
    pub txn_id: TxnId,
    pub nonce: [u8; 32],
    pub expires_at: u64,
}

/// Payload for [`AuthService::enroll_device_finish`]. The signature is by the **trusted**
/// (already-enrolled) device over the `DeviceEnroll` transcript binding the account + the NEW
/// device's reserved id + its public key; the new device's private key never appears.
pub struct EnrollRequest {
    pub txn_id: TxnId,
    /// SEC1-encoded P-256 public key of the NEW device.
    pub device_public_key: Vec<u8>,
    /// The trusted device's signature over the `DeviceEnroll` transcript.
    pub signature: Vec<u8>,
}

/// Challenge returned by [`AuthService::login_begin`]. Always returned (even on bad
/// credentials, as an unstored decoy) so the begin step does not reveal account existence.
#[derive(Clone, Debug)]
pub struct LoginChallenge {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub txn_id: TxnId,
    pub nonce: [u8; 32],
    pub expires_at: u64,
}

/// A proof-of-possession session. Tokens are raw bytes here; transport encoding (base64,
/// headers) is an API-layer concern. No `Debug` is derived — tokens must not land in logs
/// (INV-8).
pub struct Session {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub access_token: Vec<u8>,
    pub access_expires_at: u64,
    pub refresh_token: Vec<u8>,
    pub refresh_expires_at: u64,
}

/// Shared, thread-safe handles to the storage seam.
pub struct AuthService {
    creds: Arc<dyn CredentialStore + Send + Sync>,
    devices: Arc<dyn DeviceStore + Send + Sync>,
    challenges: Arc<dyn ChallengeStore + Send + Sync>,
    refresh: Arc<dyn RefreshStore + Send + Sync>,
    sessions: Arc<dyn SessionStore + Send + Sync>,
    clock: Arc<dyn Clock + Send + Sync>,
    config: Config,
    argon2: Argon2<'static>,
    /// Valid Argon2 hash of a throwaway secret, verified against on the account-not-found
    /// path to equalize timing (enumeration resistance).
    dummy_hash: String,
    /// Optional compromised-credential corpus (R-305). When set, a breached password is rejected
    /// at registration. `None` (default) keeps only the length + embedded-blocklist policy.
    breach: Option<Arc<dyn crate::breach::RangeProvider + Send + Sync>>,
}

impl AuthService {
    pub fn new(
        creds: Arc<dyn CredentialStore + Send + Sync>,
        devices: Arc<dyn DeviceStore + Send + Sync>,
        challenges: Arc<dyn ChallengeStore + Send + Sync>,
        refresh: Arc<dyn RefreshStore + Send + Sync>,
        sessions: Arc<dyn SessionStore + Send + Sync>,
        clock: Arc<dyn Clock + Send + Sync>,
        config: Config,
    ) -> Self {
        let argon2 = password::hasher();
        let dummy_hash = password::make_dummy_hash(&argon2);
        Self {
            creds,
            devices,
            challenges,
            refresh,
            sessions,
            clock,
            config,
            argon2,
            dummy_hash,
            breach: None,
        }
    }

    /// Attach a compromised-credential corpus (R-305). Registration will reject a password whose
    /// SHA-1 is in the corpus. Builder-style so existing construction is unchanged.
    pub fn with_breach_provider(
        mut self,
        provider: Arc<dyn crate::breach::RangeProvider + Send + Sync>,
    ) -> Self {
        self.breach = Some(provider);
        self
    }

    /// Mix a server-side **pepper** into all password + recovery-secret hashing (R-303). The
    /// pepper is a KMS/HSM deployment secret held only in process memory (`'static`), so a
    /// database-only compromise cannot offline-crack credentials. Rebuilds the timing-dummy hash
    /// under the same pepper so enumeration resistance is preserved. Builder-style; existing
    /// construction (no pepper) is unchanged. NOTE: enabling/changing the pepper invalidates all
    /// prior hashes — set it before any users exist.
    pub fn with_pepper(mut self, pepper: &'static [u8]) -> Self {
        self.argon2 = password::hasher_with_pepper(pepper);
        self.dummy_hash = password::make_dummy_hash(&self.argon2);
        self
    }

    // ----- Registration -------------------------------------------------------------

    /// Stage 1 of enrollment: reserve ids and issue a single-use `Register` challenge.
    pub fn register_begin(&self) -> Result<RegistrationChallenge> {
        let account_id = AccountId::random();
        let device_id = DeviceId::random();
        let txn_id = TxnId::random();
        let nonce = random_bytes::<32>();
        let expires_at = self.clock.now_unix() + self.config.challenge_ttl_secs;
        self.challenges.put(ChallengeRecord {
            txn_id,
            account_id,
            device_id,
            action: Action::Register,
            nonce,
            expires_at,
        })?;
        Ok(RegistrationChallenge {
            account_id,
            device_id,
            txn_id,
            nonce,
            expires_at,
        })
    }

    /// Stage 2 of enrollment: verify the device holds the private key for its asserted
    /// public key (proof of possession), then create the account and device atomically.
    pub fn register_finish(&self, req: RegisterRequest) -> Result<Session> {
        let challenge = self
            .challenges
            .consume(&req.txn_id)?
            .ok_or(AuthError::Denied)?;
        self.check_challenge(&challenge, Action::Register)?;

        // The signature must cover the reserved ids AND the presented public key, so the
        // key cannot be swapped after the fact.
        let transcript = Transcript {
            action: Action::Register,
            account_id: &challenge.account_id,
            device_id: &challenge.device_id,
            public_key: &req.device_public_key,
            challenge: &challenge.nonce,
            expires_at: challenge.expires_at,
            txn_id: &req.txn_id,
        };
        if !verify_p256(&req.device_public_key, &transcript.encode(), &req.signature) {
            return Err(AuthError::Denied);
        }

        // Username/password validation are client-correctable request errors, distinct
        // from Denied.
        let username = normalize_username(&req.username)?;
        password::validate_password_policy(&req.password)?;
        // Compromised-credential check (R-305). Fail OPEN on a provider error (an outage must not
        // block registration); reject only on a confirmed corpus hit.
        if let Some(provider) = &self.breach {
            if crate::breach::is_compromised(provider.as_ref(), &req.password).unwrap_or(false) {
                return Err(AuthError::WeakPassword);
            }
        }
        let password_phc = password::hash_password(&self.argon2, &req.password)?;

        let created = self.creds.create_account_with_device(
            AccountRecord {
                account_id: challenge.account_id,
                username_normalized: username,
                password_phc,
            },
            DeviceRecord {
                device_id: challenge.device_id,
                account_id: challenge.account_id,
                public_key: req.device_public_key,
                revoked: false,
            },
        )?;
        if !created {
            return Err(AuthError::UsernameUnavailable);
        }

        self.mint_session_new_family(AccountDevice {
            account_id: challenge.account_id,
            device_id: challenge.device_id,
        })
    }

    // ----- Password change (device-bound) -------------------------------------------

    /// Stage 1 of a password change: issue a single-use `PasswordChange` challenge bound to the
    /// authenticated account+device, which the device signs to prove possession of its key.
    pub fn password_change_begin(&self, account: &AccountDevice) -> Result<RegistrationChallenge> {
        let txn_id = TxnId::random();
        let nonce = random_bytes::<32>();
        let expires_at = self.clock.now_unix() + self.config.challenge_ttl_secs;
        self.challenges.put(ChallengeRecord {
            txn_id,
            account_id: account.account_id,
            device_id: account.device_id,
            action: Action::PasswordChange,
            nonce,
            expires_at,
        })?;
        Ok(RegistrationChallenge {
            account_id: account.account_id,
            device_id: account.device_id,
            txn_id,
            nonce,
            expires_at,
        })
    }

    /// Stage 2: verify the device signature (proof of possession) AND the current password, then
    /// validate + hash the new password and replace it. Requires BOTH factors — a stolen access
    /// token alone (no device key, no current password) cannot change the password. Existing
    /// device-bound sessions continue (they are not password-derived); the new password only
    /// governs future logins.
    pub fn password_change_finish(
        &self,
        account: &AccountDevice,
        txn_id: &TxnId,
        signature: &[u8],
        current_password: &str,
        new_password: &str,
    ) -> Result<()> {
        let challenge = self.challenges.consume(txn_id)?.ok_or(AuthError::Denied)?;
        self.check_challenge(&challenge, Action::PasswordChange)?;
        if challenge.account_id != account.account_id || challenge.device_id != account.device_id {
            return Err(AuthError::Denied);
        }
        // Device proof of possession over the PasswordChange transcript, under the device's key.
        let device = self
            .devices
            .device(&account.device_id)?
            .filter(|d| !d.revoked && d.account_id == account.account_id)
            .ok_or(AuthError::Denied)?;
        let transcript = Transcript {
            action: Action::PasswordChange,
            account_id: &challenge.account_id,
            device_id: &challenge.device_id,
            public_key: &device.public_key,
            challenge: &challenge.nonce,
            expires_at: challenge.expires_at,
            txn_id,
        };
        if !verify_p256(&device.public_key, &transcript.encode(), signature) {
            return Err(AuthError::Denied);
        }

        // Verify the CURRENT password (second factor).
        let acct = self
            .creds
            .find_by_account_id(&account.account_id)?
            .ok_or(AuthError::Denied)?;
        if !password::verify_password(&self.argon2, current_password, &acct.password_phc)
            .unwrap_or(false)
        {
            return Err(AuthError::Denied);
        }

        // Validate + (breach-)check the NEW password, then rehash and store.
        password::validate_password_policy(new_password)?;
        if let Some(provider) = &self.breach {
            if crate::breach::is_compromised(provider.as_ref(), new_password).unwrap_or(false) {
                return Err(AuthError::WeakPassword);
            }
        }
        let new_phc = password::hash_password(&self.argon2, new_password)?;
        if !self
            .creds
            .update_password_phc(&account.account_id, &new_phc)?
        {
            return Err(AuthError::Denied);
        }
        Ok(())
    }

    // ----- Trusted-device enrollment (ADR-0008) -------------------------------------

    /// Maximum non-revoked devices per account. A generous cap that bounds abuse (a compromised
    /// trusted device cannot enroll unbounded ghost devices) without constraining real use.
    pub const MAX_ACTIVE_DEVICES: usize = 8;

    /// Stage 1 of trusted-device enrollment: an already-enrolled (trusted) device reserves ids and
    /// a nonce for a NEW device and issues a single-use `DeviceEnroll` challenge bound to the
    /// account. Only a non-revoked device may authorize enrollment (never a password-only path).
    pub fn enroll_device_begin(&self, trusted: &AccountDevice) -> Result<EnrollChallenge> {
        // The authorizing device must currently be active.
        self.devices
            .device(&trusted.device_id)?
            .filter(|d| !d.revoked && d.account_id == trusted.account_id)
            .ok_or(AuthError::Denied)?;

        let device_id = DeviceId::random();
        let txn_id = TxnId::random();
        let nonce = random_bytes::<32>();
        let expires_at = self.clock.now_unix() + self.config.challenge_ttl_secs;
        self.challenges.put(ChallengeRecord {
            txn_id,
            account_id: trusted.account_id,
            device_id,
            action: Action::DeviceEnroll,
            nonce,
            expires_at,
        })?;
        Ok(EnrollChallenge {
            device_id,
            txn_id,
            nonce,
            expires_at,
        })
    }

    /// Stage 2 of trusted-device enrollment: verify the **trusted** device signed the
    /// `DeviceEnroll` transcript authorizing the new device's public key, add the new device
    /// (subject to [`MAX_ACTIVE_DEVICES`]), and provision it a session. The new device's private
    /// key is never involved — the trusted device's authorization is the credential (a stolen
    /// username/password can never enroll a device, R-903).
    pub fn enroll_device_finish(
        &self,
        trusted: &AccountDevice,
        req: EnrollRequest,
    ) -> Result<Session> {
        let challenge = self
            .challenges
            .consume(&req.txn_id)?
            .ok_or(AuthError::Denied)?;
        self.check_challenge(&challenge, Action::DeviceEnroll)?;
        // The challenge must belong to the trusted device's own account.
        if challenge.account_id != trusted.account_id {
            return Err(AuthError::Denied);
        }

        // The trusted device signs a transcript binding the account + the NEW device's reserved id
        // + its presented public key, so the server cannot be tricked into enrolling a different
        // key than the trusted device approved.
        let transcript = Transcript {
            action: Action::DeviceEnroll,
            account_id: &challenge.account_id,
            device_id: &challenge.device_id,
            public_key: &req.device_public_key,
            challenge: &challenge.nonce,
            expires_at: challenge.expires_at,
            txn_id: &req.txn_id,
        };
        let trusted_key = self
            .devices
            .device(&trusted.device_id)?
            .filter(|d| !d.revoked && d.account_id == trusted.account_id)
            .ok_or(AuthError::Denied)?
            .public_key;
        if !verify_p256(&trusted_key, &transcript.encode(), &req.signature) {
            return Err(AuthError::Denied);
        }

        let added = self.devices.add_active_device(
            DeviceRecord {
                device_id: challenge.device_id,
                account_id: challenge.account_id,
                public_key: req.device_public_key,
                revoked: false,
            },
            Self::MAX_ACTIVE_DEVICES,
        )?;
        if !added {
            // At the device cap (or an id clash) — a generic denial, no oracle.
            return Err(AuthError::Denied);
        }

        // Provision the new device a session (its own refresh family), relayed to it over the
        // pairing channel. It never needs the password.
        self.mint_session_new_family(AccountDevice {
            account_id: challenge.account_id,
            device_id: challenge.device_id,
        })
    }

    /// The account's devices (for the management list). Public keys included; nothing secret.
    pub fn list_devices(&self, account_id: &AccountId) -> Result<Vec<DeviceRecord>> {
        Ok(self.devices.list_devices(account_id)?)
    }

    // ----- Account recovery (ADR-0003, R-304) ---------------------------------------

    /// Minimum length of a recovery secret. Recovery secrets are **generated** high-entropy codes
    /// (not user-chosen), so this is a sanity floor, not a strength policy.
    pub const MIN_RECOVERY_SECRET_CHARS: usize = 20;

    /// Failed recovery attempts before recovery is locked (R-304 throttling).
    pub const MAX_RECOVERY_FAILURES: i32 = 5;
    /// How long recovery stays locked after hitting the failure ceiling.
    pub const RECOVERY_LOCKOUT_SECS: u64 = 15 * 60;

    /// Set (or replace) the account's recovery secret, stored only as an Argon2id hash. Called by
    /// an authenticated device (the caller must already hold an active device — recovery is set up
    /// while you still have access). A too-short secret is a client-correctable `WeakPassword`.
    pub fn set_recovery_secret(&self, account: &AccountDevice, secret: &str) -> Result<()> {
        // The caller's device must be active (defense in depth; the API also authenticates it).
        self.devices
            .device(&account.device_id)?
            .filter(|d| !d.revoked && d.account_id == account.account_id)
            .ok_or(AuthError::Denied)?;
        if secret.chars().count() < Self::MIN_RECOVERY_SECRET_CHARS {
            return Err(AuthError::WeakPassword);
        }
        let phc = password::hash_password(&self.argon2, secret)?;
        if !self.creds.set_recovery_phc(&account.account_id, &phc)? {
            return Err(AuthError::Denied);
        }
        Ok(())
    }

    /// Stage 1 of recovery: reserve a NEW device id + nonce for the recovering device to self-sign.
    /// Enumeration-resistant — a real (stored) challenge only when the username exists; otherwise
    /// an unstored decoy with random ids, so the response does not reveal account existence.
    pub fn recover_begin(&self, username: &str) -> RecoveryChallenge {
        let account = normalize_username(username)
            .ok()
            .and_then(|u| self.creds.find_by_username(&u).ok().flatten());
        let device_id = DeviceId::random();
        let txn_id = TxnId::random();
        let nonce = random_bytes::<32>();
        let expires_at = self.clock.now_unix() + self.config.challenge_ttl_secs;
        match account {
            Some(acct) => {
                // Store a real challenge only when a recovery secret is actually set.
                if matches!(self.creds.recovery_phc(&acct.account_id), Ok(Some(_))) {
                    let _ = self.challenges.put(ChallengeRecord {
                        txn_id,
                        account_id: acct.account_id,
                        device_id,
                        action: Action::DeviceEnroll,
                        nonce,
                        expires_at,
                    });
                }
                RecoveryChallenge {
                    account_id: acct.account_id,
                    device_id,
                    txn_id,
                    nonce,
                    expires_at,
                }
            }
            None => RecoveryChallenge {
                account_id: AccountId::random(),
                device_id,
                txn_id,
                nonce,
                expires_at,
            },
        }
    }

    /// Stage 2 of recovery: verify the recovery secret AND the new device's proof-of-possession,
    /// then enroll the new device and provision it a session. Recovery restores **account access**,
    /// not E2EE message history: the new device has a fresh MLS identity and is re-added to
    /// conversations by other members via MLS commits (ADR-0009); no history is silently restored.
    pub fn recover_finish(&self, req: RecoveryRequest) -> Result<Session> {
        // Burn the single-use challenge regardless of outcome.
        let challenge = self.challenges.consume(&req.txn_id)?;
        let account = normalize_username(&req.username)
            .ok()
            .and_then(|u| self.creds.find_by_username(&u).ok().flatten());

        // Always run exactly one Argon2 verification (real or dummy) so timing does not reveal
        // whether the account exists or has a recovery secret.
        let phc = account
            .as_ref()
            .and_then(|a| self.creds.recovery_phc(&a.account_id).ok().flatten());
        let secret_ok = match &phc {
            Some(h) => {
                password::verify_password(&self.argon2, &req.recovery_secret, h).unwrap_or(false)
            }
            None => {
                let _ =
                    password::verify_password(&self.argon2, &req.recovery_secret, &self.dummy_hash);
                false
            }
        };

        // Recovery-attempt throttling (R-304): if the account is currently locked out, refuse —
        // and if the secret was wrong, record the failure (locking after too many). A locked
        // account cannot be probed even with the right secret until the cooldown elapses.
        if let Some(acct) = &account {
            let locked = self
                .creds
                .recovery_locked_until(&acct.account_id)?
                .is_some_and(|until| until > self.clock.now_unix());
            if locked {
                return Err(AuthError::Denied);
            }
            if !secret_ok {
                self.creds.bump_recovery_failure(
                    &acct.account_id,
                    Self::MAX_RECOVERY_FAILURES,
                    Self::RECOVERY_LOCKOUT_SECS,
                    self.clock.now_unix(),
                )?;
            }
        }

        let (challenge, account) = match (challenge, account) {
            (Some(c), Some(a)) if c.account_id == a.account_id && secret_ok => (c, a),
            _ => return Err(AuthError::Denied),
        };
        self.check_challenge(&challenge, Action::DeviceEnroll)?;
        // Success: clear any recovery-failure state.
        self.creds.clear_recovery_failures(&account.account_id)?;

        // The recovering device proves possession of its key (self-signed, like registration).
        let transcript = Transcript {
            action: Action::DeviceEnroll,
            account_id: &account.account_id,
            device_id: &challenge.device_id,
            public_key: &req.new_device_public_key,
            challenge: &challenge.nonce,
            expires_at: challenge.expires_at,
            txn_id: &req.txn_id,
        };
        if !verify_p256(
            &req.new_device_public_key,
            &transcript.encode(),
            &req.new_device_signature,
        ) {
            return Err(AuthError::Denied);
        }

        let added = self.devices.add_active_device(
            DeviceRecord {
                device_id: challenge.device_id,
                account_id: account.account_id,
                public_key: req.new_device_public_key,
                revoked: false,
            },
            Self::MAX_ACTIVE_DEVICES,
        )?;
        if !added {
            return Err(AuthError::Denied);
        }
        self.mint_session_new_family(AccountDevice {
            account_id: account.account_id,
            device_id: challenge.device_id,
        })
    }

    /// Revoke a device **only if it belongs to `account_id`** (device management, ADR-0008).
    /// Returns `false` if the device is not the caller's (or does not exist) — one account can
    /// never revoke another's device. On success the revocation cascades (tokens + families) via
    /// [`revoke_device`](Self::revoke_device).
    pub fn revoke_own_device(&self, account_id: &AccountId, device_id: &DeviceId) -> Result<bool> {
        let owned = self
            .devices
            .device(device_id)?
            .map(|d| d.account_id == *account_id)
            .unwrap_or(false);
        if !owned {
            return Ok(false);
        }
        self.revoke_device(device_id)?;
        Ok(true)
    }

    // ----- Login (two-stage) --------------------------------------------------------

    /// Stage 1 of login. Verifies credentials with enumeration-resistant timing and always
    /// returns a challenge. A real (stored) challenge is issued only when the credentials
    /// are valid AND the account has an active device; otherwise an unstored decoy of
    /// identical shape is returned so the response reveals nothing. Storage errors surface
    /// as a decoy too — the caller cannot distinguish an outage from a bad credential.
    pub fn login_begin(&self, username: &str, password: &str) -> LoginChallenge {
        let account = normalize_username(username)
            .ok()
            .and_then(|u| self.creds.find_by_username(&u).ok().flatten());

        // Always run one Argon2 verification (real hash if found, dummy if not) so timing
        // does not distinguish existence.
        let credentials_ok = match &account {
            Some(acct) => password::verify_password(&self.argon2, password, &acct.password_phc)
                .unwrap_or(false),
            None => {
                let _ = password::verify_password(&self.argon2, password, &self.dummy_hash);
                false
            }
        };

        if credentials_ok {
            if let Some(acct) = account {
                if let Ok(Some(device)) = self.devices.active_device_for_account(&acct.account_id) {
                    let txn_id = TxnId::random();
                    let nonce = random_bytes::<32>();
                    let expires_at = self.clock.now_unix() + self.config.challenge_ttl_secs;
                    let stored = self.challenges.put(ChallengeRecord {
                        txn_id,
                        account_id: acct.account_id,
                        device_id: device.device_id,
                        action: Action::Login,
                        nonce,
                        expires_at,
                    });
                    if stored.is_ok() {
                        return LoginChallenge {
                            account_id: acct.account_id,
                            device_id: device.device_id,
                            txn_id,
                            nonce,
                            expires_at,
                        };
                    }
                }
            }
        }
        self.decoy_login_challenge()
    }

    /// Stage 2 of login. Succeeds only if the presented signature verifies against the
    /// enrolled device's public key over the bound challenge. A decoy `txn_id` (or any
    /// replay/expiry/mismatch) consumes to nothing and fails closed.
    pub fn login_finish(&self, txn_id: &TxnId, signature: &[u8]) -> Result<Session> {
        let challenge = self.challenges.consume(txn_id)?.ok_or(AuthError::Denied)?;
        self.check_challenge(&challenge, Action::Login)?;

        let device = self
            .devices
            .device(&challenge.device_id)?
            .filter(|d| !d.revoked)
            .ok_or(AuthError::Denied)?;

        let transcript = Transcript {
            action: Action::Login,
            account_id: &challenge.account_id,
            device_id: &challenge.device_id,
            public_key: &device.public_key,
            challenge: &challenge.nonce,
            expires_at: challenge.expires_at,
            txn_id,
        };
        if !verify_p256(&device.public_key, &transcript.encode(), signature) {
            return Err(AuthError::Denied);
        }

        self.mint_session_new_family(AccountDevice {
            account_id: challenge.account_id,
            device_id: challenge.device_id,
        })
    }

    // ----- Sessions: refresh / validate / logout / revocation ------------------------

    /// Rotate a refresh token. Requires BOTH the (unpredictable, rotating) refresh token
    /// and a device-key signature over a `Refresh` transcript, so a copied bearer token is
    /// insufficient (INV-2 for refresh). Verification happens before rotation so a
    /// signature-less thief cannot trigger a family revocation (DoS) against the victim.
    pub fn refresh(&self, refresh_token: &[u8], signature: &[u8]) -> Result<Session> {
        let now = self.clock.now_unix();
        let old_hash = sha256(refresh_token);

        let owner = self.refresh.owner_of(&old_hash)?.ok_or(AuthError::Denied)?;
        let device = self
            .devices
            .device(&owner.device_id)?
            .filter(|d| !d.revoked)
            .ok_or(AuthError::Denied)?;

        let txn_id = refresh_txn_id(&old_hash);
        let transcript = Transcript {
            action: Action::Refresh,
            account_id: &owner.account_id,
            device_id: &owner.device_id,
            public_key: &device.public_key,
            challenge: &old_hash, // the rotating token's hash is the anti-replay nonce
            expires_at: 0,
            txn_id: &txn_id,
        };
        if !verify_p256(&device.public_key, &transcript.encode(), signature) {
            return Err(AuthError::Denied);
        }

        let new_token = random_bytes::<32>();
        let new_hash = sha256(&new_token);
        let new_expires = now + self.config.refresh_ttl_secs;
        match self.refresh.rotate(&old_hash, new_hash, new_expires)? {
            RefreshOutcome::Rotated { account } => {
                let access_token = random_bytes::<32>();
                let access_expires_at = now + self.config.access_ttl_secs;
                self.sessions
                    .put_access(sha256(&access_token), account, access_expires_at)?;
                Ok(Session {
                    account_id: account.account_id,
                    device_id: account.device_id,
                    access_token: access_token.to_vec(),
                    access_expires_at,
                    refresh_token: new_token.to_vec(),
                    refresh_expires_at: new_expires,
                })
            }
            // Reuse or unknown: the family is now revoked. Fail closed.
            RefreshOutcome::ReuseDetected | RefreshOutcome::Unknown => Err(AuthError::Denied),
        }
    }

    /// Validate an access token: known hash, not expired, and its device still active.
    pub fn validate_access(&self, access_token: &[u8]) -> Result<AccountDevice> {
        let (account, expires_at) = self
            .sessions
            .get_access(&sha256(access_token))?
            .ok_or(AuthError::Denied)?;
        if self.clock.now_unix() > expires_at {
            return Err(AuthError::Denied);
        }
        // A revoked device's tokens are removed by revoke_device, but check anyway so a
        // missed cleanup still fails closed (defense in depth).
        let device = self
            .devices
            .device(&account.device_id)?
            .filter(|d| !d.revoked)
            .ok_or(AuthError::Denied)?;
        debug_assert_eq!(device.account_id, account.account_id);
        Ok(account)
    }

    /// The enrolled (unrevoked) device's SEC1 public key — used to verify device-signed
    /// artifacts beyond login, e.g. membership manifests (ADR-0010). Fails closed on
    /// unknown/revoked devices.
    pub fn device_public_key(&self, device_id: &DeviceId) -> Result<Vec<u8>> {
        let device = self
            .devices
            .device(device_id)?
            .filter(|d| !d.revoked)
            .ok_or(AuthError::Denied)?;
        Ok(device.public_key)
    }

    /// Revoke the family owning this refresh token and the device's access tokens
    /// (logout on one device). Idempotent; unknown tokens are a no-op.
    pub fn logout(&self, refresh_token: &[u8]) -> Result<()> {
        let hash = sha256(refresh_token);
        if let Some(owner) = self.refresh.owner_of(&hash)? {
            self.refresh.revoke_by_token_hash(&hash)?;
            self.sessions.revoke_access_for_device(&owner.device_id)?;
        }
        Ok(())
    }

    /// Look up the active device id for an account (server-side authority for routing;
    /// never a client-asserted value, INV-6). Returns `Ok(None)` if the account has no
    /// active device.
    pub fn active_device(&self, account_id: &AccountId) -> Result<Option<DeviceId>> {
        Ok(self
            .devices
            .active_device_for_account(account_id)?
            .map(|d| d.device_id))
    }

    /// Revoke a device: mark it revoked and burn all its refresh families and access
    /// tokens (INV-10). Future logins, refreshes, and API calls from it fail closed.
    pub fn revoke_device(&self, device_id: &DeviceId) -> Result<()> {
        self.devices.revoke_device(device_id)?;
        self.refresh.revoke_all_for_device(device_id)?;
        self.sessions.revoke_access_for_device(device_id)?;
        Ok(())
    }

    // ----- internals ----------------------------------------------------------------

    /// Shared challenge validation: correct action and not expired. Binding to account and
    /// device is enforced by the caller rebuilding the transcript from the stored record.
    fn check_challenge(&self, challenge: &ChallengeRecord, expected: Action) -> Result<()> {
        if challenge.action != expected {
            return Err(AuthError::Denied);
        }
        if self.clock.now_unix() > challenge.expires_at {
            return Err(AuthError::Denied);
        }
        Ok(())
    }

    fn mint_session_new_family(&self, account: AccountDevice) -> Result<Session> {
        let now = self.clock.now_unix();
        let refresh_token = random_bytes::<32>();
        let refresh_expires_at = now + self.config.refresh_ttl_secs;
        self.refresh
            .issue(account, sha256(&refresh_token), refresh_expires_at)?;

        let access_token = random_bytes::<32>();
        let access_expires_at = now + self.config.access_ttl_secs;
        self.sessions
            .put_access(sha256(&access_token), account, access_expires_at)?;

        Ok(Session {
            account_id: account.account_id,
            device_id: account.device_id,
            access_token: access_token.to_vec(),
            access_expires_at,
            refresh_token: refresh_token.to_vec(),
            refresh_expires_at,
        })
    }

    fn decoy_login_challenge(&self) -> LoginChallenge {
        LoginChallenge {
            account_id: AccountId::random(),
            device_id: DeviceId::random(),
            txn_id: TxnId::random(),
            nonce: random_bytes::<32>(),
            expires_at: self.clock.now_unix() + self.config.challenge_ttl_secs,
        }
    }
}

/// Deterministic transaction id for a refresh, derived from the token hash so client and
/// server agree without an extra round-trip. Public because the client reproduces it when
/// building the `Refresh` transcript to sign.
pub fn refresh_txn_id(old_hash: &[u8; 32]) -> TxnId {
    let mut buf = Vec::with_capacity(35);
    buf.extend_from_slice(old_hash);
    buf.extend_from_slice(b"txn");
    let digest = sha256(&buf);
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    TxnId(id)
}

/// Conservative ASCII username normalization (ABUSE_MODEL.md): lowercase, 3–32 chars, must
/// start with a letter, allowed set `[a-z0-9_.]`, no `..` and no trailing `.`. Rejecting
/// everything outside the allowlist blocks invisible/zero-width and homoglyph characters
/// and prevents casing/normalization collisions.
pub fn normalize_username(input: &str) -> Result<String> {
    let s = input.trim().to_ascii_lowercase();
    let bytes = s.as_bytes();
    if bytes.len() < 3 || bytes.len() > 32 {
        return Err(AuthError::InvalidInput);
    }
    if !bytes[0].is_ascii_lowercase() {
        return Err(AuthError::InvalidInput);
    }
    for &b in bytes {
        let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.';
        if !ok {
            return Err(AuthError::InvalidInput);
        }
    }
    if s.contains("..") || s.ends_with('.') {
        return Err(AuthError::InvalidInput);
    }
    Ok(s)
}
