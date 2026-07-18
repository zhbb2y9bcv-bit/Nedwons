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
        }
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
