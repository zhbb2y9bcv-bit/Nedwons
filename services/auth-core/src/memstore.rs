//! In-memory store implementations used by unit/integration tests. They mimic the
//! atomicity contracts documented on the store traits (ADR-0006) so the security tests
//! exercise the same fail-closed paths the PostgreSQL implementations must provide. These
//! are NOT for production use.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::ids::{AccountId, DeviceId, FamilyId, TxnId};
use crate::store::{
    AccountDevice, AccountRecord, ChallengeRecord, ChallengeStore, Clock, CredentialStore,
    DeviceRecord, DeviceStore, RefreshOutcome, RefreshStore, SessionStore, StoreResult,
};

/// Real wall-clock.
#[derive(Default)]
pub struct SystemClock;
impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Test clock that can be advanced to drive expiry.
#[derive(Default)]
pub struct MockClock {
    now: AtomicU64,
}
impl MockClock {
    pub fn new(start: u64) -> Self {
        Self {
            now: AtomicU64::new(start),
        }
    }
    pub fn advance(&self, secs: u64) {
        self.now.fetch_add(secs, Ordering::SeqCst);
    }
}
impl Clock for MockClock {
    fn now_unix(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

/// One struct implements both `CredentialStore` and `DeviceStore` so account+device
/// creation can be atomic under a single lock, mirroring the SQL transaction.
#[derive(Default)]
pub struct MemAccountStore {
    inner: Mutex<AccountsInner>,
}

#[derive(Default)]
struct AccountsInner {
    accounts_by_username: HashMap<String, AccountRecord>,
    devices_by_id: HashMap<DeviceId, DeviceRecord>,
}

impl CredentialStore for MemAccountStore {
    fn create_account_with_device(
        &self,
        account: AccountRecord,
        device: DeviceRecord,
    ) -> StoreResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        if inner
            .accounts_by_username
            .contains_key(&account.username_normalized)
        {
            return Ok(false); // unique-constraint analogue
        }
        inner
            .accounts_by_username
            .insert(account.username_normalized.clone(), account);
        inner.devices_by_id.insert(device.device_id, device);
        Ok(true)
    }

    fn find_by_username(&self, username_normalized: &str) -> StoreResult<Option<AccountRecord>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .accounts_by_username
            .get(username_normalized)
            .cloned())
    }
}

impl DeviceStore for MemAccountStore {
    fn active_device_for_account(
        &self,
        account_id: &AccountId,
    ) -> StoreResult<Option<DeviceRecord>> {
        // Deterministic primary: the non-revoked device with the smallest id (the in-memory store
        // has no creation timestamp; the SQL store orders by created_at then id).
        Ok(self
            .inner
            .lock()
            .unwrap()
            .devices_by_id
            .values()
            .filter(|d| &d.account_id == account_id && !d.revoked)
            .min_by_key(|d| d.device_id.0)
            .cloned())
    }

    fn device(&self, device_id: &DeviceId) -> StoreResult<Option<DeviceRecord>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .devices_by_id
            .get(device_id)
            .cloned())
    }

    fn revoke_device(&self, device_id: &DeviceId) -> StoreResult<()> {
        if let Some(d) = self.inner.lock().unwrap().devices_by_id.get_mut(device_id) {
            d.revoked = true;
        }
        Ok(())
    }

    fn add_active_device(&self, device: DeviceRecord, max_active: usize) -> StoreResult<bool> {
        let mut inner = self.inner.lock().unwrap();
        let active = inner
            .devices_by_id
            .values()
            .filter(|d| d.account_id == device.account_id && !d.revoked)
            .count();
        if active >= max_active || inner.devices_by_id.contains_key(&device.device_id) {
            return Ok(false);
        }
        inner.devices_by_id.insert(device.device_id, device);
        Ok(true)
    }

    fn list_devices(&self, account_id: &AccountId) -> StoreResult<Vec<DeviceRecord>> {
        let mut out: Vec<DeviceRecord> = self
            .inner
            .lock()
            .unwrap()
            .devices_by_id
            .values()
            .filter(|d| &d.account_id == account_id)
            .cloned()
            .collect();
        out.sort_by_key(|d| d.device_id.0);
        Ok(out)
    }
}

#[derive(Default)]
pub struct MemChallengeStore {
    by_txn: Mutex<HashMap<TxnId, ChallengeRecord>>,
}
impl ChallengeStore for MemChallengeStore {
    fn put(&self, challenge: ChallengeRecord) -> StoreResult<()> {
        self.by_txn
            .lock()
            .unwrap()
            .insert(challenge.txn_id, challenge);
        Ok(())
    }
    fn consume(&self, txn_id: &TxnId) -> StoreResult<Option<ChallengeRecord>> {
        // remove() is the atomic consume analogue: a second call returns None.
        Ok(self.by_txn.lock().unwrap().remove(txn_id))
    }
}

struct Family {
    account: AccountDevice,
    current_gen: u64,
    revoked: bool,
    #[allow(dead_code)]
    expires_at: u64,
}

#[derive(Default)]
pub struct MemRefreshStore {
    // token hash -> (family, generation this token belongs to)
    tokens: Mutex<HashMap<[u8; 32], (FamilyId, u64)>>,
    families: Mutex<HashMap<FamilyId, Family>>,
}
impl RefreshStore for MemRefreshStore {
    fn issue(
        &self,
        account: AccountDevice,
        token_hash: [u8; 32],
        expires_at: u64,
    ) -> StoreResult<FamilyId> {
        let family_id = FamilyId::random();
        self.families.lock().unwrap().insert(
            family_id,
            Family {
                account,
                current_gen: 0,
                revoked: false,
                expires_at,
            },
        );
        self.tokens
            .lock()
            .unwrap()
            .insert(token_hash, (family_id, 0));
        Ok(family_id)
    }
    fn owner_of(&self, token_hash: &[u8; 32]) -> StoreResult<Option<AccountDevice>> {
        let tokens = self.tokens.lock().unwrap();
        let Some((family_id, _)) = tokens.get(token_hash) else {
            return Ok(None);
        };
        Ok(self
            .families
            .lock()
            .unwrap()
            .get(family_id)
            .map(|f| f.account))
    }
    fn rotate(
        &self,
        old_hash: &[u8; 32],
        new_hash: [u8; 32],
        new_expires_at: u64,
    ) -> StoreResult<RefreshOutcome> {
        let mut tokens = self.tokens.lock().unwrap();
        let (family_id, gen) = match tokens.get(old_hash) {
            Some(v) => *v,
            None => return Ok(RefreshOutcome::Unknown),
        };
        let mut families = self.families.lock().unwrap();
        let family = match families.get_mut(&family_id) {
            Some(f) => f,
            None => return Ok(RefreshOutcome::Unknown),
        };
        if family.revoked {
            return Ok(RefreshOutcome::ReuseDetected);
        }
        if gen != family.current_gen {
            // A retired token was presented — someone is reusing an old token. Burn the
            // whole family.
            family.revoked = true;
            return Ok(RefreshOutcome::ReuseDetected);
        }
        family.current_gen += 1;
        family.expires_at = new_expires_at;
        let account = family.account;
        let new_gen = family.current_gen;
        // Keep old_hash present (now retired) so a later reuse is detectable.
        tokens.insert(new_hash, (family_id, new_gen));
        Ok(RefreshOutcome::Rotated { account })
    }
    fn revoke_by_token_hash(&self, token_hash: &[u8; 32]) -> StoreResult<()> {
        let tokens = self.tokens.lock().unwrap();
        if let Some((family_id, _)) = tokens.get(token_hash) {
            if let Some(f) = self.families.lock().unwrap().get_mut(family_id) {
                f.revoked = true;
            }
        }
        Ok(())
    }
    fn revoke_all_for_device(&self, device_id: &DeviceId) -> StoreResult<()> {
        for f in self.families.lock().unwrap().values_mut() {
            if &f.account.device_id == device_id {
                f.revoked = true;
            }
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemSessionStore {
    access: Mutex<HashMap<[u8; 32], (AccountDevice, u64)>>,
}
impl SessionStore for MemSessionStore {
    fn put_access(
        &self,
        token_hash: [u8; 32],
        account: AccountDevice,
        expires_at: u64,
    ) -> StoreResult<()> {
        self.access
            .lock()
            .unwrap()
            .insert(token_hash, (account, expires_at));
        Ok(())
    }
    fn get_access(&self, token_hash: &[u8; 32]) -> StoreResult<Option<(AccountDevice, u64)>> {
        Ok(self.access.lock().unwrap().get(token_hash).copied())
    }
    fn revoke_access_for_device(&self, device_id: &DeviceId) -> StoreResult<()> {
        self.access
            .lock()
            .unwrap()
            .retain(|_, (owner, _)| &owner.device_id != device_id);
        Ok(())
    }
}
