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
    DeviceRecord, DeviceStore, RefreshOutcome, RefreshStore,
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

#[derive(Default)]
pub struct MemCredentialStore {
    by_username: Mutex<HashMap<String, AccountRecord>>,
}
impl CredentialStore for MemCredentialStore {
    fn create_account(&self, account: AccountRecord) -> bool {
        let mut map = self.by_username.lock().unwrap();
        if map.contains_key(&account.username_normalized) {
            return false; // unique-constraint analogue
        }
        map.insert(account.username_normalized.clone(), account);
        true
    }
    fn find_by_username(&self, username_normalized: &str) -> Option<AccountRecord> {
        self.by_username
            .lock()
            .unwrap()
            .get(username_normalized)
            .cloned()
    }
}

#[derive(Default)]
pub struct MemDeviceStore {
    by_id: Mutex<HashMap<DeviceId, DeviceRecord>>,
}
impl DeviceStore for MemDeviceStore {
    fn create_device(&self, device: DeviceRecord) {
        self.by_id.lock().unwrap().insert(device.device_id, device);
    }
    fn active_device_for_account(&self, account_id: &AccountId) -> Option<DeviceRecord> {
        self.by_id
            .lock()
            .unwrap()
            .values()
            .find(|d| &d.account_id == account_id && !d.revoked)
            .cloned()
    }
    fn device(&self, device_id: &DeviceId) -> Option<DeviceRecord> {
        self.by_id.lock().unwrap().get(device_id).cloned()
    }
    fn revoke_device(&self, device_id: &DeviceId) {
        if let Some(d) = self.by_id.lock().unwrap().get_mut(device_id) {
            d.revoked = true;
        }
    }
}

#[derive(Default)]
pub struct MemChallengeStore {
    by_txn: Mutex<HashMap<TxnId, ChallengeRecord>>,
}
impl ChallengeStore for MemChallengeStore {
    fn put(&self, challenge: ChallengeRecord) {
        self.by_txn
            .lock()
            .unwrap()
            .insert(challenge.txn_id, challenge);
    }
    fn consume(&self, txn_id: &TxnId) -> Option<ChallengeRecord> {
        // remove() is the atomic consume analogue: a second call returns None.
        self.by_txn.lock().unwrap().remove(txn_id)
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
    fn issue(&self, account: AccountDevice, token_hash: [u8; 32], expires_at: u64) -> FamilyId {
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
        family_id
    }
    fn owner_of(&self, token_hash: &[u8; 32]) -> Option<AccountDevice> {
        let tokens = self.tokens.lock().unwrap();
        let (family_id, _) = tokens.get(token_hash)?;
        self.families
            .lock()
            .unwrap()
            .get(family_id)
            .map(|f| f.account)
    }
    fn rotate(
        &self,
        old_hash: &[u8; 32],
        new_hash: [u8; 32],
        new_expires_at: u64,
    ) -> RefreshOutcome {
        let mut tokens = self.tokens.lock().unwrap();
        let (family_id, gen) = match tokens.get(old_hash) {
            Some(v) => *v,
            None => return RefreshOutcome::Unknown,
        };
        let mut families = self.families.lock().unwrap();
        let family = match families.get_mut(&family_id) {
            Some(f) => f,
            None => return RefreshOutcome::Unknown,
        };
        if family.revoked {
            return RefreshOutcome::ReuseDetected;
        }
        if gen != family.current_gen {
            // A retired token was presented — someone is reusing an old token. Burn the
            // whole family.
            family.revoked = true;
            return RefreshOutcome::ReuseDetected;
        }
        family.current_gen += 1;
        family.expires_at = new_expires_at;
        let account = family.account;
        let new_gen = family.current_gen;
        // Keep old_hash present (now retired) so a later reuse is detectable.
        tokens.insert(new_hash, (family_id, new_gen));
        RefreshOutcome::Rotated { account }
    }
    fn revoke_by_token_hash(&self, token_hash: &[u8; 32]) {
        let tokens = self.tokens.lock().unwrap();
        if let Some((family_id, _)) = tokens.get(token_hash) {
            if let Some(f) = self.families.lock().unwrap().get_mut(family_id) {
                f.revoked = true;
            }
        }
    }
    fn revoke_all_for_device(&self, device_id: &DeviceId) {
        for f in self.families.lock().unwrap().values_mut() {
            if &f.account.device_id == device_id {
                f.revoked = true;
            }
        }
    }
}
