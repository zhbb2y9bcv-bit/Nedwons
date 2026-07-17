//! PostgreSQL implementations of auth-core's storage seam (ADR-0006). Every atomicity
//! contract documented on the traits is enforced here by the database:
//!
//! * `ChallengeStore::consume` — `DELETE ... RETURNING`: exactly one caller can ever get
//!   the row, even under concurrent access.
//! * `RefreshStore::rotate` — `SELECT ... FOR UPDATE` on the family row serializes racers;
//!   a generation mismatch (reuse of a retired token) revokes the family in the same
//!   transaction.
//! * `CredentialStore::create_account_with_device` — one transaction; the partial unique
//!   index `devices_one_active_per_account` and the username unique constraint make
//!   conflicting states unrepresentable.
//!
//! Errors are wrapped into `StoreError` with internal-only messages; the service maps them
//! to generic failures (never detail to API callers).

use auth_core::ids::{AccountId, DeviceId, FamilyId, TxnId};
use auth_core::store::{
    AccountDevice, AccountRecord, ChallengeRecord, ChallengeStore, CredentialStore, DeviceRecord,
    DeviceStore, RefreshOutcome, RefreshStore, SessionStore, StoreError, StoreResult,
};
use auth_core::Action;
use r2d2::Pool;
use r2d2_postgres::{postgres::NoTls, PostgresConnectionManager};

pub type PgPool = Pool<PostgresConnectionManager<NoTls>>;

/// One handle implements all five store traits over a shared connection pool.
#[derive(Clone)]
pub struct PgStores {
    pool: PgPool,
}

impl PgStores {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn conn(&self) -> StoreResult<r2d2::PooledConnection<PostgresConnectionManager<NoTls>>> {
        self.pool
            .get()
            .map_err(|e| StoreError(format!("pool: {e}")))
    }

    /// Purge expired challenges and access tokens (retention hygiene, DATA_RETENTION.md).
    /// Called periodically by the server binary.
    pub fn purge_expired(&self, now_unix: u64) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let now = to_i64(now_unix)?;
        let a = conn
            .execute("DELETE FROM challenges WHERE expires_at < $1", &[&now])
            .map_err(db_err)?;
        let b = conn
            .execute("DELETE FROM access_tokens WHERE expires_at < $1", &[&now])
            .map_err(db_err)?;
        Ok(a + b)
    }
}

fn db_err(e: postgres::Error) -> StoreError {
    StoreError(format!("db: {e}"))
}

fn to_i64(v: u64) -> StoreResult<i64> {
    i64::try_from(v).map_err(|_| StoreError("u64 out of i64 range".into()))
}

fn to_u64(v: i64) -> StoreResult<u64> {
    u64::try_from(v).map_err(|_| StoreError("negative timestamp in db".into()))
}

fn id16(bytes: &[u8], what: &str) -> StoreResult<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| StoreError(format!("{what}: bad length {}", bytes.len())))
}

fn nonce32(bytes: &[u8]) -> StoreResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| StoreError(format!("nonce: bad length {}", bytes.len())))
}

fn action_from_i16(v: i16) -> StoreResult<Action> {
    Ok(match v {
        1 => Action::Register,
        2 => Action::Login,
        3 => Action::Refresh,
        4 => Action::PasswordChange,
        5 => Action::DeviceEnroll,
        6 => Action::AccountDelete,
        other => return Err(StoreError(format!("unknown action {other}"))),
    })
}

impl CredentialStore for PgStores {
    fn create_account_with_device(
        &self,
        account: AccountRecord,
        device: DeviceRecord,
    ) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        let inserted = txn
            .execute(
                "INSERT INTO accounts (account_id, username_normalized, password_phc)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (username_normalized) DO NOTHING",
                &[
                    &account.account_id.as_bytes(),
                    &account.username_normalized,
                    &account.password_phc,
                ],
            )
            .map_err(db_err)?;
        if inserted == 0 {
            // Username taken. Transaction drops without commit; nothing persisted.
            return Ok(false);
        }
        txn.execute(
            "INSERT INTO devices (device_id, account_id, public_key, revoked)
             VALUES ($1, $2, $3, FALSE)",
            &[
                &device.device_id.as_bytes(),
                &device.account_id.as_bytes(),
                &device.public_key,
            ],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(true)
    }

    fn find_by_username(&self, username_normalized: &str) -> StoreResult<Option<AccountRecord>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT account_id, username_normalized, password_phc
                 FROM accounts WHERE username_normalized = $1",
                &[&username_normalized],
            )
            .map_err(db_err)?;
        row.map(|r| {
            Ok(AccountRecord {
                account_id: AccountId(id16(r.get::<_, &[u8]>(0), "account_id")?),
                username_normalized: r.get(1),
                password_phc: r.get(2),
            })
        })
        .transpose()
    }
}

impl DeviceStore for PgStores {
    fn active_device_for_account(
        &self,
        account_id: &AccountId,
    ) -> StoreResult<Option<DeviceRecord>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT device_id, account_id, public_key, revoked
                 FROM devices WHERE account_id = $1 AND NOT revoked",
                &[&account_id.as_bytes()],
            )
            .map_err(db_err)?;
        row.map(row_to_device).transpose()
    }

    fn device(&self, device_id: &DeviceId) -> StoreResult<Option<DeviceRecord>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT device_id, account_id, public_key, revoked
                 FROM devices WHERE device_id = $1",
                &[&device_id.as_bytes()],
            )
            .map_err(db_err)?;
        row.map(row_to_device).transpose()
    }

    fn revoke_device(&self, device_id: &DeviceId) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "UPDATE devices SET revoked = TRUE WHERE device_id = $1",
            &[&device_id.as_bytes()],
        )
        .map_err(db_err)?;
        Ok(())
    }
}

fn row_to_device(r: postgres::Row) -> StoreResult<DeviceRecord> {
    Ok(DeviceRecord {
        device_id: DeviceId(id16(r.get::<_, &[u8]>(0), "device_id")?),
        account_id: AccountId(id16(r.get::<_, &[u8]>(1), "account_id")?),
        public_key: r.get::<_, Vec<u8>>(2),
        revoked: r.get(3),
    })
}

impl ChallengeStore for PgStores {
    fn put(&self, c: ChallengeRecord) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO challenges (txn_id, account_id, device_id, action, nonce, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &c.txn_id.as_bytes(),
                &c.account_id.as_bytes(),
                &c.device_id.as_bytes(),
                &(c.action as i16),
                &c.nonce.as_slice(),
                &to_i64(c.expires_at)?,
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    fn consume(&self, txn_id: &TxnId) -> StoreResult<Option<ChallengeRecord>> {
        let mut conn = self.conn()?;
        // DELETE ... RETURNING is the atomic single-use guarantee: under any concurrency,
        // at most one caller receives the row (INV-4).
        let row = conn
            .query_opt(
                "DELETE FROM challenges WHERE txn_id = $1
                 RETURNING txn_id, account_id, device_id, action, nonce, expires_at",
                &[&txn_id.as_bytes()],
            )
            .map_err(db_err)?;
        row.map(|r| {
            Ok(ChallengeRecord {
                txn_id: TxnId(id16(r.get::<_, &[u8]>(0), "txn_id")?),
                account_id: AccountId(id16(r.get::<_, &[u8]>(1), "account_id")?),
                device_id: DeviceId(id16(r.get::<_, &[u8]>(2), "device_id")?),
                action: action_from_i16(r.get(3))?,
                nonce: nonce32(r.get::<_, &[u8]>(4))?,
                expires_at: to_u64(r.get(5))?,
            })
        })
        .transpose()
    }
}

impl RefreshStore for PgStores {
    fn issue(
        &self,
        account: AccountDevice,
        token_hash: [u8; 32],
        expires_at: u64,
    ) -> StoreResult<FamilyId> {
        let family_id = FamilyId::random();
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        txn.execute(
            "INSERT INTO refresh_families (family_id, account_id, device_id, current_gen, revoked, expires_at)
             VALUES ($1, $2, $3, 0, FALSE, $4)",
            &[
                &family_id.as_bytes(),
                &account.account_id.as_bytes(),
                &account.device_id.as_bytes(),
                &to_i64(expires_at)?,
            ],
        )
        .map_err(db_err)?;
        txn.execute(
            "INSERT INTO refresh_tokens (token_hash, family_id, gen) VALUES ($1, $2, 0)",
            &[&token_hash.as_slice(), &family_id.as_bytes()],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(family_id)
    }

    fn owner_of(&self, token_hash: &[u8; 32]) -> StoreResult<Option<AccountDevice>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT f.account_id, f.device_id
                 FROM refresh_tokens t JOIN refresh_families f USING (family_id)
                 WHERE t.token_hash = $1",
                &[&token_hash.as_slice()],
            )
            .map_err(db_err)?;
        row.map(|r| {
            Ok(AccountDevice {
                account_id: AccountId(id16(r.get::<_, &[u8]>(0), "account_id")?),
                device_id: DeviceId(id16(r.get::<_, &[u8]>(1), "device_id")?),
            })
        })
        .transpose()
    }

    fn rotate(
        &self,
        old_hash: &[u8; 32],
        new_hash: [u8; 32],
        new_expires_at: u64,
    ) -> StoreResult<RefreshOutcome> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;

        let Some(token_row) = txn
            .query_opt(
                "SELECT family_id, gen FROM refresh_tokens WHERE token_hash = $1",
                &[&old_hash.as_slice()],
            )
            .map_err(db_err)?
        else {
            return Ok(RefreshOutcome::Unknown);
        };
        let family_id: Vec<u8> = token_row.get(0);
        let token_gen: i64 = token_row.get(1);

        // FOR UPDATE serializes concurrent rotations of the same family: exactly one racer
        // proceeds first; the losers then see a bumped generation and burn the family.
        let Some(family_row) = txn
            .query_opt(
                "SELECT account_id, device_id, current_gen, revoked
                 FROM refresh_families WHERE family_id = $1 FOR UPDATE",
                &[&family_id],
            )
            .map_err(db_err)?
        else {
            return Ok(RefreshOutcome::Unknown);
        };
        let account = AccountDevice {
            account_id: AccountId(id16(family_row.get::<_, &[u8]>(0), "account_id")?),
            device_id: DeviceId(id16(family_row.get::<_, &[u8]>(1), "device_id")?),
        };
        let current_gen: i64 = family_row.get(2);
        let revoked: bool = family_row.get(3);

        if revoked {
            txn.commit().map_err(db_err)?;
            return Ok(RefreshOutcome::ReuseDetected);
        }
        if token_gen != current_gen {
            // Reuse of a retired token: revoke the whole family, fail closed.
            txn.execute(
                "UPDATE refresh_families SET revoked = TRUE WHERE family_id = $1",
                &[&family_id],
            )
            .map_err(db_err)?;
            txn.commit().map_err(db_err)?;
            return Ok(RefreshOutcome::ReuseDetected);
        }

        txn.execute(
            "UPDATE refresh_families SET current_gen = current_gen + 1, expires_at = $2
             WHERE family_id = $1",
            &[&family_id, &to_i64(new_expires_at)?],
        )
        .map_err(db_err)?;
        txn.execute(
            "INSERT INTO refresh_tokens (token_hash, family_id, gen) VALUES ($1, $2, $3)",
            &[&new_hash.as_slice(), &family_id, &(current_gen + 1)],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(RefreshOutcome::Rotated { account })
    }

    fn revoke_by_token_hash(&self, token_hash: &[u8; 32]) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "UPDATE refresh_families SET revoked = TRUE
             WHERE family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = $1)",
            &[&token_hash.as_slice()],
        )
        .map_err(db_err)?;
        Ok(())
    }

    fn revoke_all_for_device(&self, device_id: &DeviceId) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "UPDATE refresh_families SET revoked = TRUE WHERE device_id = $1",
            &[&device_id.as_bytes()],
        )
        .map_err(db_err)?;
        Ok(())
    }
}

impl SessionStore for PgStores {
    fn put_access(
        &self,
        token_hash: [u8; 32],
        account: AccountDevice,
        expires_at: u64,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO access_tokens (token_hash, account_id, device_id, expires_at)
             VALUES ($1, $2, $3, $4)",
            &[
                &token_hash.as_slice(),
                &account.account_id.as_bytes(),
                &account.device_id.as_bytes(),
                &to_i64(expires_at)?,
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    fn get_access(&self, token_hash: &[u8; 32]) -> StoreResult<Option<(AccountDevice, u64)>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT account_id, device_id, expires_at FROM access_tokens WHERE token_hash = $1",
                &[&token_hash.as_slice()],
            )
            .map_err(db_err)?;
        row.map(|r| {
            Ok((
                AccountDevice {
                    account_id: AccountId(id16(r.get::<_, &[u8]>(0), "account_id")?),
                    device_id: DeviceId(id16(r.get::<_, &[u8]>(1), "device_id")?),
                },
                to_u64(r.get(2))?,
            ))
        })
        .transpose()
    }

    fn revoke_access_for_device(&self, device_id: &DeviceId) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "DELETE FROM access_tokens WHERE device_id = $1",
            &[&device_id.as_bytes()],
        )
        .map_err(db_err)?;
        Ok(())
    }
}
