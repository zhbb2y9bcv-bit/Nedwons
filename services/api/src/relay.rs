//! Message relay storage. Handles key-package publication/claiming, conversation routing
//! membership, and opaque encrypted-envelope queue/fetch. The relay never decrypts anything
//! — `ciphertext` is stored and returned as-is (THREAT_MODEL.md INV-1). This module does not
//! depend on `mls-core`; the server cannot read message content by construction.

use auth_core::ids::{AccountId, DeviceId};
use auth_core::store::{StoreError, StoreResult};

use crate::pgstore::PgPool;
use r2d2_postgres::postgres::NoTls;

/// Relay storage over the shared connection pool.
#[derive(Clone)]
pub struct PgRelay {
    pool: PgPool,
}

/// A queued envelope handed back to a recipient device.
pub struct EnvelopeOut {
    pub id: i64,
    pub conversation_id: [u8; 16],
    pub sender_device: [u8; 16],
    pub ciphertext: Vec<u8>,
}

/// A claimed key package plus the device it belongs to.
pub struct ClaimedKeyPackage {
    pub device_id: [u8; 16],
    pub key_package: Vec<u8>,
}

fn db_err(e: postgres::Error) -> StoreError {
    StoreError(format!("relay db: {e}"))
}

fn id16(bytes: &[u8]) -> StoreResult<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| StoreError("bad id length".into()))
}

impl PgRelay {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn conn(
        &self,
    ) -> StoreResult<r2d2::PooledConnection<r2d2_postgres::PostgresConnectionManager<NoTls>>> {
        self.pool
            .get()
            .map_err(|e| StoreError(format!("pool: {e}")))
    }

    /// Publish a key package for a device.
    pub fn publish_key_package(
        &self,
        account: AccountId,
        device: DeviceId,
        key_package: &[u8],
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO key_packages (account_id, device_id, key_package) VALUES ($1, $2, $3)",
            &[&account.as_bytes(), &device.as_bytes(), &key_package],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Claim (pop) one key package for the given account's device. `DELETE ... RETURNING`
    /// with a subquery makes claiming atomic — two claimants cannot get the same package.
    pub fn claim_key_package(&self, account: &AccountId) -> StoreResult<Option<ClaimedKeyPackage>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "DELETE FROM key_packages WHERE id = (
                     SELECT id FROM key_packages WHERE account_id = $1 ORDER BY id LIMIT 1
                     FOR UPDATE SKIP LOCKED
                 ) RETURNING device_id, key_package",
                &[&account.as_bytes()],
            )
            .map_err(db_err)?;
        row.map(|r| {
            Ok(ClaimedKeyPackage {
                device_id: id16(r.get::<_, &[u8]>(0))?,
                key_package: r.get::<_, Vec<u8>>(1),
            })
        })
        .transpose()
    }

    /// Create a conversation and add the creator as its first member (one transaction).
    pub fn create_conversation(
        &self,
        conversation_id: [u8; 16],
        creator_account: AccountId,
        creator_device: DeviceId,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        txn.execute(
            "INSERT INTO conversations (conversation_id) VALUES ($1)",
            &[&conversation_id.as_slice()],
        )
        .map_err(db_err)?;
        txn.execute(
            "INSERT INTO conversation_members (conversation_id, account_id, device_id)
             VALUES ($1, $2, $3)",
            &[
                &conversation_id.as_slice(),
                &creator_account.as_bytes(),
                &creator_device.as_bytes(),
            ],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(())
    }

    /// Add a device to a conversation's routing membership (idempotent).
    pub fn add_member(
        &self,
        conversation_id: &[u8; 16],
        account: AccountId,
        device: DeviceId,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO conversation_members (conversation_id, account_id, device_id)
             VALUES ($1, $2, $3) ON CONFLICT (conversation_id, device_id) DO NOTHING",
            &[
                &conversation_id.as_slice(),
                &account.as_bytes(),
                &device.as_bytes(),
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn is_member(&self, conversation_id: &[u8; 16], device: &DeviceId) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND device_id = $2",
                &[&conversation_id.as_slice(), &device.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(row.is_some())
    }

    /// Store an opaque envelope for a recipient device. Returns the server-assigned id
    /// (a server receipt — delivery to the server, NOT a decryption claim).
    pub fn send_envelope(
        &self,
        conversation_id: &[u8; 16],
        sender_device: &DeviceId,
        recipient_device: &DeviceId,
        ciphertext: &[u8],
    ) -> StoreResult<i64> {
        let mut conn = self.conn()?;
        let row = conn
            .query_one(
                "INSERT INTO envelopes (conversation_id, sender_device, recipient_device, ciphertext)
                 VALUES ($1, $2, $3, $4) RETURNING id",
                &[
                    &conversation_id.as_slice(),
                    &sender_device.as_bytes(),
                    &recipient_device.as_bytes(),
                    &ciphertext,
                ],
            )
            .map_err(db_err)?;
        Ok(row.get(0))
    }

    /// Fetch and mark-delivered the undelivered envelopes for a device (in order).
    pub fn fetch_inbox(&self, device: &DeviceId, limit: i64) -> StoreResult<Vec<EnvelopeOut>> {
        let mut conn = self.conn()?;
        // Atomically claim a batch: mark delivered and return them.
        let rows = conn
            .query(
                "UPDATE envelopes SET delivered = TRUE
                 WHERE id IN (
                     SELECT id FROM envelopes
                     WHERE recipient_device = $1 AND NOT delivered
                     ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED
                 )
                 RETURNING id, conversation_id, sender_device, ciphertext",
                &[&device.as_bytes(), &limit],
            )
            .map_err(db_err)?;
        let mut out: Vec<EnvelopeOut> = rows
            .into_iter()
            .map(|r| {
                Ok(EnvelopeOut {
                    id: r.get(0),
                    conversation_id: id16(r.get::<_, &[u8]>(1))?,
                    sender_device: id16(r.get::<_, &[u8]>(2))?,
                    ciphertext: r.get::<_, Vec<u8>>(3),
                })
            })
            .collect::<StoreResult<Vec<_>>>()?;
        // `UPDATE ... RETURNING` does not preserve the subquery's ORDER BY, so sort by id
        // here. Ordered delivery is REQUIRED: MLS commits/welcomes must be processed in the
        // order they were produced or the receiver's group state diverges.
        out.sort_by_key(|e| e.id);
        Ok(out)
    }
}
