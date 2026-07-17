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

/// Result of a fanout send.
pub enum FanoutOutcome {
    /// The sender is not a member of the conversation.
    Forbidden,
    /// Delivered (or already delivered, on an idempotent retry). Carries the recipient
    /// devices that received a *new* envelope, so only those get woken.
    Delivered { newly_queued: Vec<[u8; 16]> },
}

fn db_err(e: postgres::Error) -> StoreError {
    StoreError(format!("relay db: {e}"))
}

/// Membership check inside an open transaction (so the check and the dependent write are
/// atomic — a member removed concurrently can't slip a message in).
fn member_in_txn(
    txn: &mut postgres::Transaction<'_>,
    conversation_id: &[u8; 16],
    device: &[u8],
) -> StoreResult<bool> {
    let row = txn
        .query_opt(
            "SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND device_id = $2",
            &[&conversation_id.as_slice(), &device],
        )
        .map_err(db_err)?;
    Ok(row.is_some())
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

    /// Store an opaque envelope for a single recipient device (used for targeted messages
    /// like MLS Welcomes). Idempotent: a retry with the same `idempotency_key` returns the
    /// existing envelope id rather than inserting a duplicate. Returns `None` if the sender
    /// is not a member of the conversation.
    pub fn send_targeted(
        &self,
        conversation_id: &[u8; 16],
        sender_device: &DeviceId,
        recipient_device: &DeviceId,
        ciphertext: &[u8],
        idempotency_key: &[u8; 16],
    ) -> StoreResult<Option<i64>> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        if !member_in_txn(&mut txn, conversation_id, sender_device.as_bytes())? {
            return Ok(None);
        }
        // Insert, or on idempotent conflict fetch the existing row's id.
        let inserted = txn
            .query_opt(
                "INSERT INTO envelopes
                     (conversation_id, sender_device, recipient_device, ciphertext, idempotency_key)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (sender_device, recipient_device, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
                 RETURNING id",
                &[
                    &conversation_id.as_slice(),
                    &sender_device.as_bytes(),
                    &recipient_device.as_bytes(),
                    &ciphertext,
                    &idempotency_key.as_slice(),
                ],
            )
            .map_err(db_err)?;
        let id = match inserted {
            Some(row) => row.get::<_, i64>(0),
            None => txn
                .query_one(
                    "SELECT id FROM envelopes
                     WHERE sender_device = $1 AND recipient_device = $2 AND idempotency_key = $3",
                    &[
                        &sender_device.as_bytes(),
                        &recipient_device.as_bytes(),
                        &idempotency_key.as_slice(),
                    ],
                )
                .map_err(db_err)?
                .get::<_, i64>(0),
        };
        txn.commit().map_err(db_err)?;
        Ok(Some(id))
    }

    /// Fan out one ciphertext to every OTHER member device of a conversation in a single
    /// round trip and a single statement (`INSERT ... SELECT ... ON CONFLICT DO NOTHING`).
    /// This matches MLS semantics — an application message is one ciphertext the whole group
    /// decrypts — so the client uploads once instead of once per recipient. Idempotent per
    /// `idempotency_key`.
    pub fn fanout_message(
        &self,
        conversation_id: &[u8; 16],
        sender_device: &DeviceId,
        ciphertext: &[u8],
        idempotency_key: &[u8; 16],
    ) -> StoreResult<FanoutOutcome> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        if !member_in_txn(&mut txn, conversation_id, sender_device.as_bytes())? {
            return Ok(FanoutOutcome::Forbidden);
        }
        let rows = txn
            .query(
                "INSERT INTO envelopes
                     (conversation_id, sender_device, recipient_device, ciphertext, idempotency_key)
                 SELECT $1, $2, cm.device_id, $3, $4
                 FROM conversation_members cm
                 WHERE cm.conversation_id = $1 AND cm.device_id <> $2
                 ON CONFLICT (sender_device, recipient_device, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
                 RETURNING recipient_device",
                &[
                    &conversation_id.as_slice(),
                    &sender_device.as_bytes(),
                    &ciphertext,
                    &idempotency_key.as_slice(),
                ],
            )
            .map_err(db_err)?;
        txn.commit().map_err(db_err)?;

        let newly_queued = rows
            .into_iter()
            .map(|r| id16(r.get::<_, &[u8]>(0)))
            .collect::<StoreResult<Vec<_>>>()?;
        Ok(FanoutOutcome::Delivered { newly_queued })
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
