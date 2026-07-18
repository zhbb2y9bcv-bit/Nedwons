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

/// A conversation the caller belongs to, with its member accounts (for the Chats list).
pub struct ConversationSummary {
    pub conversation_id: [u8; 16],
    pub member_account_ids: Vec<[u8; 16]>,
}

/// Result of a fanout send.
pub enum FanoutOutcome {
    /// The sender is not a member of the conversation.
    Forbidden,
    /// The idempotency key was already used by this sender for a DIFFERENT payload or
    /// conversation. Refused: silently deduping would drop the new message while reporting
    /// success (a client bug becomes silent data loss). The client must use a fresh key.
    IdempotencyMismatch,
    /// Delivered (or already delivered, on an idempotent retry). Carries the recipient
    /// devices that received a *new* envelope, so only those get woken.
    Delivered { newly_queued: Vec<[u8; 16]> },
}

/// Result of a targeted send.
pub enum SendOutcome {
    /// The sender is not a member of the conversation.
    Forbidden,
    /// Same as [`FanoutOutcome::IdempotencyMismatch`].
    IdempotencyMismatch,
    /// Queued (or already queued, on an idempotent retry) under this envelope id.
    Queued(i64),
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

    /// Create a conversation and add the creator as its first member (one transaction). When
    /// `mls_authoritative`, membership afterwards may change ONLY through an MLS commit
    /// (ADR-0010): the legacy direct-mutation endpoints refuse.
    pub fn create_conversation(
        &self,
        conversation_id: [u8; 16],
        creator_account: AccountId,
        creator_device: DeviceId,
        mls_authoritative: bool,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        txn.execute(
            "INSERT INTO conversations (conversation_id, mls_authoritative) VALUES ($1, $2)",
            &[&conversation_id.as_slice(), &mls_authoritative],
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

    /// Whether a conversation is MLS-authoritative (membership changes only via `/commit`).
    /// Returns `false` for an unknown conversation (safe default; ids are opaque so this leaks
    /// nothing).
    pub fn is_authoritative(&self, conversation_id: &[u8; 16]) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT mls_authoritative FROM conversations WHERE conversation_id = $1",
                &[&conversation_id.as_slice()],
            )
            .map_err(db_err)?;
        Ok(row.map(|r| r.get::<_, bool>(0)).unwrap_or(false))
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

    // NOTE: leaving/removal moved to `groups::PgGroups::leave_conversation` (ADR-0009), which
    // additionally handles admin-role cleanup and auto-promotion. The relay stays mail-only.

    /// List the conversations a device belongs to, most recent first, each with its member
    /// account ids. Rows for one conversation are contiguous (ordered by created_at then
    /// conversation_id), so they group in a single pass.
    pub fn list_conversations(&self, device: &DeviceId) -> StoreResult<Vec<ConversationSummary>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT c.conversation_id, m2.account_id
                 FROM conversation_members m1
                 JOIN conversations c ON c.conversation_id = m1.conversation_id
                 JOIN conversation_members m2 ON m2.conversation_id = c.conversation_id
                 WHERE m1.device_id = $1
                 ORDER BY c.created_at DESC, c.conversation_id, m2.account_id",
                &[&device.as_bytes()],
            )
            .map_err(db_err)?;

        let mut out: Vec<ConversationSummary> = Vec::new();
        for row in rows {
            let cid = id16(row.get::<_, &[u8]>(0))?;
            let account = id16(row.get::<_, &[u8]>(1))?;
            match out.last_mut() {
                Some(last) if last.conversation_id == cid => {
                    if !last.member_account_ids.contains(&account) {
                        last.member_account_ids.push(account);
                    }
                }
                _ => out.push(ConversationSummary {
                    conversation_id: cid,
                    member_account_ids: vec![account],
                }),
            }
        }
        Ok(out)
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
    /// like MLS Welcomes). Idempotent: a retry with the same `idempotency_key` **and identical
    /// payload** returns the existing envelope id rather than inserting a duplicate.
    ///
    /// Idempotency-key scope (defined precisely): a key belongs to the **sender device** and
    /// identifies one logical send — same conversation, same ciphertext bytes. Reusing a key with
    /// a different payload or conversation is refused (`IdempotencyMismatch`), never silently
    /// deduplicated: silent dedup would drop the new message while reporting success.
    pub fn send_targeted(
        &self,
        conversation_id: &[u8; 16],
        sender_device: &DeviceId,
        recipient_device: &DeviceId,
        ciphertext: &[u8],
        idempotency_key: &[u8; 16],
    ) -> StoreResult<SendOutcome> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        if !member_in_txn(&mut txn, conversation_id, sender_device.as_bytes())? {
            return Ok(SendOutcome::Forbidden);
        }
        if idem_key_conflicts(
            &mut txn,
            conversation_id,
            sender_device,
            ciphertext,
            idempotency_key,
        )? {
            return Ok(SendOutcome::IdempotencyMismatch);
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
        Ok(SendOutcome::Queued(id))
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
        if idem_key_conflicts(
            &mut txn,
            conversation_id,
            sender_device,
            ciphertext,
            idempotency_key,
        )? {
            return Ok(FanoutOutcome::IdempotencyMismatch);
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

    /// **Peek** a device's undelivered envelopes, in order, WITHOUT marking them delivered.
    /// This is at-least-once delivery: the client persists them locally and then calls
    /// [`Self::ack_envelopes`]. If the client crashes between peek and ack, it simply
    /// re-peeks and re-processes (deduping by envelope id) — no message is lost, unlike the
    /// old mark-on-fetch model where a lost response silently dropped mail.
    pub fn peek_inbox(&self, device: &DeviceId, limit: i64) -> StoreResult<Vec<EnvelopeOut>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT id, conversation_id, sender_device, ciphertext
                 FROM envelopes
                 WHERE recipient_device = $1 AND NOT delivered
                 ORDER BY id LIMIT $2",
                &[&device.as_bytes(), &limit],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| {
                Ok(EnvelopeOut {
                    id: r.get(0),
                    conversation_id: id16(r.get::<_, &[u8]>(1))?,
                    sender_device: id16(r.get::<_, &[u8]>(2))?,
                    ciphertext: r.get::<_, Vec<u8>>(3),
                })
            })
            .collect()
    }

    /// Acknowledge durably-persisted envelopes: **delete** them. DATA_RETENTION.md commits to
    /// "purged from server on delivery ack" — the recipient's device is the store, so retaining
    /// acked ciphertext would be a silent retention violation. Scoped to the caller's own device,
    /// so a client cannot ack (delete) another device's mail. Idempotent: re-acking deleted ids is
    /// a no-op. Returns the number of rows purged.
    pub fn ack_envelopes(&self, device: &DeviceId, ids: &[i64]) -> StoreResult<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn()?;
        let acked = conn
            .execute(
                "DELETE FROM envelopes WHERE recipient_device = $1 AND id = ANY($2)",
                &[&device.as_bytes(), &ids],
            )
            .map_err(db_err)?;
        Ok(acked)
    }

    /// Retention TTL (DATA_RETENTION.md): purge envelopes older than `ttl` (the 30-day queue
    /// TTL — the sender's client shows "failed" after this). Returns rows purged.
    ///
    /// Deletes in **bounded batches** (`batch_size` rows via the `envelopes_created_at` index, at
    /// most `max_batches` per call): one unbounded `DELETE` over a large backlog would hold locks
    /// and generate a WAL spike that stalls concurrent sends — the failure mode that matters at
    /// scale. A backlog larger than `batch_size * max_batches` simply drains across successive
    /// ticks of the minutely purge task.
    pub fn purge_stale_envelopes(
        &self,
        ttl: std::time::Duration,
        batch_size: i64,
        max_batches: u32,
    ) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let ttl_secs = ttl.as_secs_f64();
        let mut total: u64 = 0;
        for _ in 0..max_batches {
            let purged = conn
                .execute(
                    "DELETE FROM envelopes WHERE id IN (
                         SELECT id FROM envelopes
                         WHERE created_at < now() - make_interval(secs => $1)
                         ORDER BY created_at
                         LIMIT $2)",
                    &[&ttl_secs, &batch_size],
                )
                .map_err(db_err)?;
            total += purged;
            if purged < batch_size as u64 {
                break; // backlog drained
            }
        }
        Ok(total)
    }
}

/// True if this sender has already used `idempotency_key` for a DIFFERENT payload or
/// conversation. Runs inside the send transaction, only touching the sender's own rows via the
/// `envelopes_idem` index prefix. A `true` result must abort the send: the key identifies one
/// logical message, and silently deduplicating a *different* message would drop it.
fn idem_key_conflicts(
    txn: &mut postgres::Transaction<'_>,
    conversation_id: &[u8; 16],
    sender_device: &DeviceId,
    ciphertext: &[u8],
    idempotency_key: &[u8; 16],
) -> StoreResult<bool> {
    let row = txn
        .query_opt(
            "SELECT 1 FROM envelopes
             WHERE sender_device = $1 AND idempotency_key = $2
               AND (conversation_id <> $3 OR ciphertext <> $4)
             LIMIT 1",
            &[
                &sender_device.as_bytes(),
                &idempotency_key.as_slice(),
                &conversation_id.as_slice(),
                &ciphertext,
            ],
        )
        .map_err(db_err)?;
    Ok(row.is_some())
}
