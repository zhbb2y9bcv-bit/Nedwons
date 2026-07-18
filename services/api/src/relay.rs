//! Message relay storage. Handles key-package publication/claiming, conversation routing
//! membership, and opaque encrypted-envelope queue/fetch. The relay never decrypts anything
//! — `ciphertext` is stored and returned as-is (THREAT_MODEL.md INV-1). This module does not
//! depend on `mls-core`; the server cannot read message content by construction.

use auth_core::ids::{AccountId, DeviceId};
use auth_core::store::{StoreError, StoreResult};

use crate::pgstore::PgPool;
use r2d2_postgres::postgres::NoTls;

/// MLS key packages ("prekeys") expire after this (hygiene): a stale prekey must never be used to
/// add a device. The client replenishes when its available count drops below the low-watermark.
pub const KEY_PACKAGE_TTL_SECS: u64 = 30 * 24 * 3600;
/// Suggested client replenishment threshold (surfaced via the count endpoint).
pub const KEY_PACKAGE_LOW_WATERMARK: u64 = 5;

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

/// A queued **sealed-sender** envelope (ADR-0014): the relay knows only who to deliver it to and the
/// opaque ciphertext — never the sender or conversation.
pub struct SealedEnvelopeOut {
    pub id: i64,
    pub ciphertext: Vec<u8>,
}

/// A queued **self-group** envelope (ADR-0015 option 3): opaque ciphertext for one of the account's
/// own devices — an MLS Welcome/commit during device linking, or a `SecretConsumed` control message.
/// Both endpoints are the same account's authenticated devices, so the sender device is recorded.
pub struct SelfGroupEnvelopeOut {
    pub id: i64,
    pub sender_device: [u8; 16],
    pub ciphertext: Vec<u8>,
}

/// Outcome of a self-group delivery (targeted or fan-out).
#[derive(Debug, PartialEq, Eq)]
pub enum SelfGroupSendOutcome {
    /// The recipient device is not a device of the delivering account (targeted delivery only).
    Forbidden,
    /// Delivered (or already delivered on an idempotent retry). Carries the recipient devices that
    /// received a *new* envelope, so only those get woken.
    Delivered { newly_queued: Vec<[u8; 16]> },
}

/// Outcome of a sealed delivery.
#[derive(Debug, PartialEq, Eq)]
pub enum SealedSendOutcome {
    /// Stored for the recipient device.
    Enqueued { id: i64 },
    /// The (recipient_device, idempotency_key) pair already exists — a retry, deduplicated.
    Duplicate,
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

    /// Register (or rotate) the account's sealed-sender **delivery access verifier**
    /// `V_r = SHA-256(K_r)` (ADR-0014 Slice 2a). Upsert: a second call replaces the previous
    /// verifier (rotation), instantly revoking every holder of the old key at the relay. The relay
    /// stores only the 32-byte hash, never `K_r`.
    pub fn set_delivery_verifier(&self, account: &AccountId, verifier: &[u8]) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO delivery_access_keys (account_id, verifier, updated_at)
             VALUES ($1, $2, now())
             ON CONFLICT (account_id) DO UPDATE SET verifier = EXCLUDED.verifier, updated_at = now()",
            &[&account.as_bytes(), &verifier],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// The owning account of a **non-revoked** device, or `None` if the device is unknown or
    /// revoked. Used by sealed delivery to find whose delivery-access verifier gates the recipient.
    pub fn account_for_device(&self, device: &DeviceId) -> StoreResult<Option<AccountId>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT account_id FROM devices WHERE device_id = $1 AND NOT revoked",
                &[&device.as_bytes()],
            )
            .map_err(db_err)?;
        match row {
            Some(r) => Ok(Some(AccountId(id16(r.get::<_, &[u8]>(0))?))),
            None => Ok(None),
        }
    }

    /// The account's registered delivery access verifier, or `None` if it has not set one. Used by
    /// the sealed-delivery endpoint to gate a presented key.
    pub fn delivery_verifier(&self, account: &AccountId) -> StoreResult<Option<Vec<u8>>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT verifier FROM delivery_access_keys WHERE account_id = $1",
                &[&account.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(row.map(|r| r.get::<_, Vec<u8>>(0)))
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

    /// Claim (pop) one **non-expired** key package for the given account's device. `DELETE ...
    /// RETURNING` with a subquery makes claiming atomic — two claimants cannot get the same
    /// package. Key packages older than `ttl_secs` are ignored (a stale prekey must never be used
    /// to add a device — MLS key-package hygiene); the purge task deletes them.
    pub fn claim_key_package(
        &self,
        account: &AccountId,
        ttl_secs: u64,
    ) -> StoreResult<Option<ClaimedKeyPackage>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "DELETE FROM key_packages WHERE id = (
                     SELECT id FROM key_packages
                     WHERE account_id = $1 AND created_at > now() - make_interval(secs => $2)
                     ORDER BY id LIMIT 1
                     FOR UPDATE SKIP LOCKED
                 ) RETURNING device_id, key_package",
                &[&account.as_bytes(), &(ttl_secs as f64)],
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

    /// How many non-expired key packages a device still has published. The client publishes more
    /// when this drops below a low-watermark, so the device stays addable offline (replenishment).
    pub fn count_available_key_packages(
        &self,
        device: &DeviceId,
        ttl_secs: u64,
    ) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let count: i64 = conn
            .query_one(
                "SELECT count(*) FROM key_packages
                 WHERE device_id = $1 AND created_at > now() - make_interval(secs => $2)",
                &[&device.as_bytes(), &(ttl_secs as f64)],
            )
            .map_err(db_err)?
            .get(0);
        Ok(count as u64)
    }

    /// Delete key packages older than `ttl_secs` (MLS prekey hygiene). Returns rows purged.
    pub fn purge_expired_key_packages(&self, ttl_secs: u64) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let purged = conn
            .execute(
                "DELETE FROM key_packages WHERE created_at <= now() - make_interval(secs => $1)",
                &[&(ttl_secs as f64)],
            )
            .map_err(db_err)?;
        Ok(purged)
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

    /// Store a **sealed** envelope for `recipient_device` (ADR-0014 Slice 2b). No sender or
    /// conversation is recorded. Idempotent on `(recipient_device, idempotency_key)`: a retry with
    /// the same key is a `Duplicate` no-op (the key is a 128-bit sender-chosen random, so a
    /// cross-sender collision is ~2^-128). The DAK gate is enforced by the caller *before* this.
    pub fn deliver_sealed(
        &self,
        recipient_device: &DeviceId,
        ciphertext: &[u8],
        idempotency_key: &[u8; 16],
    ) -> StoreResult<SealedSendOutcome> {
        let mut conn = self.conn()?;
        let idem = idempotency_key.as_slice();
        let row = conn
            .query_opt(
                "INSERT INTO sealed_envelopes (recipient_device, ciphertext, idempotency_key)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (recipient_device, idempotency_key) DO NOTHING
                 RETURNING id",
                &[&recipient_device.as_bytes(), &ciphertext, &idem],
            )
            .map_err(db_err)?;
        Ok(match row {
            Some(r) => SealedSendOutcome::Enqueued { id: r.get(0) },
            None => SealedSendOutcome::Duplicate,
        })
    }

    /// Peek a device's undelivered **sealed** envelopes (at-least-once, like [`Self::peek_inbox`]).
    pub fn peek_sealed_inbox(
        &self,
        device: &DeviceId,
        limit: i64,
    ) -> StoreResult<Vec<SealedEnvelopeOut>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT id, ciphertext FROM sealed_envelopes
                 WHERE recipient_device = $1 AND NOT delivered
                 ORDER BY id LIMIT $2",
                &[&device.as_bytes(), &limit],
            )
            .map_err(db_err)?;
        Ok(rows
            .into_iter()
            .map(|r| SealedEnvelopeOut {
                id: r.get(0),
                ciphertext: r.get::<_, Vec<u8>>(1),
            })
            .collect())
    }

    /// Acknowledge (delete) sealed envelopes, scoped to the caller's own device.
    pub fn ack_sealed(&self, device: &DeviceId, ids: &[i64]) -> StoreResult<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn()?;
        let acked = conn
            .execute(
                "DELETE FROM sealed_envelopes WHERE recipient_device = $1 AND id = ANY($2)",
                &[&device.as_bytes(), &ids],
            )
            .map_err(db_err)?;
        Ok(acked)
    }

    /// Retention purge for sealed envelopes (mirrors [`Self::purge_stale_envelopes`]).
    pub fn purge_stale_sealed(
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
                    "DELETE FROM sealed_envelopes WHERE id IN (
                         SELECT id FROM sealed_envelopes
                         WHERE created_at < now() - make_interval(secs => $1)
                         ORDER BY created_at
                         LIMIT $2)",
                    &[&ttl_secs, &batch_size],
                )
                .map_err(db_err)?;
            total += purged;
            if purged < batch_size as u64 {
                break;
            }
        }
        Ok(total)
    }

    // ----- Device self-group (ADR-0015 option 3) --------------------------------------------------
    //
    // Establishing + using the account's own-devices MLS group over the relay. The relay is MLS-blind
    // throughout: it never sees the self-group's group id or plaintext, only routes opaque ciphertext
    // among ONE account's authenticated devices. Every method here is account-scoped by construction.

    /// Record that `device` (of `account`) has joined its account's self-group. Idempotent — a repeat
    /// is a no-op. The caller authenticates as this device, so no cross-account membership is
    /// representable.
    pub fn register_self_group_member(
        &self,
        account: &AccountId,
        device: &DeviceId,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO self_group_members (account_id, device_id) VALUES ($1, $2)
             ON CONFLICT (account_id, device_id) DO NOTHING",
            &[&account.as_bytes(), &device.as_bytes()],
        )
        .map_err(db_err)?;
        Ok(())
    }

    // ----- Push notification tokens (#4) ----------------------------------------------------------

    /// Register (or rotate) a device's push token for a platform (`apns`). Upsert — one token per
    /// (device, platform). The token is opaque to the relay; it addresses a contentless wake push.
    pub fn register_push_token(
        &self,
        device: &DeviceId,
        platform: &str,
        token: &str,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO device_push_tokens (device_id, platform, token, updated_at)
             VALUES ($1, $2, $3, now())
             ON CONFLICT (device_id, platform)
             DO UPDATE SET token = EXCLUDED.token, updated_at = now()",
            &[&device.as_bytes(), &platform, &token],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// This device's registered push tokens as `(platform, token)` pairs.
    pub fn push_tokens_for_device(&self, device: &DeviceId) -> StoreResult<Vec<(String, String)>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT platform, token FROM device_push_tokens WHERE device_id = $1",
                &[&device.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)))
            .collect())
    }

    /// Delete all of a device's push tokens (on revocation). Idempotent; returns rows removed.
    pub fn delete_push_tokens(&self, device: &DeviceId) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let removed = conn
            .execute(
                "DELETE FROM device_push_tokens WHERE device_id = $1",
                &[&device.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(removed)
    }

    /// Drop a device from its account's self-group membership (housekeeping when the device is
    /// revoked). Idempotent. The *cryptographic* re-key is a client action (an existing device issues
    /// an MLS remove-commit); this just stops the relay routing self-group traffic to it and keeps
    /// the pending-devices view accurate. Returns rows removed.
    pub fn remove_self_group_member(
        &self,
        account: &AccountId,
        device: &DeviceId,
    ) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let removed = conn
            .execute(
                "DELETE FROM self_group_members WHERE account_id = $1 AND device_id = $2",
                &[&account.as_bytes(), &device.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(removed)
    }

    /// True if `device` is a joined member of `account`'s self-group.
    pub fn is_self_group_member(
        &self,
        account: &AccountId,
        device: &DeviceId,
    ) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT 1 FROM self_group_members WHERE account_id = $1 AND device_id = $2",
                &[&account.as_bytes(), &device.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(row.is_some())
    }

    /// The account's non-revoked devices that are enrolled but NOT yet in its self-group — the
    /// candidates a linking device claims a key package for and adds. Excludes `caller` itself.
    pub fn pending_self_group_devices(
        &self,
        account: &AccountId,
        caller: &DeviceId,
    ) -> StoreResult<Vec<[u8; 16]>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT d.device_id FROM devices d
                 WHERE d.account_id = $1 AND NOT d.revoked AND d.device_id <> $2
                   AND NOT EXISTS (
                       SELECT 1 FROM self_group_members m
                       WHERE m.account_id = $1 AND m.device_id = d.device_id)
                 ORDER BY d.device_id",
                &[&account.as_bytes(), &caller.as_bytes()],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| id16(r.get::<_, &[u8]>(0)))
            .collect()
    }

    /// Claim (pop) one non-expired key package for a **specific** device (used to add a named sibling
    /// device to the self-group). Like [`Self::claim_key_package`] but scoped to one device rather
    /// than any of the account's devices, so a multi-device link targets each sibling deterministically.
    pub fn claim_key_package_for_device(
        &self,
        device: &DeviceId,
        ttl_secs: u64,
    ) -> StoreResult<Option<ClaimedKeyPackage>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "DELETE FROM key_packages WHERE id = (
                     SELECT id FROM key_packages
                     WHERE device_id = $1 AND created_at > now() - make_interval(secs => $2)
                     ORDER BY id LIMIT 1
                     FOR UPDATE SKIP LOCKED
                 ) RETURNING device_id, key_package",
                &[&device.as_bytes(), &(ttl_secs as f64)],
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

    /// Deliver a self-group envelope to ONE specific recipient device of `account` (an MLS Welcome to
    /// a device being linked, or a commit to an existing member). Refuses if the recipient is not a
    /// non-revoked device of `account`. Idempotent on `(recipient, sender, idempotency_key)`.
    pub fn deliver_self_group_targeted(
        &self,
        account: &AccountId,
        sender_device: &DeviceId,
        recipient_device: &DeviceId,
        ciphertext: &[u8],
        idempotency_key: &[u8; 16],
    ) -> StoreResult<SelfGroupSendOutcome> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        // The recipient must be a non-revoked device of the SAME account (authorization boundary).
        let ok = txn
            .query_opt(
                "SELECT 1 FROM devices WHERE device_id = $1 AND account_id = $2 AND NOT revoked",
                &[&recipient_device.as_bytes(), &account.as_bytes()],
            )
            .map_err(db_err)?
            .is_some();
        if !ok {
            return Ok(SelfGroupSendOutcome::Forbidden);
        }
        let row = txn
            .query_opt(
                "INSERT INTO self_group_envelopes
                     (recipient_device, sender_device, ciphertext, idempotency_key)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (recipient_device, sender_device, idempotency_key) DO NOTHING
                 RETURNING recipient_device",
                &[
                    &recipient_device.as_bytes(),
                    &sender_device.as_bytes(),
                    &ciphertext,
                    &idempotency_key.as_slice(),
                ],
            )
            .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        let newly_queued = match row {
            Some(_) => vec![recipient_device.0],
            None => vec![], // idempotent retry
        };
        Ok(SelfGroupSendOutcome::Delivered { newly_queued })
    }

    /// Fan a self-group envelope out to every OTHER **joined member** of `account`'s self-group (a
    /// `SecretConsumed` control message, or a commit to the whole self-group). Excludes the sender and
    /// any revoked device. Idempotent per key. One statement, mirroring [`Self::fanout_message`].
    pub fn fanout_self_group(
        &self,
        account: &AccountId,
        sender_device: &DeviceId,
        ciphertext: &[u8],
        idempotency_key: &[u8; 16],
    ) -> StoreResult<SelfGroupSendOutcome> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "INSERT INTO self_group_envelopes
                     (recipient_device, sender_device, ciphertext, idempotency_key)
                 SELECT m.device_id, $2, $3, $4
                 FROM self_group_members m
                 JOIN devices d ON d.device_id = m.device_id
                 WHERE m.account_id = $1 AND m.device_id <> $2 AND NOT d.revoked
                 ON CONFLICT (recipient_device, sender_device, idempotency_key) DO NOTHING
                 RETURNING recipient_device",
                &[
                    &account.as_bytes(),
                    &sender_device.as_bytes(),
                    &ciphertext,
                    &idempotency_key.as_slice(),
                ],
            )
            .map_err(db_err)?;
        let newly_queued = rows
            .into_iter()
            .map(|r| id16(r.get::<_, &[u8]>(0)))
            .collect::<StoreResult<Vec<_>>>()?;
        Ok(SelfGroupSendOutcome::Delivered { newly_queued })
    }

    /// Peek a device's undelivered self-group envelopes (at-least-once, like [`Self::peek_inbox`]).
    pub fn peek_self_group_inbox(
        &self,
        device: &DeviceId,
        limit: i64,
    ) -> StoreResult<Vec<SelfGroupEnvelopeOut>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT id, sender_device, ciphertext FROM self_group_envelopes
                 WHERE recipient_device = $1 AND NOT delivered
                 ORDER BY id LIMIT $2",
                &[&device.as_bytes(), &limit],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| {
                Ok(SelfGroupEnvelopeOut {
                    id: r.get(0),
                    sender_device: id16(r.get::<_, &[u8]>(1))?,
                    ciphertext: r.get::<_, Vec<u8>>(2),
                })
            })
            .collect()
    }

    /// Acknowledge (delete) self-group envelopes, scoped to the caller's own device.
    pub fn ack_self_group(&self, device: &DeviceId, ids: &[i64]) -> StoreResult<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn()?;
        let acked = conn
            .execute(
                "DELETE FROM self_group_envelopes WHERE recipient_device = $1 AND id = ANY($2)",
                &[&device.as_bytes(), &ids],
            )
            .map_err(db_err)?;
        Ok(acked)
    }

    /// Retention purge for self-group envelopes (mirrors [`Self::purge_stale_envelopes`]).
    pub fn purge_stale_self_group(
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
                    "DELETE FROM self_group_envelopes WHERE id IN (
                         SELECT id FROM self_group_envelopes
                         WHERE created_at < now() - make_interval(secs => $1)
                         ORDER BY created_at
                         LIMIT $2)",
                    &[&ttl_secs, &batch_size],
                )
                .map_err(db_err)?;
            total += purged;
            if purged < batch_size as u64 {
                break;
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
