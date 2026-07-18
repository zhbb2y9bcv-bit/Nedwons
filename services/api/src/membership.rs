//! MLS-commit-authoritative membership (ADR-0010, R-506).
//!
//! [`PgMembership::apply_commit`] is the single transaction that accepts a membership change:
//! governance (ADR-0009 roles/blocks) → idempotency → **epoch compare-and-swap** (linearizes
//! membership history; exactly one commit per epoch transition) → routing delta → commit/welcome
//! fan-out → removed-device delivery cutoff → append-only audit log. A failure anywhere applies
//! nothing.
//!
//! The relay stays MLS-blind: this module handles ids, hashes, and opaque ciphertext only. The
//! manifest signature is verified by the HTTP layer (auth-core) BEFORE this store is called; the
//! semantic checks that must be atomic with the write happen here, inside the transaction.

use auth_core::ids::{AccountId, DeviceId};
use auth_core::store::{StoreError, StoreResult};

use crate::pgstore::PgPool;
use r2d2_postgres::postgres::NoTls;

/// Outcome of attempting to apply a membership commit.
pub enum ApplyOutcome {
    /// Applied; wake these recipient devices (commit fan-out + welcomes).
    Applied { woken: Vec<[u8; 16]> },
    /// Identical manifest already applied under this idempotency key — a retry. Durable no-op.
    AlreadyApplied,
    /// Actor is not a member / lacks the required role / a block forbids an added account. One
    /// generic outcome (no membership oracle).
    Forbidden,
    /// `prev_epoch` did not match the stored epoch: a concurrent commit won. Nothing applied;
    /// the client must discard its pending commit, resync, and rebuild.
    StaleEpoch,
    /// The idempotency key was used before with a DIFFERENT manifest.
    IdempotencyMismatch,
    /// Semantically invalid against current state (unknown removed device, duplicate added
    /// device, missing welcome, malformed lists).
    Invalid,
}

/// A stored membership event's evidence (canonical manifest bytes + device signature).
pub struct MembershipEventRow {
    pub manifest: Vec<u8>,
    pub signature: Vec<u8>,
}

/// One accepted membership change, fully described (what `apply_commit` persists and fans out).
pub struct CommitRequest<'a> {
    pub conversation_id: &'a [u8; 16],
    pub actor_account: &'a AccountId,
    pub actor_device: &'a DeviceId,
    /// 1 = add, 2 = remove, 3 = self-leave (`auth_core::membership::ControlType`).
    pub control_type: u8,
    pub prev_epoch: u64,
    pub next_epoch: u64,
    pub commit_hash: &'a [u8; 32],
    pub manifest_hash: &'a [u8; 32],
    /// Canonical manifest bytes + signature, stored verbatim in the audit log.
    pub manifest: &'a [u8],
    pub signature: &'a [u8],
    pub idempotency_key: &'a [u8; 16],
    /// The opaque MLS commit, fanned to every pre-change member device except the actor and the
    /// removed devices.
    pub commit: &'a [u8],
    pub added: &'a [(AccountId, DeviceId)],
    pub removed: &'a [DeviceId],
    /// One opaque Welcome per added device, same order as `added`.
    pub welcomes: &'a [Vec<u8>],
}

#[derive(Clone)]
pub struct PgMembership {
    pool: PgPool,
}

fn db_err(e: postgres::Error) -> StoreError {
    StoreError(format!("membership db: {e}"))
}

impl PgMembership {
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

    /// Apply one membership commit atomically (ADR-0010 server acceptance, steps 5–9; the HTTP
    /// layer performed steps 1–4: auth, signature, freshness, hash binding).
    pub fn apply_commit(&self, req: &CommitRequest<'_>) -> StoreResult<ApplyOutcome> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        let conv = req.conversation_id.as_slice();

        // Idempotency FIRST: a retry of an already-applied commit must short-circuit before any
        // check against current state (the member it added now exists; the epoch has moved). Same
        // key + same manifest = benign retry; same key + different manifest = refusal.
        if let Some(row) = txn
            .query_opt(
                "SELECT manifest_hash FROM membership_events
                 WHERE actor_device = $1 AND idempotency_key = $2",
                &[
                    &req.actor_device.as_bytes(),
                    &req.idempotency_key.as_slice(),
                ],
            )
            .map_err(db_err)?
        {
            let prior: &[u8] = row.get(0);
            return Ok(if prior == req.manifest_hash.as_slice() {
                ApplyOutcome::AlreadyApplied
            } else {
                ApplyOutcome::IdempotencyMismatch
            });
        }

        // Actor must be a routed member (their device row exists).
        let actor_is_member = txn
            .query_opt(
                "SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND device_id = $2",
                &[&conv, &req.actor_device.as_bytes()],
            )
            .map_err(db_err)?
            .is_some();
        if !actor_is_member {
            return Ok(ApplyOutcome::Forbidden);
        }

        // Governance (ADR-0009, re-checked inside the txn).
        match req.control_type {
            // Add / Remove require the admin role.
            1 | 2 => {
                let is_admin = txn
                    .query_opt(
                        "SELECT 1 FROM group_admins WHERE conversation_id = $1 AND account_id = $2",
                        &[&conv, &req.actor_account.as_bytes()],
                    )
                    .map_err(db_err)?
                    .is_some();
                if !is_admin {
                    return Ok(ApplyOutcome::Forbidden);
                }
            }
            // Self-leave: the removed set must be exactly the actor's own routed devices.
            3 => {
                let mut own: Vec<[u8; 16]> = txn
                    .query(
                        "SELECT device_id FROM conversation_members
                         WHERE conversation_id = $1 AND account_id = $2",
                        &[&conv, &req.actor_account.as_bytes()],
                    )
                    .map_err(db_err)?
                    .into_iter()
                    .filter_map(|r| r.get::<_, &[u8]>(0).try_into().ok())
                    .collect();
                own.sort();
                let mut claimed: Vec<[u8; 16]> = req.removed.iter().map(|d| d.0).collect();
                claimed.sort();
                if own.is_empty() || own != claimed {
                    return Ok(ApplyOutcome::Forbidden);
                }
            }
            _ => return Ok(ApplyOutcome::Invalid),
        }

        // Adds: device not already routed; no block between the added account and any member;
        // a welcome per added device (checked by the HTTP layer for length, here for count).
        if req.welcomes.len() != req.added.len() {
            return Ok(ApplyOutcome::Invalid);
        }
        for (account, device) in req.added {
            let exists = txn
                .query_opt(
                    "SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND device_id = $2",
                    &[&conv, &device.as_bytes()],
                )
                .map_err(db_err)?
                .is_some();
            if exists {
                return Ok(ApplyOutcome::Invalid);
            }
            let blocked = txn
                .query_opt(
                    "SELECT 1 FROM blocks b
                     WHERE (b.blocker = $2 AND b.blocked IN (
                                SELECT account_id FROM conversation_members WHERE conversation_id = $1))
                        OR (b.blocked = $2 AND b.blocker IN (
                                SELECT account_id FROM conversation_members WHERE conversation_id = $1))",
                    &[&conv, &account.as_bytes()],
                )
                .map_err(db_err)?
                .is_some();
            if blocked {
                return Ok(ApplyOutcome::Forbidden);
            }
        }

        // Removes: every named device must currently be routed; removing another ADMIN's device
        // is refused unless it is a self-leave (demote first — ADR-0009 keeps admin churn
        // explicit and preserves the last-admin invariant).
        for device in req.removed {
            let owner: Option<[u8; 16]> = txn
                .query_opt(
                    "SELECT account_id FROM conversation_members
                     WHERE conversation_id = $1 AND device_id = $2",
                    &[&conv, &device.as_bytes()],
                )
                .map_err(db_err)?
                .and_then(|r| r.get::<_, &[u8]>(0).try_into().ok());
            let Some(owner) = owner else {
                return Ok(ApplyOutcome::Invalid);
            };
            if req.control_type == 2 && owner != req.actor_account.0 {
                let target_is_admin = txn
                    .query_opt(
                        "SELECT 1 FROM group_admins WHERE conversation_id = $1 AND account_id = $2",
                        &[&conv, &owner.as_slice()],
                    )
                    .map_err(db_err)?
                    .is_some();
                if target_is_admin {
                    return Ok(ApplyOutcome::Forbidden);
                }
            }
        }

        // Epoch compare-and-swap: exactly one commit wins prev → prev+1.
        let swapped = txn
            .execute(
                "UPDATE conversations SET epoch = $3
                 WHERE conversation_id = $1 AND epoch = $2",
                &[&conv, &(req.prev_epoch as i64), &(req.next_epoch as i64)],
            )
            .map_err(db_err)?;
        if swapped == 0 {
            return Ok(ApplyOutcome::StaleEpoch);
        }

        // The commit fans out to every PRE-change member device except the actor and except the
        // removed devices (their delivery is being cut, and MLS removals need no delivery to the
        // removed party). Captured before the delta mutates the table.
        let commit_recipients: Vec<[u8; 16]> = txn
            .query(
                "SELECT device_id FROM conversation_members
                 WHERE conversation_id = $1 AND device_id <> $2",
                &[&conv, &req.actor_device.as_bytes()],
            )
            .map_err(db_err)?
            .into_iter()
            .filter_map(|r| r.get::<_, &[u8]>(0).try_into().ok())
            .filter(|d: &[u8; 16]| !req.removed.iter().any(|r| &r.0 == d))
            .collect();

        // Routing delta.
        for (account, device) in req.added {
            txn.execute(
                "INSERT INTO conversation_members (conversation_id, account_id, device_id)
                 VALUES ($1, $2, $3)",
                &[&conv, &account.as_bytes(), &device.as_bytes()],
            )
            .map_err(db_err)?;
        }
        for device in req.removed {
            txn.execute(
                "DELETE FROM conversation_members WHERE conversation_id = $1 AND device_id = $2",
                &[&conv, &device.as_bytes()],
            )
            .map_err(db_err)?;
            // Delivery cutoff: the removed device's queued mail for this conversation vanishes
            // with the same transaction that removes it.
            txn.execute(
                "DELETE FROM envelopes WHERE conversation_id = $1 AND recipient_device = $2",
                &[&conv, &device.as_bytes()],
            )
            .map_err(db_err)?;
            // Role hygiene on self-leave: an account with no remaining devices keeps no admin row.
            txn.execute(
                "DELETE FROM group_admins ga WHERE ga.conversation_id = $1
                   AND NOT EXISTS (SELECT 1 FROM conversation_members cm
                                   WHERE cm.conversation_id = $1 AND cm.account_id = ga.account_id)",
                &[&conv],
            )
            .map_err(db_err)?;
        }

        // Fan out the commit + targeted welcomes under the manifest's idempotency key.
        let mut woken: Vec<[u8; 16]> = Vec::new();
        for recipient in &commit_recipients {
            txn.execute(
                "INSERT INTO envelopes
                     (conversation_id, sender_device, recipient_device, ciphertext, idempotency_key)
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &conv,
                    &req.actor_device.as_bytes(),
                    &recipient.as_slice(),
                    &req.commit,
                    &req.idempotency_key.as_slice(),
                ],
            )
            .map_err(db_err)?;
            woken.push(*recipient);
        }
        for ((_, device), welcome) in req.added.iter().zip(req.welcomes) {
            txn.execute(
                "INSERT INTO envelopes
                     (conversation_id, sender_device, recipient_device, ciphertext, idempotency_key)
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &conv,
                    &req.actor_device.as_bytes(),
                    &device.as_bytes(),
                    &welcome.as_slice(),
                    &req.idempotency_key.as_slice(),
                ],
            )
            .map_err(db_err)?;
            woken.push(device.0);
        }

        // Append-only audit log.
        txn.execute(
            "INSERT INTO membership_events
                 (conversation_id, prev_epoch, next_epoch, control_type, actor_device,
                  commit_hash, manifest_hash, manifest, signature, idempotency_key)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            &[
                &conv,
                &(req.prev_epoch as i64),
                &(req.next_epoch as i64),
                &(req.control_type as i16),
                &req.actor_device.as_bytes(),
                &req.commit_hash.as_slice(),
                &req.manifest_hash.as_slice(),
                &req.manifest,
                &req.signature,
                &req.idempotency_key.as_slice(),
            ],
        )
        .map_err(db_err)?;

        txn.commit().map_err(db_err)?;
        Ok(ApplyOutcome::Applied { woken })
    }

    /// The stored manifest + signature for a specific epoch transition (`next_epoch`), for a
    /// recipient's correspondence check. `None` if no such event. Auth/membership is enforced by
    /// the caller (the HTTP layer) before this runs.
    pub fn event_for_epoch(
        &self,
        conversation_id: &[u8; 16],
        next_epoch: u64,
    ) -> StoreResult<Option<MembershipEventRow>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT manifest, signature FROM membership_events
                 WHERE conversation_id = $1 AND next_epoch = $2",
                &[&conversation_id.as_slice(), &(next_epoch as i64)],
            )
            .map_err(db_err)?;
        Ok(row.map(|r| MembershipEventRow {
            manifest: r.get::<_, Vec<u8>>(0),
            signature: r.get::<_, Vec<u8>>(1),
        }))
    }

    /// Current membership epoch of a conversation the caller belongs to (`None` = not a member —
    /// one generic answer, no oracle).
    pub fn epoch_for_member(
        &self,
        conversation_id: &[u8; 16],
        device: &DeviceId,
    ) -> StoreResult<Option<u64>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT c.epoch FROM conversations c
                 JOIN conversation_members m ON m.conversation_id = c.conversation_id
                 WHERE c.conversation_id = $1 AND m.device_id = $2",
                &[&conversation_id.as_slice(), &device.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(row.map(|r| r.get::<_, i64>(0) as u64))
    }
}
