//! Group governance (ADR-0009): admin roles, invite links, join requests, member removal, and
//! leave. All social/routing metadata — never message content. Rules enforced here:
//!
//! * The creator of a conversation is its first **admin**; admins manage invites, join requests,
//!   removal, roles, and settings. Absence from `group_admins` = ordinary member.
//! * **Invite tokens are the joiner's own consent**: whoever presents a valid token joins (or
//!   requests to join) themselves. Tokens are 32 random bytes, expiring, use-bounded, revocable.
//! * **Blocks are enforced at every entry path**: a joiner is refused if a block exists (either
//!   direction) between them and ANY current member.
//! * When the **last admin** leaves, the earliest-added remaining member is auto-promoted, so a
//!   group is never left unmanageable.

use auth_core::ids::{AccountId, DeviceId};
use auth_core::store::{StoreError, StoreResult};
use r2d2_postgres::postgres::NoTls;

use crate::pgstore::PgPool;

#[derive(Clone)]
pub struct PgGroups {
    pool: PgPool,
}

/// Outcome of presenting an invite token.
#[derive(Debug, PartialEq, Eq)]
pub enum InviteOutcome {
    /// Token consumed; caller may be added to routing for this conversation.
    Joined { conversation_id: [u8; 16] },
    /// Token consumed; the conversation requires admin approval — a join request now exists.
    Requested { conversation_id: [u8; 16] },
    /// Invalid/expired/revoked/exhausted token, or a block bars the joiner. Deliberately one
    /// generic refusal: an invite token must not become an oracle for group/block state.
    Refused,
}

/// An active invite (for the admin's management list).
pub struct InviteSummary {
    pub token: [u8; 32],
    pub expires_at_unix: i64,
    pub max_uses: i32,
    pub uses: i32,
}

fn db_err(e: postgres::Error) -> StoreError {
    StoreError(format!("groups db: {e}"))
}

fn id16(bytes: &[u8]) -> StoreResult<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| StoreError("bad id length".into()))
}

impl PgGroups {
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

    // ----- roles ---------------------------------------------------------------------

    pub fn is_admin(&self, conversation_id: &[u8; 16], account: &AccountId) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        Ok(conn
            .query_opt(
                "SELECT 1 FROM group_admins WHERE conversation_id = $1 AND account_id = $2",
                &[&conversation_id.as_slice(), &account.as_bytes()],
            )
            .map_err(db_err)?
            .is_some())
    }

    /// Grant admin. Idempotent. The target must already be a member (has a routing row).
    /// Returns false if the target is not a member.
    pub fn promote(&self, conversation_id: &[u8; 16], account: &AccountId) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        let member = txn
            .query_opt(
                "SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND account_id = $2",
                &[&conversation_id.as_slice(), &account.as_bytes()],
            )
            .map_err(db_err)?
            .is_some();
        if !member {
            return Ok(false);
        }
        txn.execute(
            "INSERT INTO group_admins (conversation_id, account_id) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
            &[&conversation_id.as_slice(), &account.as_bytes()],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(true)
    }

    /// Revoke admin. Refuses (returns false) if the target is the LAST admin — a group must never
    /// become unmanageable by demotion. Idempotent for non-admin targets.
    pub fn demote(&self, conversation_id: &[u8; 16], account: &AccountId) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        let admins: i64 = txn
            .query_one(
                "SELECT count(*) FROM group_admins WHERE conversation_id = $1",
                &[&conversation_id.as_slice()],
            )
            .map_err(db_err)?
            .get(0);
        let target_is_admin = txn
            .query_opt(
                "SELECT 1 FROM group_admins WHERE conversation_id = $1 AND account_id = $2",
                &[&conversation_id.as_slice(), &account.as_bytes()],
            )
            .map_err(db_err)?
            .is_some();
        if target_is_admin && admins <= 1 {
            return Ok(false); // last admin: refuse
        }
        txn.execute(
            "DELETE FROM group_admins WHERE conversation_id = $1 AND account_id = $2",
            &[&conversation_id.as_slice(), &account.as_bytes()],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(true)
    }

    /// Set whether joining via invite requires admin approval.
    pub fn set_join_approval(&self, conversation_id: &[u8; 16], required: bool) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "UPDATE conversations SET join_approval = $2 WHERE conversation_id = $1",
            &[&conversation_id.as_slice(), &required],
        )
        .map_err(db_err)?;
        Ok(())
    }

    // ----- invites -------------------------------------------------------------------

    /// Create an invite link token. Caller must have verified admin-ship.
    pub fn create_invite(
        &self,
        conversation_id: &[u8; 16],
        created_by: &AccountId,
        token: [u8; 32],
        expires_in_secs: i64,
        max_uses: i32,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO group_invites (token, conversation_id, created_by, expires_at, max_uses)
             VALUES ($1, $2, $3, now() + ($4 * interval '1 second'), $5)",
            &[
                &token.as_slice(),
                &conversation_id.as_slice(),
                &created_by.as_bytes(),
                &f64::from(i32::try_from(expires_in_secs).unwrap_or(i32::MAX)),
                &max_uses,
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Active (unexpired, unrevoked, unexhausted) invites for a conversation.
    pub fn list_invites(&self, conversation_id: &[u8; 16]) -> StoreResult<Vec<InviteSummary>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT token, extract(epoch FROM expires_at)::bigint, max_uses, uses
                 FROM group_invites
                 WHERE conversation_id = $1 AND NOT revoked
                   AND expires_at > now() AND uses < max_uses
                 ORDER BY created_at DESC",
                &[&conversation_id.as_slice()],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| {
                let token: &[u8] = r.get(0);
                Ok(InviteSummary {
                    token: token
                        .try_into()
                        .map_err(|_| StoreError("bad token length".into()))?,
                    expires_at_unix: r.get(1),
                    max_uses: r.get(2),
                    uses: r.get(3),
                })
            })
            .collect()
    }

    /// Revoke an invite belonging to this conversation. Idempotent.
    pub fn revoke_invite(&self, conversation_id: &[u8; 16], token: &[u8; 32]) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "UPDATE group_invites SET revoked = TRUE
             WHERE token = $1 AND conversation_id = $2",
            &[&token.as_slice(), &conversation_id.as_slice()],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Present an invite token as `joiner`. One transaction: validates the token (unexpired,
    /// unrevoked, uses < max), enforces blocks against ALL current members, consumes a use, and
    /// either records a join request (approval groups) or reports Joined — the caller then adds
    /// the joiner's device to routing. A joiner already in the group is Refused (no use burned).
    pub fn accept_invite(
        &self,
        token: &[u8; 32],
        joiner: &AccountId,
    ) -> StoreResult<InviteOutcome> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        // Lock the invite row so concurrent accepts serialize on the use counter.
        let row = txn
            .query_opt(
                "SELECT conversation_id FROM group_invites
                 WHERE token = $1 AND NOT revoked AND expires_at > now() AND uses < max_uses
                 FOR UPDATE",
                &[&token.as_slice()],
            )
            .map_err(db_err)?;
        let Some(row) = row else {
            return Ok(InviteOutcome::Refused);
        };
        let conversation_id = id16(row.get::<_, &[u8]>(0))?;

        // Already a member (or already requested)? Refuse without burning a use.
        let already = txn
            .query_opt(
                "SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND account_id = $2
                 UNION ALL
                 SELECT 1 FROM group_join_requests WHERE conversation_id = $1 AND account_id = $2",
                &[&conversation_id.as_slice(), &joiner.as_bytes()],
            )
            .map_err(db_err)?
            .is_some();
        if already {
            return Ok(InviteOutcome::Refused);
        }

        // Blocks bar entry (either direction, against any current member).
        let blocked = txn
            .query_opt(
                "SELECT 1 FROM blocks b
                 WHERE (b.blocker = $2 AND b.blocked IN (
                            SELECT account_id FROM conversation_members WHERE conversation_id = $1))
                    OR (b.blocked = $2 AND b.blocker IN (
                            SELECT account_id FROM conversation_members WHERE conversation_id = $1))",
                &[&conversation_id.as_slice(), &joiner.as_bytes()],
            )
            .map_err(db_err)?
            .is_some();
        if blocked {
            return Ok(InviteOutcome::Refused);
        }

        txn.execute(
            "UPDATE group_invites SET uses = uses + 1 WHERE token = $1",
            &[&token.as_slice()],
        )
        .map_err(db_err)?;

        let approval: bool = txn
            .query_one(
                "SELECT join_approval FROM conversations WHERE conversation_id = $1",
                &[&conversation_id.as_slice()],
            )
            .map_err(db_err)?
            .get(0);
        if approval {
            txn.execute(
                "INSERT INTO group_join_requests (conversation_id, account_id) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
                &[&conversation_id.as_slice(), &joiner.as_bytes()],
            )
            .map_err(db_err)?;
            txn.commit().map_err(db_err)?;
            return Ok(InviteOutcome::Requested { conversation_id });
        }
        txn.commit().map_err(db_err)?;
        Ok(InviteOutcome::Joined { conversation_id })
    }

    // ----- join requests -------------------------------------------------------------

    /// Pending join requests (account ids, oldest first).
    pub fn list_join_requests(&self, conversation_id: &[u8; 16]) -> StoreResult<Vec<[u8; 16]>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT account_id FROM group_join_requests
                 WHERE conversation_id = $1 ORDER BY requested_at",
                &[&conversation_id.as_slice()],
            )
            .map_err(db_err)?;
        rows.into_iter().map(|r| id16(r.get(0))).collect()
    }

    /// Approve a pending request: re-checks blocks at approval time (they may have appeared since
    /// the request), removes the request, and reports whether the caller should add the joiner to
    /// routing. Returns false if there was no request or a block now bars entry.
    pub fn approve_join_request(
        &self,
        conversation_id: &[u8; 16],
        account: &AccountId,
    ) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        let existed = txn
            .execute(
                "DELETE FROM group_join_requests WHERE conversation_id = $1 AND account_id = $2",
                &[&conversation_id.as_slice(), &account.as_bytes()],
            )
            .map_err(db_err)?;
        if existed == 0 {
            return Ok(false);
        }
        let blocked = txn
            .query_opt(
                "SELECT 1 FROM blocks b
                 WHERE (b.blocker = $2 AND b.blocked IN (
                            SELECT account_id FROM conversation_members WHERE conversation_id = $1))
                    OR (b.blocked = $2 AND b.blocker IN (
                            SELECT account_id FROM conversation_members WHERE conversation_id = $1))",
                &[&conversation_id.as_slice(), &account.as_bytes()],
            )
            .map_err(db_err)?
            .is_some();
        if blocked {
            txn.commit().map_err(db_err)?; // request stays consumed
            return Ok(false);
        }
        txn.commit().map_err(db_err)?;
        Ok(true)
    }

    /// Deny (drop) a pending request. Idempotent.
    pub fn deny_join_request(
        &self,
        conversation_id: &[u8; 16],
        account: &AccountId,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "DELETE FROM group_join_requests WHERE conversation_id = $1 AND account_id = $2",
            &[&conversation_id.as_slice(), &account.as_bytes()],
        )
        .map_err(db_err)?;
        Ok(())
    }

    // ----- membership exit (leave / admin removal) -----------------------------------

    /// Leave a conversation (or, via `remove_member`, be removed): removes ALL of the account's
    /// devices from routing, purges their queued undelivered envelopes, drops their admin role,
    /// auto-promotes the earliest member if no admin remains, and deletes the conversation when
    /// empty. One transaction; idempotent.
    pub fn leave_conversation(
        &self,
        conversation_id: &[u8; 16],
        account: &AccountId,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        txn.execute(
            "DELETE FROM envelopes
             WHERE conversation_id = $1 AND NOT delivered
               AND recipient_device IN (
                   SELECT device_id FROM conversation_members
                   WHERE conversation_id = $1 AND account_id = $2)",
            &[&conversation_id.as_slice(), &account.as_bytes()],
        )
        .map_err(db_err)?;
        txn.execute(
            "DELETE FROM conversation_members WHERE conversation_id = $1 AND account_id = $2",
            &[&conversation_id.as_slice(), &account.as_bytes()],
        )
        .map_err(db_err)?;
        txn.execute(
            "DELETE FROM group_admins WHERE conversation_id = $1 AND account_id = $2",
            &[&conversation_id.as_slice(), &account.as_bytes()],
        )
        .map_err(db_err)?;

        let remaining: i64 = txn
            .query_one(
                "SELECT count(*) FROM conversation_members WHERE conversation_id = $1",
                &[&conversation_id.as_slice()],
            )
            .map_err(db_err)?
            .get(0);
        if remaining == 0 {
            txn.execute(
                "DELETE FROM envelopes WHERE conversation_id = $1",
                &[&conversation_id.as_slice()],
            )
            .map_err(db_err)?;
            txn.execute(
                "DELETE FROM conversations WHERE conversation_id = $1",
                &[&conversation_id.as_slice()],
            )
            .map_err(db_err)?;
        } else {
            // Never leave a populated group unmanageable: promote the earliest member if no
            // admin remains (deterministic tiebreak on account id).
            let admins: i64 = txn
                .query_one(
                    "SELECT count(*) FROM group_admins WHERE conversation_id = $1",
                    &[&conversation_id.as_slice()],
                )
                .map_err(db_err)?
                .get(0);
            if admins == 0 {
                txn.execute(
                    "INSERT INTO group_admins (conversation_id, account_id)
                     SELECT conversation_id, account_id FROM conversation_members
                     WHERE conversation_id = $1
                     ORDER BY added_at, account_id LIMIT 1
                     ON CONFLICT DO NOTHING",
                    &[&conversation_id.as_slice()],
                )
                .map_err(db_err)?;
            }
        }
        txn.commit().map_err(db_err)?;
        Ok(())
    }

    /// Record the creator as the first admin of a conversation. Idempotent.
    pub fn bootstrap_admin(
        &self,
        conversation_id: &[u8; 16],
        creator: &AccountId,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO group_admins (conversation_id, account_id) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
            &[&conversation_id.as_slice(), &creator.as_bytes()],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// True iff a block (either direction) exists between `account` and any current member.
    pub fn blocked_against_members(
        &self,
        conversation_id: &[u8; 16],
        account: &AccountId,
    ) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        Ok(conn
            .query_opt(
                "SELECT 1 FROM blocks b
                 WHERE (b.blocker = $2 AND b.blocked IN (
                            SELECT account_id FROM conversation_members WHERE conversation_id = $1))
                    OR (b.blocked = $2 AND b.blocker IN (
                            SELECT account_id FROM conversation_members WHERE conversation_id = $1))",
                &[&conversation_id.as_slice(), &account.as_bytes()],
            )
            .map_err(db_err)?
            .is_some())
    }

    /// The device ids to which `account` is routed in this conversation (empty if not a member).
    pub fn member_devices(
        &self,
        conversation_id: &[u8; 16],
        account: &AccountId,
    ) -> StoreResult<Vec<DeviceId>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT device_id FROM conversation_members
                 WHERE conversation_id = $1 AND account_id = $2",
                &[&conversation_id.as_slice(), &account.as_bytes()],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| Ok(DeviceId(id16(r.get(0))?)))
            .collect()
    }
}
