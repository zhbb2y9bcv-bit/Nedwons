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

/// A stable advisory-lock key for one conversation's governance state.
///
/// The "never zero admins" and "never an orphan conversation" rules are both `count(*)`-then-act,
/// and at READ COMMITTED a count is not a reservation. Two demotions of two DIFFERENT admins touch
/// different rows, so no row-level conflict ever arises and both commit against the same stale
/// count — leaving a populated group unmanageable, permanently, because `promote` itself requires
/// an existing admin. Row locks cannot fix this: the danger is a phantom (the set changing size),
/// not one contended row.
///
/// So governance mutations serialize per conversation, using the same `pg_advisory_xact_lock`
/// idiom `transparency.rs` uses for gapless appends. The lock is held until the transaction ends,
/// and different conversations never contend.
fn conversation_lock_key(conversation_id: &[u8; 16]) -> i64 {
    i64::from_be_bytes(
        auth_core::crypto::sha256(conversation_id)[..8]
            .try_into()
            .expect("8 bytes"),
    )
}

fn lock_conversation(
    txn: &mut postgres::Transaction<'_>,
    conversation_id: &[u8; 16],
) -> StoreResult<()> {
    txn.execute(
        "SELECT pg_advisory_xact_lock($1)",
        &[&conversation_lock_key(conversation_id)],
    )
    .map_err(db_err)?;
    Ok(())
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

/// Outcome of muting a member.
#[derive(Debug, PartialEq, Eq)]
pub enum MuteOutcome {
    Muted,
    /// The target is not in this conversation.
    NotMember,
    /// The target administers this group. Refused rather than silently demoting them: taking
    /// someone's role is a separate decision from silencing them, and an admin who could be muted
    /// by a peer could be locked out of the group they administer.
    TargetIsAdmin,
}

/// One member as the group's admin panel renders it. Account-level (roles and mutes are
/// account-scoped), so an account with several linked devices appears once.
pub struct MemberSummary {
    pub account_id: [u8; 16],
    /// Empty when the account has no profile row yet — never `NULL` to the caller.
    pub username: String,
    pub display_name: String,
    pub is_admin: bool,
    /// Present iff a mute is in force right now. `None` inside `Some` = indefinite.
    pub mute: Option<MuteState>,
}

/// A mute in force, as shown next to a member.
pub struct MuteState {
    pub muted_by: [u8; 16],
    pub muted_at_unix: i64,
    /// `None` = until an admin lifts it.
    pub expires_at_unix: Option<i64>,
}

/// Group-level settings an admin controls.
pub struct GroupSettings {
    pub join_approval: bool,
    pub announcements_only: bool,
    pub mls_authoritative: bool,
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
        // Same governance lock as demote/leave: the membership check below and the admin INSERT
        // must not straddle a concurrent removal, which would leave an admin who is not a member.
        lock_conversation(&mut txn, conversation_id)?;
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
        // Without this, concurrent demotions of two different admins both pass the last-admin
        // guard below and both commit, zeroing the admin set.
        lock_conversation(&mut txn, conversation_id)?;
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

    // ----- moderation: mutes and announcement mode -----------------------------------
    //
    // A mute is a relay-enforced SEND PERMISSION, not a cryptographic one — see the header of
    // `V25__group_moderation.sql`. The gate that consumes these rows lives in `relay.rs`, on both
    // paths that accept caller-supplied ciphertext for a conversation.

    /// Toggle announcement mode: when on, only admins may send into the conversation.
    ///
    /// `FOR UPDATE` on the conversation row is what makes the flip take effect atomically with
    /// respect to sends: the send gate reads the same row `FOR SHARE`, so a message that started
    /// before the flip finishes first and one that starts after sees the new mode. Without the
    /// lock, a send in flight at READ COMMITTED could read the old value and deliver after the
    /// admin had been told the group was locked.
    pub fn set_announcements_only(&self, conversation_id: &[u8; 16], on: bool) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        lock_conversation(&mut txn, conversation_id)?;
        txn.query_opt(
            "SELECT 1 FROM conversations WHERE conversation_id = $1 FOR UPDATE",
            &[&conversation_id.as_slice()],
        )
        .map_err(db_err)?;
        txn.execute(
            "UPDATE conversations SET announcements_only = $2 WHERE conversation_id = $1",
            &[&conversation_id.as_slice(), &on],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(())
    }

    /// Mute one member. `expires_in_secs = None` mutes until an admin lifts it. Re-muting an
    /// already-muted member replaces the expiry, so "extend to 8 hours" needs no unmute first.
    ///
    /// Caller must have verified the actor's adminship.
    pub fn mute_member(
        &self,
        conversation_id: &[u8; 16],
        target: &AccountId,
        actor: &AccountId,
        expires_in_secs: Option<i64>,
    ) -> StoreResult<MuteOutcome> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        // The same governance serializer promote/demote/leave use. The membership and adminship
        // checks below are reads that authorize a write; a concurrent promotion between them and
        // the INSERT would produce a muted admin, which the schema then rejects with an
        // exception — a 500 where the honest answer is 409. Holding the lock turns that race into
        // an ordering.
        lock_conversation(&mut txn, conversation_id)?;
        // Lock the target's routing rows too, in the same order `leave_conversation` takes them
        // (members before conversations), so a message already in flight from this account
        // completes before the mute lands rather than being half-applied.
        let member = !txn
            .query(
                "SELECT 1 FROM conversation_members
                 WHERE conversation_id = $1 AND account_id = $2 FOR UPDATE",
                &[&conversation_id.as_slice(), &target.as_bytes()],
            )
            .map_err(db_err)?
            .is_empty();
        if !member {
            return Ok(MuteOutcome::NotMember);
        }
        if Self::is_admin_in_txn(&mut txn, conversation_id, target)? {
            return Ok(MuteOutcome::TargetIsAdmin);
        }
        txn.execute(
            "INSERT INTO group_mutes (conversation_id, account_id, muted_by, expires_at)
             VALUES ($1, $2, $3, CASE WHEN $4::double precision IS NULL THEN NULL
                                      ELSE now() + ($4 * interval '1 second') END)
             ON CONFLICT (conversation_id, account_id) DO UPDATE
                 SET muted_by = EXCLUDED.muted_by,
                     muted_at = now(),
                     expires_at = EXCLUDED.expires_at",
            &[
                &conversation_id.as_slice(),
                &target.as_bytes(),
                &actor.as_bytes(),
                &expires_in_secs.map(|s| s as f64),
            ],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(MuteOutcome::Muted)
    }

    /// Lift a mute. Idempotent: unmuting someone who is not muted is a no-op, so a retry after a
    /// lost response cannot fail. Returns whether a mute was actually lifted (for the audit line,
    /// never for authorization).
    pub fn unmute_member(
        &self,
        conversation_id: &[u8; 16],
        target: &AccountId,
    ) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        lock_conversation(&mut txn, conversation_id)?;
        let lifted = txn
            .execute(
                "DELETE FROM group_mutes WHERE conversation_id = $1 AND account_id = $2",
                &[&conversation_id.as_slice(), &target.as_bytes()],
            )
            .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(lifted > 0)
    }

    /// Lift every mute in the conversation ("unmute everyone"). Returns how many were lifted.
    pub fn unmute_all(&self, conversation_id: &[u8; 16]) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        lock_conversation(&mut txn, conversation_id)?;
        let lifted = txn
            .execute(
                "DELETE FROM group_mutes WHERE conversation_id = $1",
                &[&conversation_id.as_slice()],
            )
            .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(lifted)
    }

    /// Group settings, or `None` if the conversation does not exist.
    pub fn settings(&self, conversation_id: &[u8; 16]) -> StoreResult<Option<GroupSettings>> {
        let mut conn = self.conn()?;
        Ok(conn
            .query_opt(
                "SELECT join_approval, announcements_only, mls_authoritative
                 FROM conversations WHERE conversation_id = $1",
                &[&conversation_id.as_slice()],
            )
            .map_err(db_err)?
            .map(|r| GroupSettings {
                join_approval: r.get(0),
                announcements_only: r.get(1),
                mls_authoritative: r.get(2),
            }))
    }

    /// Every member of a conversation, once per account, with role, live mute state, and the
    /// profile fields the server already stores in the clear (PRIVACY.md lists both). One query,
    /// so opening a group's admin panel costs a single round trip rather than one per member.
    ///
    /// Expired mutes are filtered here with the same `expires_at > now()` predicate the send gate
    /// uses, so the panel can never show a mute the gate no longer enforces.
    pub fn members(&self, conversation_id: &[u8; 16]) -> StoreResult<Vec<MemberSummary>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT DISTINCT ON (cm.account_id)
                        cm.account_id,
                        COALESCE(a.username_normalized, ''),
                        COALESCE(p.display_name, ''),
                        (ga.account_id IS NOT NULL),
                        gm.muted_by,
                        extract(epoch FROM gm.muted_at)::bigint,
                        extract(epoch FROM gm.expires_at)::bigint
                 FROM conversation_members cm
                 LEFT JOIN accounts a ON a.account_id = cm.account_id
                 LEFT JOIN profiles p ON p.account_id = cm.account_id
                 LEFT JOIN group_admins ga
                        ON ga.conversation_id = cm.conversation_id AND ga.account_id = cm.account_id
                 LEFT JOIN group_mutes gm
                        ON gm.conversation_id = cm.conversation_id AND gm.account_id = cm.account_id
                       AND (gm.expires_at IS NULL OR gm.expires_at > now())
                 WHERE cm.conversation_id = $1
                 ORDER BY cm.account_id, cm.added_at",
                &[&conversation_id.as_slice()],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| {
                let muted_by: Option<&[u8]> = r.get(4);
                let mute = match muted_by {
                    Some(by) => Some(MuteState {
                        muted_by: id16(by)?,
                        muted_at_unix: r.get::<_, Option<i64>>(5).unwrap_or(0),
                        expires_at_unix: r.get(6),
                    }),
                    None => None,
                };
                Ok(MemberSummary {
                    account_id: id16(r.get::<_, &[u8]>(0))?,
                    username: r.get(1),
                    display_name: r.get(2),
                    is_admin: r.get(3),
                    mute,
                })
            })
            .collect()
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
        let outcome = Self::accept_invite_in_txn(&mut txn, token, joiner)?;
        txn.commit().map_err(db_err)?;
        Ok(outcome)
    }

    /// As [`Self::accept_invite`], but joins a caller-owned transaction.
    ///
    /// This burns an invite USE. The caller must add the resulting routing membership in the SAME
    /// transaction: committed separately, a failure in between spends the joiner's one chance to
    /// join without joining them, and the invite's use budget is corrupted with nothing to show
    /// for it. Every `Refused` path returns before any write, so a caller committing after a
    /// refusal commits nothing.
    pub fn accept_invite_in_txn(
        txn: &mut postgres::Transaction<'_>,
        token: &[u8; 32],
        joiner: &AccountId,
    ) -> StoreResult<InviteOutcome> {
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
            return Ok(InviteOutcome::Requested { conversation_id });
        }
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
        let approved = Self::approve_join_request_in_txn(&mut txn, conversation_id, account)?;
        txn.commit().map_err(db_err)?;
        Ok(approved)
    }

    /// As [`Self::approve_join_request`], but joins a caller-owned transaction.
    ///
    /// This CONSUMES the pending request, so the caller must add the routing membership in the
    /// same transaction — otherwise a failure in between destroys the request without admitting
    /// the user, and there is no way to re-request except a fresh invite.
    ///
    /// The block path deliberately still consumes the request (returning `false`): an approval
    /// aimed at someone a member has blocked should not remain pending for a later retry. That is
    /// a policy choice, not an accident, and it survives the caller's commit.
    pub fn approve_join_request_in_txn(
        txn: &mut postgres::Transaction<'_>,
        conversation_id: &[u8; 16],
        account: &AccountId,
    ) -> StoreResult<bool> {
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
            return Ok(false); // request stays consumed
        }
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
        // This function is two count-then-act decisions — delete the conversation when the last
        // member leaves, and auto-promote when the last admin leaves. Both are phantom-sensitive,
        // so concurrent leaves could each see the other still present and neither clean up (an
        // orphan conversation with no members), or race a demotion to zero admins.
        lock_conversation(&mut txn, conversation_id)?;
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

    /// As [`Self::bootstrap_admin`], but joins a caller-owned transaction so the conversation and
    /// its first admin commit together. Separately committed, a failure in between leaves a
    /// conversation nobody can ever administer: `promote` requires an existing admin, and only a
    /// member LEAVING triggers auto-promotion.
    pub fn bootstrap_admin_in_txn(
        txn: &mut postgres::Transaction<'_>,
        conversation_id: &[u8; 16],
        creator: &AccountId,
    ) -> StoreResult<()> {
        txn.execute(
            "INSERT INTO group_admins (conversation_id, account_id) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
            &[&conversation_id.as_slice(), &creator.as_bytes()],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Adminship inside a caller-owned transaction, so an authorization check can share one
    /// transaction with the write it authorizes.
    pub fn is_admin_in_txn(
        txn: &mut postgres::Transaction<'_>,
        conversation_id: &[u8; 16],
        account: &AccountId,
    ) -> StoreResult<bool> {
        Ok(txn
            .query_opt(
                "SELECT 1 FROM group_admins WHERE conversation_id = $1 AND account_id = $2",
                &[&conversation_id.as_slice(), &account.as_bytes()],
            )
            .map_err(db_err)?
            .is_some())
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
