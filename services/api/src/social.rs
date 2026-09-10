//! Profiles, friendship graph, requests, blocking, reporting — social/routing metadata, never
//! message content. Group creation requires no friend clique (ADR-0009): any members may be
//! grouped provided no pair has blocked each other (`any_block_within`).

use auth_core::ids::AccountId;
use auth_core::store::{StoreError, StoreResult};
use r2d2_postgres::postgres::NoTls;

use crate::pgstore::PgPool;

#[derive(Clone)]
pub struct PgSocial {
    pool: PgPool,
}

/// A public profile view (safe to show to another user).
pub struct Profile {
    pub account_id: [u8; 16],
    pub username: String,
    pub display_name: String,
    pub bio: String,
}

/// A compact profile summary for lists and search results.
pub struct ProfileSummary {
    pub account_id: [u8; 16],
    pub username: String,
    pub display_name: String,
}

/// Outcome of sending a friend request.
#[derive(Debug, PartialEq, Eq)]
pub enum FriendRequestOutcome {
    /// A pending request was created (the other side must accept).
    Requested,
    /// The other side had already requested us, so we are now friends.
    Friended,
    /// Already friends; nothing to do.
    AlreadyFriends,
    /// A block exists between the two accounts (either direction); the request is refused.
    Blocked,
}

fn db_err(e: postgres::Error) -> StoreError {
    StoreError(format!("social db: {e}"))
}

fn id16(bytes: &[u8]) -> StoreResult<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| StoreError("bad id length".into()))
}

/// Canonical (lo, hi) ordering for a friendship pair.
fn canon(a: [u8; 16], b: [u8; 16]) -> ([u8; 16], [u8; 16]) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// A stable advisory-lock key for an account PAIR, derived from the canonical ordering so both
/// directions map to the same key.
///
/// `blocks` and `friendships` are different tables, so no row lock covers the invariant "a pair is
/// never both blocked and friends". At READ COMMITTED neither transaction sees the other's
/// uncommitted write, so a block and a friendship can commit concurrently, each blind to the other
/// — write skew, which only SERIALIZABLE or an explicit lock prevents. Advisory locks are already
/// this codebase's tool for exactly this shape of problem (`transparency.rs` serializes log
/// appends the same way).
///
/// A 64-bit key over a 256-bit input can collide between unrelated pairs. That is harmless: a
/// collision only makes two unrelated pairs take turns, it can never let a pair skip the lock.
fn pair_lock_key(a: [u8; 16], b: [u8; 16]) -> i64 {
    let (lo, hi) = canon(a, b);
    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(&lo);
    buf[16..].copy_from_slice(&hi);
    i64::from_be_bytes(
        auth_core::crypto::sha256(&buf)[..8]
            .try_into()
            .expect("8 bytes"),
    )
}

/// Serialize every social mutation for one pair. Held until the transaction ends.
fn lock_pair(txn: &mut postgres::Transaction<'_>, a: [u8; 16], b: [u8; 16]) -> StoreResult<()> {
    txn.execute("SELECT pg_advisory_xact_lock($1)", &[&pair_lock_key(a, b)])
        .map_err(db_err)?;
    Ok(())
}

impl PgSocial {
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

    // ----- profiles -----------------------------------------------------------------

    pub fn upsert_profile(
        &self,
        account: &AccountId,
        display_name: &str,
        bio: &str,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO profiles (account_id, display_name, bio, updated_at)
             VALUES ($1, $2, $3, now())
             ON CONFLICT (account_id)
             DO UPDATE SET display_name = EXCLUDED.display_name, bio = EXCLUDED.bio,
                           updated_at = now()",
            &[&account.as_bytes(), &display_name, &bio],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn get_profile(&self, account: &AccountId) -> StoreResult<Option<Profile>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT a.account_id, a.username_normalized,
                        COALESCE(p.display_name, ''), COALESCE(p.bio, '')
                 FROM accounts a LEFT JOIN profiles p USING (account_id)
                 WHERE a.account_id = $1",
                &[&account.as_bytes()],
            )
            .map_err(db_err)?;
        row.map(|r| {
            Ok(Profile {
                account_id: id16(r.get::<_, &[u8]>(0))?,
                username: r.get(1),
                display_name: r.get(2),
                bio: r.get(3),
            })
        })
        .transpose()
    }

    /// Prefix search over usernames (the stable discovery handle). Deliberately not a
    /// substring/bulk scan; callers enforce a minimum query length and the route is
    /// rate-limited.
    pub fn search_profiles(&self, prefix: &str, limit: i64) -> StoreResult<Vec<ProfileSummary>> {
        let mut conn = self.conn()?;
        // Escape LIKE metacharacters in the user input, then anchor as a prefix.
        let escaped = prefix
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("{escaped}%");
        let rows = conn
            .query(
                "SELECT a.account_id, a.username_normalized, COALESCE(p.display_name, '')
                 FROM accounts a LEFT JOIN profiles p USING (account_id)
                 WHERE a.username_normalized LIKE $1
                 ORDER BY a.username_normalized
                 LIMIT $2",
                &[&pattern, &limit],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| {
                Ok(ProfileSummary {
                    account_id: id16(r.get::<_, &[u8]>(0))?,
                    username: r.get(1),
                    display_name: r.get(2),
                })
            })
            .collect()
    }

    // ----- friendships --------------------------------------------------------------

    pub fn are_friends(&self, a: &AccountId, b: &AccountId) -> StoreResult<bool> {
        let (lo, hi) = canon(a.0, b.0);
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT 1 FROM friendships WHERE account_lo = $1 AND account_hi = $2",
                &[&lo.as_slice(), &hi.as_slice()],
            )
            .map_err(db_err)?;
        Ok(row.is_some())
    }

    /// Send a friend request. If the other side already requested us, this auto-accepts
    /// (both added each other). All-in-one transaction.
    pub fn send_friend_request(
        &self,
        from: &AccountId,
        to: &AccountId,
    ) -> StoreResult<FriendRequestOutcome> {
        if from.0 == to.0 {
            return Err(StoreError("cannot friend self".into()));
        }
        let (lo, hi) = canon(from.0, to.0);
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        // Serialize against a concurrent block(): without this the block check below and the
        // friendship INSERT straddle a window in which a block can commit unseen.
        lock_pair(&mut txn, from.0, to.0)?;

        // Refuse if either party has blocked the other (dropping the txn rolls back).
        if txn
            .query_opt(
                "SELECT 1 FROM blocks
                 WHERE (blocker = $1 AND blocked = $2) OR (blocker = $2 AND blocked = $1)",
                &[&from.as_bytes(), &to.as_bytes()],
            )
            .map_err(db_err)?
            .is_some()
        {
            return Ok(FriendRequestOutcome::Blocked);
        }

        // Already friends?
        if txn
            .query_opt(
                "SELECT 1 FROM friendships WHERE account_lo = $1 AND account_hi = $2",
                &[&lo.as_slice(), &hi.as_slice()],
            )
            .map_err(db_err)?
            .is_some()
        {
            return Ok(FriendRequestOutcome::AlreadyFriends);
        }

        // Reverse request pending? -> auto-accept.
        let reverse = txn
            .query_opt(
                "SELECT 1 FROM friend_requests WHERE from_account = $1 AND to_account = $2",
                &[&to.as_bytes(), &from.as_bytes()],
            )
            .map_err(db_err)?
            .is_some();

        if reverse {
            txn.execute(
                "INSERT INTO friendships (account_lo, account_hi) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
                &[&lo.as_slice(), &hi.as_slice()],
            )
            .map_err(db_err)?;
            txn.execute(
                "DELETE FROM friend_requests
                 WHERE (from_account = $1 AND to_account = $2)
                    OR (from_account = $2 AND to_account = $1)",
                &[&from.as_bytes(), &to.as_bytes()],
            )
            .map_err(db_err)?;
            txn.commit().map_err(db_err)?;
            return Ok(FriendRequestOutcome::Friended);
        }

        txn.execute(
            "INSERT INTO friend_requests (from_account, to_account) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
            &[&from.as_bytes(), &to.as_bytes()],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(FriendRequestOutcome::Requested)
    }

    /// Accept a pending request from `other` to `me`. Returns false if no such request.
    pub fn accept_friend_request(&self, me: &AccountId, other: &AccountId) -> StoreResult<bool> {
        let (lo, hi) = canon(me.0, other.0);
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        lock_pair(&mut txn, me.0, other.0)?;

        // Blocks MUST be re-checked here. This path previously relied entirely on `block()` having
        // already deleted the pending request, which is not an invariant: a block committing around
        // this accept would leave the pair both blocked and friends, and the friendship is a live
        // authorization credential (`are_friends` gates `add_member`).
        if txn
            .query_opt(
                "SELECT 1 FROM blocks
                 WHERE (blocker = $1 AND blocked = $2) OR (blocker = $2 AND blocked = $1)",
                &[&me.as_bytes(), &other.as_bytes()],
            )
            .map_err(db_err)?
            .is_some()
        {
            return Ok(false);
        }

        let deleted = txn
            .execute(
                "DELETE FROM friend_requests WHERE from_account = $1 AND to_account = $2",
                &[&other.as_bytes(), &me.as_bytes()],
            )
            .map_err(db_err)?;
        if deleted == 0 {
            return Ok(false);
        }
        // Remove any request the other direction too, then create the friendship.
        txn.execute(
            "DELETE FROM friend_requests WHERE from_account = $1 AND to_account = $2",
            &[&me.as_bytes(), &other.as_bytes()],
        )
        .map_err(db_err)?;
        txn.execute(
            "INSERT INTO friendships (account_lo, account_hi) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
            &[&lo.as_slice(), &hi.as_slice()],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(true)
    }

    /// Decline/cancel any pending request between `me` and `other` (either direction).
    pub fn cancel_request(&self, me: &AccountId, other: &AccountId) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "DELETE FROM friend_requests
             WHERE (from_account = $1 AND to_account = $2)
                OR (from_account = $2 AND to_account = $1)",
            &[&me.as_bytes(), &other.as_bytes()],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn remove_friend(&self, me: &AccountId, other: &AccountId) -> StoreResult<()> {
        let (lo, hi) = canon(me.0, other.0);
        let mut conn = self.conn()?;
        conn.execute(
            "DELETE FROM friendships WHERE account_lo = $1 AND account_hi = $2",
            &[&lo.as_slice(), &hi.as_slice()],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn list_friends(&self, me: &AccountId) -> StoreResult<Vec<ProfileSummary>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT a.account_id, a.username_normalized, COALESCE(p.display_name, '')
                 FROM friendships f
                 JOIN accounts a ON a.account_id =
                     CASE WHEN f.account_lo = $1 THEN f.account_hi ELSE f.account_lo END
                 LEFT JOIN profiles p ON p.account_id = a.account_id
                 WHERE f.account_lo = $1 OR f.account_hi = $1
                 ORDER BY a.username_normalized",
                &[&me.as_bytes()],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| {
                Ok(ProfileSummary {
                    account_id: id16(r.get::<_, &[u8]>(0))?,
                    username: r.get(1),
                    display_name: r.get(2),
                })
            })
            .collect()
    }

    pub fn list_incoming_requests(&self, me: &AccountId) -> StoreResult<Vec<ProfileSummary>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT a.account_id, a.username_normalized, COALESCE(p.display_name, '')
                 FROM friend_requests r
                 JOIN accounts a ON a.account_id = r.from_account
                 LEFT JOIN profiles p ON p.account_id = a.account_id
                 WHERE r.to_account = $1
                 ORDER BY r.created_at",
                &[&me.as_bytes()],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| {
                Ok(ProfileSummary {
                    account_id: id16(r.get::<_, &[u8]>(0))?,
                    username: r.get(1),
                    display_name: r.get(2),
                })
            })
            .collect()
    }

    // ----- blocks --------------------------------------------------------------------

    /// Block `blocked`: record the block and, atomically, drop any existing friendship and pending
    /// requests in either direction. Idempotent.
    pub fn block(&self, blocker: &AccountId, blocked: &AccountId) -> StoreResult<()> {
        if blocker.0 == blocked.0 {
            return Err(StoreError("cannot block self".into()));
        }
        let (lo, hi) = canon(blocker.0, blocked.0);
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        // Same pair lock the friendship paths take, so "insert block, then tear down friendship
        // and requests" cannot interleave with a friendship being created underneath it.
        lock_pair(&mut txn, blocker.0, blocked.0)?;
        txn.execute(
            "INSERT INTO blocks (blocker, blocked) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&blocker.as_bytes(), &blocked.as_bytes()],
        )
        .map_err(db_err)?;
        txn.execute(
            "DELETE FROM friendships WHERE account_lo = $1 AND account_hi = $2",
            &[&lo.as_slice(), &hi.as_slice()],
        )
        .map_err(db_err)?;
        txn.execute(
            "DELETE FROM friend_requests
             WHERE (from_account = $1 AND to_account = $2)
                OR (from_account = $2 AND to_account = $1)",
            &[&blocker.as_bytes(), &blocked.as_bytes()],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(())
    }

    /// Remove a block `blocker` placed on `blocked`. Idempotent. Does not restore prior friendship.
    pub fn unblock(&self, blocker: &AccountId, blocked: &AccountId) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "DELETE FROM blocks WHERE blocker = $1 AND blocked = $2",
            &[&blocker.as_bytes(), &blocked.as_bytes()],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// True iff a block exists in either direction between the two accounts.
    pub fn is_blocked_between(&self, a: &AccountId, b: &AccountId) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        Ok(conn
            .query_opt(
                "SELECT 1 FROM blocks
                 WHERE (blocker = $1 AND blocked = $2) OR (blocker = $2 AND blocked = $1)",
                &[&a.as_bytes(), &b.as_bytes()],
            )
            .map_err(db_err)?
            .is_some())
    }

    /// Accounts `me` has blocked, most recent first.
    pub fn list_blocked(&self, me: &AccountId) -> StoreResult<Vec<ProfileSummary>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT a.account_id, a.username_normalized, COALESCE(p.display_name, '')
                 FROM blocks b
                 JOIN accounts a ON a.account_id = b.blocked
                 LEFT JOIN profiles p ON p.account_id = a.account_id
                 WHERE b.blocker = $1
                 ORDER BY b.created_at DESC",
                &[&me.as_bytes()],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| {
                Ok(ProfileSummary {
                    account_id: id16(r.get::<_, &[u8]>(0))?,
                    username: r.get(1),
                    display_name: r.get(2),
                })
            })
            .collect()
    }

    // ----- message requests ----------------------------------------------------------

    /// A sender may have at most this many pending outbound requests at once — a coarse anti-spam
    /// cap on top of the per-route rate limiter, so one account cannot paper the whole app with
    /// requests even slowly.
    pub const MAX_PENDING_OUTBOUND_REQUESTS: i64 = 20;

    /// True iff `from` already has a pending request to `to` — one outstanding request per pair, so
    /// a re-send is a no-op rather than a second row.
    pub fn message_request_pending(&self, from: &AccountId, to: &AccountId) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        Ok(conn
            .query_opt(
                "SELECT 1 FROM message_requests
                 WHERE from_account = $1 AND to_account = $2 AND status = 'pending'",
                &[&from.as_bytes(), &to.as_bytes()],
            )
            .map_err(db_err)?
            .is_some())
    }

    /// How many pending requests `from` currently has outstanding (for the anti-spam cap).
    pub fn pending_outbound_request_count(&self, from: &AccountId) -> StoreResult<i64> {
        let mut conn = self.conn()?;
        Ok(conn
            .query_one(
                "SELECT count(*) FROM message_requests
                 WHERE from_account = $1 AND status = 'pending'",
                &[&from.as_bytes()],
            )
            .map_err(db_err)?
            .get::<_, i64>(0))
    }

    /// Record a new pending request for the conversation `from` just created toward `to`.
    pub fn insert_message_request(
        &self,
        conversation_id: &[u8; 16],
        from: &AccountId,
        to: &AccountId,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO message_requests (conversation_id, from_account, to_account)
             VALUES ($1, $2, $3)",
            &[
                &conversation_id.as_slice(),
                &from.as_bytes(),
                &to.as_bytes(),
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// The pending requests addressed to `me`, newest first: (conversation_id, from_account, from
    /// username, from display name) so the folder can name who is asking without a second lookup.
    pub fn incoming_message_requests(
        &self,
        me: &AccountId,
    ) -> StoreResult<Vec<([u8; 16], ProfileSummary)>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT r.conversation_id, a.account_id, a.username_normalized,
                        COALESCE(p.display_name, '')
                 FROM message_requests r
                 JOIN accounts a ON a.account_id = r.from_account
                 LEFT JOIN profiles p ON p.account_id = a.account_id
                 WHERE r.to_account = $1 AND r.status = 'pending'
                 ORDER BY r.created_at DESC",
                &[&me.as_bytes()],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| {
                Ok((
                    id16(r.get::<_, &[u8]>(0))?,
                    ProfileSummary {
                        account_id: id16(r.get::<_, &[u8]>(1))?,
                        username: r.get(2),
                        display_name: r.get(3),
                    },
                ))
            })
            .collect()
    }

    /// The (from, to, status) of a request conversation, if it is one.
    pub fn message_request(
        &self,
        conversation_id: &[u8; 16],
    ) -> StoreResult<Option<(AccountId, AccountId, String)>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT from_account, to_account, status FROM message_requests
                 WHERE conversation_id = $1",
                &[&conversation_id.as_slice()],
            )
            .map_err(db_err)?;
        match row {
            None => Ok(None),
            Some(r) => Ok(Some((
                AccountId(id16(r.get::<_, &[u8]>(0))?),
                AccountId(id16(r.get::<_, &[u8]>(1))?),
                r.get(2),
            ))),
        }
    }

    /// Accept the request `me` received on `conversation_id`: mark it accepted AND create the
    /// friendship (so everything onward is an ordinary conversation between friends). Returns false
    /// if there is no such pending request addressed to `me`, or a block stands between the pair.
    /// First-writer-wins on the status flip, like the report resolver.
    pub fn accept_message_request(
        &self,
        me: &AccountId,
        conversation_id: &[u8; 16],
    ) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        let row = txn
            .query_opt(
                "SELECT from_account FROM message_requests
                 WHERE conversation_id = $1 AND to_account = $2 AND status = 'pending'
                 FOR UPDATE",
                &[&conversation_id.as_slice(), &me.as_bytes()],
            )
            .map_err(db_err)?;
        let Some(row) = row else { return Ok(false) };
        let from = AccountId(id16(row.get::<_, &[u8]>(0))?);
        // A block placed while the request sat pending must win — never befriend across a block.
        if txn
            .query_opt(
                "SELECT 1 FROM blocks
                 WHERE (blocker = $1 AND blocked = $2) OR (blocker = $2 AND blocked = $1)",
                &[&me.as_bytes(), &from.as_bytes()],
            )
            .map_err(db_err)?
            .is_some()
        {
            return Ok(false);
        }
        txn.execute(
            "UPDATE message_requests SET status = 'accepted' WHERE conversation_id = $1",
            &[&conversation_id.as_slice()],
        )
        .map_err(db_err)?;
        let (lo, hi) = canon(me.0, from.0);
        txn.execute(
            "INSERT INTO friendships (account_lo, account_hi) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
            &[&lo.as_slice(), &hi.as_slice()],
        )
        .map_err(db_err)?;
        // Any leftover friend request between the two is now redundant.
        txn.execute(
            "DELETE FROM friend_requests
             WHERE (from_account = $1 AND to_account = $2)
                OR (from_account = $2 AND to_account = $1)",
            &[&me.as_bytes(), &from.as_bytes()],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(true)
    }

    /// Decline the request `me` received on `conversation_id`: mark it declined. Returns the sender
    /// account (so the caller can also drop `me` from the conversation, and block if asked), or
    /// None if there was no pending request addressed to `me`.
    pub fn decline_message_request(
        &self,
        me: &AccountId,
        conversation_id: &[u8; 16],
    ) -> StoreResult<Option<AccountId>> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        let row = txn
            .query_opt(
                "SELECT from_account FROM message_requests
                 WHERE conversation_id = $1 AND to_account = $2 AND status = 'pending'
                 FOR UPDATE",
                &[&conversation_id.as_slice(), &me.as_bytes()],
            )
            .map_err(db_err)?;
        let Some(row) = row else { return Ok(None) };
        let from = AccountId(id16(row.get::<_, &[u8]>(0))?);
        txn.execute(
            "UPDATE message_requests SET status = 'declined' WHERE conversation_id = $1",
            &[&conversation_id.as_slice()],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(Some(from))
    }

    // ----- reports -------------------------------------------------------------------

    /// Record a user report. `evidence` is only what the reporter chose to submit (the server
    /// cannot read E2EE content). Returns the new report id.
    pub fn create_report(
        &self,
        reporter: &AccountId,
        reported: &AccountId,
        reason: &str,
        evidence: Option<&str>,
    ) -> StoreResult<i64> {
        let mut conn = self.conn()?;
        let row = conn
            .query_one(
                "INSERT INTO reports (reporter, reported, reason, evidence)
                 VALUES ($1, $2, $3, $4) RETURNING id",
                &[
                    &reporter.as_bytes(),
                    &reported.as_bytes(),
                    &reason,
                    &evidence,
                ],
            )
            .map_err(db_err)?;
        Ok(row.get(0))
    }

    /// True iff a block (either direction) exists between two accounts that are BOTH in `members`.
    /// ADR-0009 replaces the old full-friend-clique rule: group membership no longer requires
    /// friendship, only the absence of a block within the group — a group must never force together
    /// a pair that has blocked each other. One query: count blocks whose both endpoints are in set.
    pub fn any_block_within(&self, members: &[AccountId]) -> StoreResult<bool> {
        if members.len() < 2 {
            return Ok(false);
        }
        let ids: Vec<&[u8]> = members.iter().map(|m| m.as_bytes()).collect();
        let mut conn = self.conn()?;
        let row = conn
            .query_one(
                "SELECT count(*) FROM blocks WHERE blocker = ANY($1) AND blocked = ANY($1)",
                &[&ids],
            )
            .map_err(db_err)?;
        let n: i64 = row.get(0);
        Ok(n > 0)
    }
}
