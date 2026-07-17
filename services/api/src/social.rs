//! Profiles, the friendship graph, and friend requests. All of this is social/routing
//! metadata — never message content. The friendship graph gates group creation: a group can
//! only be formed among people who are ALL mutually friends (a complete clique).

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

    /// True iff EVERY pair among `members` is friends (a complete clique). One query:
    /// count the friendships whose both endpoints are in the set and compare to C(n,2).
    /// This is the gate for group creation — a group only forms among people who have all
    /// added each other.
    pub fn all_mutually_friends(&self, members: &[AccountId]) -> StoreResult<bool> {
        let n = members.len();
        if n < 2 {
            return Ok(true); // 0 or 1 member: trivially a clique
        }
        let ids: Vec<&[u8]> = members.iter().map(|m| m.as_bytes()).collect();
        let mut conn = self.conn()?;
        let row = conn
            .query_one(
                "SELECT count(*) FROM friendships
                 WHERE account_lo = ANY($1) AND account_hi = ANY($1)",
                &[&ids],
            )
            .map_err(db_err)?;
        let edges: i64 = row.get(0);
        let required = (n as i64) * (n as i64 - 1) / 2;
        Ok(edges == required)
    }
}
