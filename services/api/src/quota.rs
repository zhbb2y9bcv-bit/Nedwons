//! Per-account abuse quotas, shared across API instances (R-306).
//!
//! The existing limiters are per-IP and per-process, and abuse control needs neither. A per-process
//! limiter multiplies by the instance count behind a load balancer and resets on deploy. A per-IP
//! limit is simultaneously too coarse (a carrier NAT shares one address, so one abuser throttles
//! thousands of bystanders) and too weak (addresses are cheap; rotating a proxy pool resets the
//! counter while the account doing the spamming is untouched).
//!
//! Accounts commit abuse, so accounts are what these quotas bound. The per-IP limiter stays as the
//! outer, pre-authentication guard — this is the inner one, applied once the caller is known.

use auth_core::ids::AccountId;
use auth_core::store::{StoreError, StoreResult};

use crate::pgstore::PgPool;

/// A named quota: `limit` events per `window_secs`, per subject.
#[derive(Clone, Copy)]
pub struct Quota {
    pub scope: &'static str,
    pub limit: i32,
    pub window_secs: i64,
}

impl Quota {
    pub const fn new(scope: &'static str, limit: i32, window_secs: i64) -> Self {
        Self {
            scope,
            limit,
            window_secs,
        }
    }
}

/// Outbound friend requests. Bounds the classic harassment pattern — spraying requests at strangers
/// — while leaving ordinary use (adding everyone you know in one sitting) untouched.
pub const FRIEND_REQUESTS: Quota = Quota::new("friend_request", 60, 3600);

/// Username searches. Discovery is username-only, so search is the ONLY enumeration surface: this
/// is what stops an authenticated account from harvesting the user list by walking prefixes.
pub const PROFILE_SEARCH: Quota = Quota::new("profile_search", 300, 3600);

/// Abuse reports. Reporting must stay easy and cheap for real users, but unbounded reporting is
/// itself an abuse vector (mass false reports to trigger moderation against a target).
pub const REPORTS: Quota = Quota::new("report", 30, 86_400);

/// Group invite creation. An invite token is a capability; unbounded minting turns one account into
/// a spam vector for whole groups.
pub const GROUP_INVITES: Quota = Quota::new("group_invite", 60, 3600);

/// Distributed fixed-window counters.
pub struct Quotas {
    pool: PgPool,
}

impl Quotas {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Consume one unit. `Ok(true)` when the caller is within quota, `Ok(false)` when they have
    /// exhausted it.
    ///
    /// The increment is a single `INSERT ... ON CONFLICT DO UPDATE ... RETURNING count`, so it
    /// takes the row lock and returns the post-increment value in one statement — concurrent
    /// racers on any instance serialize on that row and the count cannot drift.
    ///
    /// Deliberately counts the REFUSED attempt too. Someone hammering past their limit should not
    /// get a free retry every time they are refused; the window has to actually elapse.
    pub fn consume(&self, quota: Quota, subject: &[u8], now: i64) -> StoreResult<bool> {
        let window_start = now - now.rem_euclid(quota.window_secs);
        let mut conn = self
            .pool
            .get()
            .map_err(|e| StoreError(format!("pool: {e}")))?;
        let count: i32 = conn
            .query_one(
                "INSERT INTO rate_counters (scope, subject, window_start, count)
                 VALUES ($1, $2, $3, 1)
                 ON CONFLICT (scope, subject, window_start)
                 DO UPDATE SET count = rate_counters.count + 1
                 RETURNING count",
                &[&quota.scope, &subject, &window_start],
            )
            .map_err(|e| StoreError(format!("quota db: {e}")))?
            .get(0);
        Ok(count <= quota.limit)
    }

    /// Convenience for the common case: quotas are keyed by account.
    pub fn consume_account(
        &self,
        quota: Quota,
        account: &AccountId,
        now: i64,
    ) -> StoreResult<bool> {
        self.consume(quota, account.as_bytes(), now)
    }

    /// Drop windows that can no longer be current. Called by the retention sweep.
    pub fn purge_expired(&self, now: i64, max_window_secs: i64) -> StoreResult<u64> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| StoreError(format!("pool: {e}")))?;
        conn.execute(
            "DELETE FROM rate_counters WHERE window_start < $1",
            &[&(now - max_window_secs * 2)],
        )
        .map_err(|e| StoreError(format!("quota purge: {e}")))
    }
}
