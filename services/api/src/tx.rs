//! Cross-store transactions.
//!
//! Every store (`PgRelay`, `PgGroups`, `PgSocial`, `PgMembership`, `PgStores`) owns a private
//! `conn()` that checks out its own pooled connection. That makes a handler calling two stores
//! **two transactions by construction**, no matter how the calls are ordered, and no lock can
//! repair it: the first transaction is already committed and visible before the second begins.
//!
//! Concretely, that shape produced three defects:
//!
//! * `create_conversation` committed the conversation, then bootstrapped its admin separately —
//!   a failure between them left a conversation nobody can administer, permanently, because
//!   `promote` itself requires an existing admin.
//! * `accept_invite` / `approve_join_request` burned the invite use (or deleted the join request)
//!   and only then added routing membership — a failure between them consumed the user's one
//!   chance to join without joining them.
//! * `is_conversation_admin` read membership on one connection and adminship on another, then the
//!   write it authorized ran on a third. The authorization was never atomic with its own effect.
//!
//! All stores are built from the SAME pool, so one checked-out connection can serve all of them.
//! The fix is therefore a shape, not a rewrite: each composable operation gains an `*_in_txn`
//! form taking `&mut postgres::Transaction`, the existing public method becomes a thin wrapper
//! that opens a transaction and delegates (so every current caller and test is unaffected), and a
//! handler that needs two stores to agree runs them through [`transaction`].
//!
//! Ordering rule for anything added here: take advisory locks (`groups::lock_conversation`,
//! `social::lock_pair`) before row locks, and never hold two advisory locks at once. Every
//! current path obeys that, which is what keeps the lock graph acyclic.

use auth_core::store::{StoreError, StoreResult};

use crate::pgstore::PgPool;

/// Run `f` against a single transaction on one pooled connection, committing on `Ok` and rolling
/// back on `Err` (the `Transaction` drop does the rollback).
///
/// Use this whenever two stores must agree — not for single-store work, which should keep using
/// that store's own method.
pub fn transaction<T>(
    pool: &PgPool,
    f: impl FnOnce(&mut postgres::Transaction<'_>) -> StoreResult<T>,
) -> StoreResult<T> {
    let mut conn = pool.get().map_err(|e| StoreError(format!("pool: {e}")))?;
    let mut txn = conn
        .transaction()
        .map_err(|e| StoreError(format!("txn begin: {e}")))?;
    let out = f(&mut txn)?;
    txn.commit()
        .map_err(|e| StoreError(format!("txn commit: {e}")))?;
    Ok(out)
}
