//! In-app account deletion: erase everything an account owns, in ONE transaction.
//!
//! **Why this is explicit rather than a cascade.** Only two tables cascade from `accounts`:
//! `devices` and `profiles`. Every other table holding account or device data — tokens,
//! challenges, the social graph, group membership and roles, key packages, push tokens, attest
//! keys, self-group state, queued envelopes — has NO foreign key to `accounts` at all. A bare
//! `DELETE FROM accounts` would therefore orphan the overwhelming majority of a user's data while
//! appearing to succeed. Adding those foreign keys is worthwhile on its own, but deletion must not
//! depend on schema changes landing first, and an explicit list is auditable: you can read it
//! against the table list and see what is covered.
//!
//! **What is deliberately RETAINED, and why.** Two categories survive, each for a stated reason:
//!
//! * `transparency_log` — an append-only key-transparency log. Clients self-monitor their own
//!   keys against it, and existing inclusion proofs are only meaningful because entries are never
//!   rewritten. Deleting leaves would silently invalidate other users' proofs and convert an
//!   auditable log into an unauditable one. This is the "security-required record" case.
//! * `membership_events` — the MLS commit history for conversations the account participated in.
//!   Other members' clients still depend on that epoch chain to validate group state. It is
//!   conversation protocol state, not personal profile data, and it disappears with the
//!   conversation itself (it cascades from `conversations`).
//!
//! `reports` are retained but irreversibly anonymized: abuse history must outlive the account, or
//! deleting and re-registering would launder it. Note `reports` carries `CHECK (reporter <>
//! reported)`, so the two roles get DISTINCT sentinels — collapsing both to one value would
//! violate that constraint the moment both parties deleted their accounts.
//!
//! **What is NOT retracted.** Envelopes the account already SENT to other people are left alone.
//! Deleting your account is not a retraction of messages other people already received or are
//! queued to receive; silently rewriting their history would be a worse surprise than a message
//! from a since-deleted user. Envelopes queued TO this account's devices are deleted, because with
//! the devices gone nothing can ever decrypt them.

use auth_core::ids::AccountId;
use auth_core::store::{StoreError, StoreResult};

/// Distinct sentinels for the two report roles, so anonymizing both sides of a report cannot
/// violate `CHECK (reporter <> reported)`.
const ANON_REPORTER: [u8; 16] = [0u8; 16];
const ANON_REPORTED: [u8; 16] = [0xFFu8; 16];

fn db_err(e: postgres::Error) -> StoreError {
    StoreError(format!("account deletion db: {e}"))
}

/// Erase `account` and everything it owns, inside a caller-owned transaction.
///
/// Ordered so that rows are removed before anything they are looked up through, and so the
/// account row (which cascades `devices` and `profiles`) goes last. Idempotent: deleting an
/// already-deleted account is a no-op rather than an error.
pub fn delete_account_in_txn(
    txn: &mut postgres::Transaction<'_>,
    account: &AccountId,
) -> StoreResult<()> {
    let account_bytes = account.as_bytes();

    // The account's devices drive every device-keyed table below. Collected first, because
    // deleting the account row would cascade them away before we could enumerate them.
    let device_ids: Vec<Vec<u8>> = txn
        .query(
            "SELECT device_id FROM devices WHERE account_id = $1",
            &[&account_bytes],
        )
        .map_err(db_err)?
        .iter()
        .map(|r| r.get::<_, Vec<u8>>(0))
        .collect();
    let devices: Vec<&[u8]> = device_ids.iter().map(|d| d.as_slice()).collect();

    // --- device-keyed state -------------------------------------------------------------
    // Queued mail TO this account's devices can never be decrypted once the devices are gone.
    for (sql, label) in [
        (
            "DELETE FROM envelopes WHERE recipient_device = ANY($1)",
            "envelopes",
        ),
        (
            "DELETE FROM sealed_envelopes WHERE recipient_device = ANY($1)",
            "sealed envelopes",
        ),
        // Self-group mail is between this account's OWN devices, so both directions go.
        (
            "DELETE FROM self_group_envelopes
             WHERE recipient_device = ANY($1) OR sender_device = ANY($1)",
            "self-group envelopes",
        ),
        (
            "DELETE FROM self_group_members WHERE device_id = ANY($1)",
            "self-group membership",
        ),
        (
            "DELETE FROM device_push_tokens WHERE device_id = ANY($1)",
            "push tokens",
        ),
        (
            "DELETE FROM app_attest_keys WHERE device_id = ANY($1)",
            "attest keys",
        ),
        (
            "DELETE FROM app_attest_challenges WHERE device_id = ANY($1)",
            "attest challenges",
        ),
        (
            "DELETE FROM key_packages WHERE device_id = ANY($1)",
            "key packages",
        ),
        (
            "DELETE FROM conversation_members WHERE device_id = ANY($1)",
            "routing membership",
        ),
    ] {
        txn.execute(sql, &[&devices])
            .map_err(|e| StoreError(format!("account deletion db ({label}): {e}")))?;
    }

    // --- account-keyed state ------------------------------------------------------------
    for sql in [
        // Sessions and credentials: every path back in.
        "DELETE FROM access_tokens WHERE account_id = $1",
        "DELETE FROM refresh_families WHERE account_id = $1", // cascades refresh_tokens
        "DELETE FROM challenges WHERE account_id = $1",
        "DELETE FROM delivery_access_keys WHERE account_id = $1",
        // Key packages are also account-keyed; catch any not covered by the device sweep.
        "DELETE FROM key_packages WHERE account_id = $1",
        "DELETE FROM self_group_members WHERE account_id = $1",
        // Social graph, both directions.
        "DELETE FROM friendships WHERE account_lo = $1 OR account_hi = $1",
        "DELETE FROM friend_requests WHERE from_account = $1 OR to_account = $1",
        "DELETE FROM blocks WHERE blocker = $1 OR blocked = $1",
        // Group governance.
        "DELETE FROM group_admins WHERE account_id = $1",
        "DELETE FROM group_join_requests WHERE account_id = $1",
        "DELETE FROM group_invites WHERE created_by = $1",
        // Any routing rows keyed by account that the device sweep missed.
        "DELETE FROM conversation_members WHERE account_id = $1",
    ] {
        txn.execute(sql, &[&account_bytes]).map_err(db_err)?;
    }

    // --- retained-but-anonymized ---------------------------------------------------------
    // Abuse history outlives the account: otherwise delete-and-re-register launders it.
    txn.execute(
        "UPDATE reports SET reporter = $2 WHERE reporter = $1",
        &[&account_bytes, &ANON_REPORTER.as_slice()],
    )
    .map_err(db_err)?;
    txn.execute(
        "UPDATE reports SET reported = $2 WHERE reported = $1",
        &[&account_bytes, &ANON_REPORTED.as_slice()],
    )
    .map_err(db_err)?;

    // --- conversations left with nobody in them -----------------------------------------
    // Leaving the last member deletes the conversation elsewhere (`leave_conversation`); deletion
    // must do the same or it strands unreachable rows. Envelopes go first: they carry no foreign
    // key to `conversations`, so the cascade would not take them.
    txn.execute(
        "DELETE FROM envelopes e
         WHERE NOT EXISTS (SELECT 1 FROM conversation_members m
                           WHERE m.conversation_id = e.conversation_id)",
        &[],
    )
    .map_err(db_err)?;
    txn.execute(
        "DELETE FROM conversations c
         WHERE NOT EXISTS (SELECT 1 FROM conversation_members m
                           WHERE m.conversation_id = c.conversation_id)",
        &[],
    )
    .map_err(db_err)?;

    // --- the account itself (cascades `devices` and `profiles`) --------------------------
    txn.execute(
        "DELETE FROM accounts WHERE account_id = $1",
        &[&account_bytes],
    )
    .map_err(db_err)?;

    Ok(())
}
