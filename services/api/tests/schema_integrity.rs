//! Blocker-5 evidence: the schema itself now refuses states the application used to have to
//! remember to avoid.
//!
//! Before V22 only `devices` and `profiles` cascaded from `accounts`; everything else — tokens,
//! the social graph, group roles, key packages, queued mail — could refer to accounts that no
//! longer existed, and a real database had accumulated hundreds of such rows. These tests check
//! the guarantees rather than the migration text: run it against an empty database and a seeded
//! one, hammer the social and group paths concurrently, then ask the database whether any
//! impossible state exists.

mod common;

use std::sync::Arc;

use auth_core::ids::AccountId;
use common::{db_url, seed_account, seed_device_for, shared_groups, shared_relay, shared_social};

fn client() -> postgres::Client {
    postgres::Client::connect(&db_url(), postgres::NoTls).expect("db connect")
}

fn scalar(sql: &str) -> i64 {
    client().query_one(sql, &[]).expect("query").get(0)
}

/// A migration that only ever runs against an already-migrated database is untested. Build a fresh
/// database, run the whole chain into it, and confirm the integrity objects actually arrive.
#[test]
fn migrations_apply_to_an_empty_database() {
    let name = format!(
        "nedwons_migrate_{}",
        hex::encode(&AccountId::random().as_bytes()[..6])
    );
    let base = db_url();
    let admin_url = base
        .rsplit_once('/')
        .expect("db url has a path")
        .0
        .to_string();

    let mut admin = postgres::Client::connect(&format!("{admin_url}/postgres"), postgres::NoTls)
        .expect("connect to the maintenance database");
    admin
        .execute(&format!("CREATE DATABASE {name}"), &[])
        .expect("create a scratch database");

    let fresh_url = format!("{admin_url}/{name}");
    let outcome = nedwons_api::run_migrations(&fresh_url);

    // Inspect before dropping, so a failure still cleans up after itself.
    let objects = outcome.as_ref().ok().map(|_| {
        let mut c = postgres::Client::connect(&fresh_url, postgres::NoTls).expect("connect fresh");
        let fks: i64 = c
            .query_one(
                "SELECT count(*) FROM information_schema.table_constraints tc
                 JOIN information_schema.constraint_column_usage ccu
                   ON ccu.constraint_name = tc.constraint_name
                 WHERE tc.constraint_type = 'FOREIGN KEY' AND ccu.table_name = 'accounts'",
                &[],
            )
            .expect("count fks")
            .get(0);
        let triggers: i64 = c
            .query_one(
                "SELECT count(*) FROM information_schema.triggers WHERE trigger_schema = 'public'",
                &[],
            )
            .expect("count triggers")
            .get(0);
        let unique_token: i64 = c
            .query_one(
                "SELECT count(*) FROM pg_indexes
                 WHERE schemaname = 'public' AND indexname = 'device_push_tokens_one_owner'",
                &[],
            )
            .expect("count index")
            .get(0);
        drop(c);
        (fks, triggers, unique_token)
    });

    admin
        .execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"), &[])
        .expect("drop the scratch database");

    outcome.expect("migrations must apply cleanly to an empty database");
    let (fks, triggers, unique_token) = objects.expect("inspected");
    assert!(
        fks >= 15,
        "expected the account foreign keys to exist on a fresh database, found {fks}"
    );
    assert!(
        triggers >= 3,
        "expected the cross-table invariant triggers, found {triggers}"
    );
    assert_eq!(
        unique_token, 1,
        "push tokens must have a single-owner index"
    );
}

/// The already-migrated shared database is the "seeded" half of the same requirement: the
/// migration had to clean hundreds of pre-existing orphans before it could add these keys, so
/// re-running it must be a no-op and the database must now be free of orphans.
#[test]
fn the_seeded_database_has_no_orphans_left() {
    nedwons_api::run_migrations(&db_url()).expect("re-running migrations must be idempotent");

    for (label, sql) in [
        ("access_tokens", "SELECT count(*) FROM access_tokens t WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = t.account_id)"),
        ("refresh_families", "SELECT count(*) FROM refresh_families t WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = t.account_id)"),
        ("conversation_members", "SELECT count(*) FROM conversation_members t WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = t.account_id)"),
        ("group_admins", "SELECT count(*) FROM group_admins t WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = t.account_id)"),
        ("blocks", "SELECT count(*) FROM blocks t WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = t.blocker)"),
        ("friendships", "SELECT count(*) FROM friendships t WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = t.account_lo)"),
        ("key_packages", "SELECT count(*) FROM key_packages t WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.device_id = t.device_id)"),
        ("admins without membership", "SELECT count(*) FROM group_admins g WHERE NOT EXISTS (SELECT 1 FROM conversation_members m WHERE m.conversation_id = g.conversation_id AND m.account_id = g.account_id)"),
        ("duplicate push-token owners", "SELECT count(*) FROM (SELECT platform, token FROM device_push_tokens GROUP BY 1, 2 HAVING count(DISTINCT device_id) > 1) x"),
    ] {
        assert_eq!(scalar(sql), 0, "{label}: orphaned or impossible rows remain");
    }
}

/// An admin who is not a member is unreachable by every governance path, so the database refuses
/// to store one. This cannot be a foreign key: `conversation_members` is keyed per DEVICE, so one
/// account legitimately has several rows per conversation and there is no unique target.
#[test]
fn an_admin_cannot_exist_without_membership() {
    let groups = shared_groups();
    let relay = shared_relay();
    let conversation_id: [u8; 16] = AccountId::random().as_bytes().try_into().expect("16");
    let (owner, owner_device) = seed_account();
    let (outsider, _) = seed_account();

    relay
        .create_conversation(conversation_id, owner, owner_device, false)
        .expect("create");

    // Direct insert, bypassing every application check — the database must still refuse.
    let refused = client().execute(
        "INSERT INTO group_admins (conversation_id, account_id) VALUES ($1, $2)",
        &[&conversation_id.as_slice(), &outsider.as_bytes()],
    );
    assert!(
        refused.is_err(),
        "a non-member must not be storable as an admin"
    );

    // And an admin loses the role when their last device leaves, even on the removal path that
    // never cleaned up `group_admins` itself.
    groups
        .bootstrap_admin(&conversation_id, &owner)
        .expect("bootstrap");
    client()
        .execute(
            "DELETE FROM conversation_members WHERE conversation_id = $1 AND account_id = $2",
            &[&conversation_id.as_slice(), &owner.as_bytes()],
        )
        .expect("remove membership");
    let remaining: i64 = client()
        .query_one(
            "SELECT count(*) FROM group_admins WHERE conversation_id = $1 AND account_id = $2",
            &[&conversation_id.as_slice(), &owner.as_bytes()],
        )
        .expect("count")
        .get(0);
    assert_eq!(
        remaining, 0,
        "the admin row must not outlive the membership it depends on"
    );
}

/// A friendship is a live authorization credential (`are_friends` gates group additions), so a
/// blocked pair must not be able to acquire one even if a future code path forgets to check.
#[test]
fn a_blocked_pair_cannot_become_friends() {
    let social = shared_social();
    let (a, _) = seed_account();
    let (b, _) = seed_account();

    social.block(&a, &b).expect("block");

    let (lo, hi) = if a.0 <= b.0 { (a.0, b.0) } else { (b.0, a.0) };
    let refused = client().execute(
        "INSERT INTO friendships (account_lo, account_hi) VALUES ($1, $2)",
        &[&lo.as_slice(), &hi.as_slice()],
    );
    assert!(
        refused.is_err(),
        "the database must refuse a friendship between a blocked pair"
    );
}

/// One APNs token addresses one device. APNs reassigns tokens to reinstalled apps, so registering
/// a token another device still claims must TRANSFER it, not duplicate it — otherwise the stale
/// owner keeps receiving wake pushes meant for the new one.
#[test]
fn a_push_token_has_exactly_one_owner() {
    let relay = shared_relay();
    let (_account, first) = seed_account();
    let (_account2, second) = seed_account();
    let token = format!("tok-{}", hex::encode(AccountId::random().as_bytes()));

    relay
        .register_push_token(&first, "apns", &token)
        .expect("first registration");
    relay
        .register_push_token(&second, "apns", &token)
        .expect("re-registration must transfer, not conflict");

    let owners: i64 = client()
        .query_one(
            "SELECT count(*) FROM device_push_tokens WHERE platform = 'apns' AND token = $1",
            &[&token],
        )
        .expect("count owners")
        .get(0);
    assert_eq!(owners, 1, "a token must have exactly one owner");

    let owner: Vec<u8> = client()
        .query_one(
            "SELECT device_id FROM device_push_tokens WHERE platform = 'apns' AND token = $1",
            &[&token],
        )
        .expect("owner")
        .get(0);
    assert_eq!(
        owner,
        second.as_bytes().to_vec(),
        "the newest registration owns the token"
    );
}

/// Randomized social and group traffic, run concurrently, then the invariant queries. This is the
/// part that would catch an invariant the individual tests each satisfy but that some interleaving
/// breaks.
#[test]
fn randomized_social_and_group_traffic_preserves_every_invariant() {
    let social = shared_social();
    let groups = shared_groups();
    let relay = shared_relay();

    // A cohort of real accounts, plus a second device for some of them so the per-device and
    // per-account paths both get exercised.
    let cohort: Vec<(AccountId, auth_core::ids::DeviceId)> =
        (0..8).map(|_| seed_account()).collect();
    let extra_devices: Vec<_> = cohort
        .iter()
        .take(3)
        .map(|(a, _)| (*a, seed_device_for(a)))
        .collect();

    let conversations: Vec<[u8; 16]> = (0..4)
        .map(|i| {
            let id: [u8; 16] = AccountId::random().as_bytes().try_into().expect("16");
            let (owner, device) = cohort[i % cohort.len()];
            relay
                .create_conversation(id, owner, device, false)
                .expect("create");
            groups.bootstrap_admin(&id, &owner).expect("bootstrap");
            id
        })
        .collect();

    let cohort = Arc::new(cohort);
    let extra_devices = Arc::new(extra_devices);
    let conversations = Arc::new(conversations);

    let mut handles = Vec::new();
    for worker in 0..8usize {
        let (social, groups, relay) = (social.clone(), groups.clone(), relay.clone());
        let (cohort, extra_devices, conversations) =
            (cohort.clone(), extra_devices.clone(), conversations.clone());
        handles.push(std::thread::spawn(move || {
            for step in 0..24usize {
                let i = (worker * 7 + step * 3) % cohort.len();
                let j = (worker * 5 + step * 11 + 1) % cohort.len();
                if i == j {
                    continue;
                }
                let (a, a_device) = cohort[i];
                let (b, _) = cohort[j];
                let conversation = conversations[(worker + step) % conversations.len()];

                // Deliberately unchecked: these paths are ALLOWED to refuse (blocked, already a
                // member, last admin). What must never happen is an impossible stored state.
                match step % 6 {
                    0 => {
                        let _ = social.send_friend_request(&a, &b);
                    }
                    1 => {
                        let _ = social.accept_friend_request(&b, &a);
                    }
                    2 => {
                        let _ = social.block(&a, &b);
                    }
                    3 => {
                        let _ = social.unblock(&a, &b);
                    }
                    4 => {
                        let _ = relay.add_member(&conversation, a, a_device);
                        let _ = groups.promote(&conversation, &a);
                    }
                    _ => {
                        let _ = groups.demote(&conversation, &a);
                        let _ = groups.leave_conversation(&conversation, &a);
                    }
                }
                if let Some((acct, device)) = extra_devices.get(step % 4) {
                    let _ = relay.add_member(&conversation, *acct, *device);
                }
            }
        }));
    }
    for h in handles {
        h.join().expect("worker");
    }

    // The traffic above deliberately ignores per-call outcomes (refusals are legitimate), so first
    // confirm it actually moved state. Without this, every invariant below would hold trivially on
    // a run where nothing succeeded.
    let cohort_ids: Vec<&[u8]> = cohort.iter().map(|(a, _)| a.as_bytes()).collect();
    let touched: i64 = client()
        .query_one(
            "SELECT (SELECT count(*) FROM friendships WHERE account_lo = ANY($1) OR account_hi = ANY($1))
                  + (SELECT count(*) FROM friend_requests WHERE from_account = ANY($1) OR to_account = ANY($1))
                  + (SELECT count(*) FROM blocks WHERE blocker = ANY($1) OR blocked = ANY($1))
                  + (SELECT count(*) FROM conversation_members WHERE account_id = ANY($1))",
            &[&cohort_ids],
        )
        .expect("touched")
        .get(0);
    assert!(
        touched > 0,
        "the randomized traffic produced no state at all, so the invariants below prove nothing"
    );

    // The invariants, asked of the database directly.
    assert_eq!(
        scalar(
            "SELECT count(*) FROM group_admins g
             WHERE NOT EXISTS (SELECT 1 FROM conversation_members m
                               WHERE m.conversation_id = g.conversation_id
                                 AND m.account_id = g.account_id)"
        ),
        0,
        "an admin outlived its membership"
    );
    assert_eq!(
        scalar(
            "SELECT count(*) FROM friendships f
             JOIN blocks b ON (b.blocker = f.account_lo AND b.blocked = f.account_hi)
                           OR (b.blocker = f.account_hi AND b.blocked = f.account_lo)"
        ),
        0,
        "a blocked pair is also friends"
    );
    assert_eq!(
        scalar(
            "SELECT count(*) FROM friendships f
             JOIN friend_requests r ON (r.from_account = f.account_lo AND r.to_account = f.account_hi)
                                    OR (r.from_account = f.account_hi AND r.to_account = f.account_lo)"
        ),
        0,
        "a pending request survived alongside an established friendship"
    );

    // Every conversation this test created is either gone or still has members — never a
    // memberless row that nothing can reach.
    for conversation in conversations.iter() {
        let rows: i64 = client()
            .query_one(
                "SELECT count(*) FROM conversations c
                 WHERE c.conversation_id = $1
                   AND NOT EXISTS (SELECT 1 FROM conversation_members m
                                   WHERE m.conversation_id = c.conversation_id)",
                &[&conversation.as_slice()],
            )
            .expect("count")
            .get(0);
        assert_eq!(rows, 0, "a memberless conversation survived");
    }

    // Deleting every account in the cohort must leave nothing behind.
    let pool = relay.pool_clone();
    for (account, _) in cohort.iter() {
        nedwons_api::tx::transaction(&pool, |txn| {
            nedwons_api::account_deletion::delete_account_in_txn(txn, account)
        })
        .expect("delete");
    }
    for (account, _) in cohort.iter() {
        let residue: i64 = client()
            .query_one(
                "SELECT (SELECT count(*) FROM accounts WHERE account_id = $1)
                      + (SELECT count(*) FROM conversation_members WHERE account_id = $1)
                      + (SELECT count(*) FROM group_admins WHERE account_id = $1)
                      + (SELECT count(*) FROM friendships WHERE account_lo = $1 OR account_hi = $1)
                      + (SELECT count(*) FROM friend_requests WHERE from_account = $1 OR to_account = $1)
                      + (SELECT count(*) FROM blocks WHERE blocker = $1 OR blocked = $1)",
                &[&account.as_bytes()],
            )
            .expect("residue")
            .get(0);
        assert_eq!(residue, 0, "account data survived deletion");
    }
}
