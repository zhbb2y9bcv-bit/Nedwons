//! Evidence closing R-102: against a REAL PostgreSQL, the SQL implementations enforce the same
//! atomicity the in-memory stores promised (ADR-0006), including under true concurrency.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use auth_core::crypto::sha256;
use auth_core::ids::TxnId;
use auth_core::store::{
    AccountDevice, ChallengeRecord, ChallengeStore, CredentialStore, DeviceStore, RefreshOutcome,
    RefreshStore,
};
use auth_core::transcript::{Action, Transcript};
use auth_core::{refresh_txn_id, AccountId, AuthError, DeviceId};
use common::{register, setup, unique_username, TestDevice, PASSWORD};

/// Full register → login → whoami → refresh → logout cycle over PostgreSQL.
#[test]
fn full_auth_cycle_over_postgres() {
    let (_stores, service) = setup();
    let username = unique_username("alice");
    let (device, session) = register(&service, &username);

    // Login with the enrolled device succeeds.
    let challenge = service.login_begin(&username, PASSWORD);
    let transcript = Transcript {
        action: Action::Login,
        account_id: &challenge.account_id,
        device_id: &challenge.device_id,
        public_key: &device.public_key,
        challenge: &challenge.nonce,
        expires_at: challenge.expires_at,
        txn_id: &challenge.txn_id,
    };
    let login_session = service
        .login_finish(&challenge.txn_id, &device.sign(&transcript.encode()))
        .expect("login should succeed");
    assert_eq!(login_session.account_id, session.account_id);

    // Access token validates.
    let who = service
        .validate_access(&login_session.access_token)
        .expect("access token valid");
    assert_eq!(who.account_id, session.account_id);

    // Refresh rotates.
    let old_hash = sha256(&login_session.refresh_token);
    let txn = refresh_txn_id(&old_hash);
    let refresh_transcript = Transcript {
        action: Action::Refresh,
        account_id: &who.account_id,
        device_id: &who.device_id,
        public_key: &device.public_key,
        challenge: &old_hash,
        expires_at: 0,
        txn_id: &txn,
    };
    let rotated = service
        .refresh(
            &login_session.refresh_token,
            &device.sign(&refresh_transcript.encode()),
        )
        .expect("refresh should succeed");
    assert_ne!(rotated.refresh_token, login_session.refresh_token);

    // Logout kills the access token.
    service.logout(&rotated.refresh_token).expect("logout");
    assert!(matches!(
        service.validate_access(&rotated.access_token),
        Err(AuthError::Denied)
    ));
}

/// INV-2 against the real database: correct credentials, wrong device key → denied.
#[test]
fn wrong_device_key_denied_over_postgres() {
    let (_stores, service) = setup();
    let username = unique_username("bob");
    let (_device, _session) = register(&service, &username);

    let attacker = TestDevice::new();
    let challenge = service.login_begin(&username, PASSWORD);
    let transcript = Transcript {
        action: Action::Login,
        account_id: &challenge.account_id,
        device_id: &challenge.device_id,
        public_key: &attacker.public_key,
        challenge: &challenge.nonce,
        expires_at: challenge.expires_at,
        txn_id: &challenge.txn_id,
    };
    let result = service.login_finish(&challenge.txn_id, &attacker.sign(&transcript.encode()));
    assert!(matches!(result, Err(AuthError::Denied)));
}

/// INV-4 under real concurrency: N threads race to consume one challenge; the
/// DELETE ... RETURNING contract means exactly one wins.
#[test]
fn challenge_consume_race_exactly_one_winner() {
    let (stores, _service) = setup();

    let txn_id = TxnId::random();
    stores
        .put(ChallengeRecord {
            txn_id,
            account_id: AccountId::random(),
            device_id: DeviceId::random(),
            action: Action::Login,
            nonce: [7u8; 32],
            expires_at: u64::MAX / 2,
        })
        .expect("put");

    const RACERS: usize = 16;
    let winners = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(std::sync::Barrier::new(RACERS));
    let mut handles = Vec::new();
    for _ in 0..RACERS {
        let stores = stores.clone();
        let winners = winners.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait(); // maximize contention
            if stores.consume(&txn_id).expect("consume").is_some() {
                winners.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
    assert_eq!(
        winners.load(Ordering::SeqCst),
        1,
        "exactly one racer must consume the challenge"
    );
}

/// Refresh rotation under real concurrency: N threads race to rotate the same token.
/// FOR UPDATE + generation CAS means at most one Rotated; the losers' reuse burns the
/// family, so afterwards even the winner's token is dead (fail closed on races).
#[test]
fn refresh_rotate_race_at_most_one_winner() {
    let (stores, _service) = setup();

    let account = AccountDevice {
        account_id: AccountId::random(),
        device_id: DeviceId::random(),
    };
    // All hashes are randomized per run: the test database persists across runs (tests use
    // unique data instead of truncation), so fixed bytes would collide on the PK.
    let token = auth_core::crypto::random_bytes::<32>();
    let run_nonce = auth_core::crypto::random_bytes::<16>();
    let racer_hash = move |i: usize| {
        let mut buf = run_nonce.to_vec();
        buf.push(i as u8);
        sha256(&buf)
    };
    let old_hash = sha256(&token);
    stores
        .issue(account, old_hash, u64::MAX / 2)
        .expect("issue");

    const RACERS: usize = 12;
    let rotated = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(std::sync::Barrier::new(RACERS));
    let mut handles = Vec::new();
    for i in 0..RACERS {
        let stores = stores.clone();
        let rotated = rotated.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let new_hash = racer_hash(i);
            barrier.wait();
            match stores
                .rotate(&old_hash, new_hash, u64::MAX / 2)
                .expect("rotate")
            {
                RefreshOutcome::Rotated { .. } => {
                    rotated.fetch_add(1, Ordering::SeqCst);
                }
                RefreshOutcome::ReuseDetected | RefreshOutcome::Unknown => {}
            }
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
    assert!(
        rotated.load(Ordering::SeqCst) <= 1,
        "at most one racer may rotate"
    );

    // The race triggered reuse detection, so the family must now be revoked: even a
    // rotation with any surviving token fails closed.
    let post_race = auth_core::crypto::random_bytes::<32>();
    for i in 0..RACERS {
        let hash_i = racer_hash(i);
        if let Ok(RefreshOutcome::Rotated { .. }) =
            stores.rotate(&hash_i, sha256(&post_race), u64::MAX / 2)
        {
            panic!("family must be revoked after reuse");
        }
    }
}

/// Multi-device (ADR-0008): the DB no longer forbids a second active device — the trusted-device
/// ceremony plus a per-account cap (`add_active_device`) govern that. Username uniqueness is still
/// enforced by the database; revoked devices don't count against the cap; `active_device_for_account`
/// resolves the deterministic primary.
#[test]
fn schema_allows_capped_multi_device_and_unique_usernames() {
    use auth_core::store::{Assurance, DeviceRecord};
    const MAX: usize = auth_core::AuthService::MAX_ACTIVE_DEVICES;
    let new_device = |account| DeviceRecord {
        device_id: DeviceId::random(),
        account_id: account,
        public_key: vec![0x04; 65],
        revoked: false,
        // This test is about the cap and uniqueness, not assurance; enrolled devices are always
        // born Software (ADR-0017).
        assurance: Assurance::Software,
    };

    let (stores, service) = setup();
    let username = unique_username("carol");
    let (_device, session) = register(&service, &username);
    let active_count = || {
        stores
            .list_devices(&session.account_id)
            .expect("list")
            .iter()
            .filter(|d| !d.revoked)
            .count()
    };

    // A second active device is now ALLOWED (the single-active index is gone).
    assert!(
        stores
            .add_active_device(new_device(session.account_id), MAX)
            .expect("add"),
        "a second active device is allowed under the cap"
    );
    assert_eq!(active_count(), 2);

    // The per-account cap IS enforced: fill to MAX, then the next is refused.
    while active_count() < MAX {
        assert!(stores
            .add_active_device(new_device(session.account_id), MAX)
            .expect("add"));
    }
    assert!(
        !stores
            .add_active_device(new_device(session.account_id), MAX)
            .expect("add"),
        "the cap is enforced at the store"
    );

    // Duplicate username is still a clean `false`, not an error.
    let dup = auth_core::store::AccountRecord {
        account_id: AccountId::random(),
        username_normalized: username.clone(),
        password_phc: "x".repeat(32),
    };
    assert!(
        !stores
            .create_account_with_device(dup, new_device(AccountId::random()))
            .expect("no error"),
        "duplicate username returns false"
    );

    // Revoked devices don't count against the cap, and primary resolution stays defined.
    let primary = stores
        .active_device_for_account(&session.account_id)
        .expect("query")
        .expect("a primary exists");
    stores.revoke_device(&primary.device_id).expect("revoke");
    assert_eq!(active_count(), MAX - 1);
    assert!(
        stores
            .active_device_for_account(&session.account_id)
            .expect("query")
            .is_some(),
        "primary resolves to the next earliest non-revoked device"
    );
}

/// The per-account cap must hold under TRUE concurrency, not merely sequentially.
///
/// `add_active_device` counts active devices then inserts. Wrapping both in one transaction is
/// NOT sufficient at PostgreSQL's default READ COMMITTED: concurrent racers each read the same
/// pre-insert count, each see room under the cap, and each insert — so the account ends up with
/// more active devices than `MAX_ACTIVE_DEVICES`. V13 dropped `devices_one_active_per_account`,
/// so no database constraint catches this either; the cap is application-enforced and must
/// therefore serialize on the account row.
#[test]
fn add_active_device_race_never_exceeds_cap() {
    use auth_core::store::{Assurance, DeviceRecord};
    const MAX: usize = auth_core::AuthService::MAX_ACTIVE_DEVICES;

    let (stores, service) = setup();
    let username = unique_username("racecap");
    let (_device, session) = register(&service, &username);

    // Registration leaves exactly one active device, so MAX - 1 slots remain. Racing more
    // enrollments than slots means the cap MUST refuse the surplus.
    const RACERS: usize = 16;
    const {
        assert!(
            RACERS > MAX,
            "racers must outnumber the cap to test refusal"
        )
    };

    let granted = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(std::sync::Barrier::new(RACERS));
    let mut handles = Vec::new();
    for _ in 0..RACERS {
        let stores = stores.clone();
        let granted = granted.clone();
        let barrier = barrier.clone();
        let account_id = session.account_id;
        handles.push(std::thread::spawn(move || {
            let device = DeviceRecord {
                device_id: DeviceId::random(),
                account_id,
                public_key: vec![0x04; 65],
                revoked: false,
                assurance: Assurance::Software,
            };
            barrier.wait(); // maximize contention
            if stores.add_active_device(device, MAX).expect("add") {
                granted.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }

    let active = stores
        .list_devices(&session.account_id)
        .expect("list")
        .iter()
        .filter(|d| !d.revoked)
        .count();

    assert!(
        active <= MAX,
        "cap breached under concurrency: {active} active devices exceeds MAX {MAX}"
    );
    assert_eq!(
        granted.load(Ordering::SeqCst),
        MAX - 1,
        "exactly the remaining slots may be granted"
    );
}

/// A sender removed from a conversation must never fan out into it.
///
/// `member_in_txn` documents that the check and the dependent write are atomic — "a member
/// removed concurrently can't slip a message in". At READ COMMITTED that is false without a row
/// lock, and the fanout INSERT makes it worse: its predicate is `cm.device_id <> $2`, enumerating
/// the OTHER members, so the sender's own absence never changes the inserted rows. A removal
/// committing after the check is therefore invisible to the write it was supposed to guard.
///
/// Deterministic proof rather than a timing lottery: hold an UNCOMMITTED delete of the sender's
/// membership row, then fan out from another thread. Correct behavior is to block on that row and,
/// once the delete commits, observe the removal and refuse. The unlocked version never touches the
/// locked row, so it sails past and queues envelopes from a non-member.
#[test]
fn fanout_refuses_a_sender_removed_concurrently() {
    use nedwons_api::relay::FanoutOutcome;
    use std::sync::atomic::AtomicBool;

    let relay = common::shared_relay();
    let conversation_id: [u8; 16] = DeviceId::random().as_bytes().try_into().expect("16 bytes");
    let sender = DeviceId::random();
    let recipient = DeviceId::random();

    relay
        .create_conversation(conversation_id, AccountId::random(), sender, false)
        .expect("create conversation (seeds the sender as a member)");
    relay
        .add_member(&conversation_id, AccountId::random(), recipient)
        .expect("add a second member so a fanout has somewhere to go");

    // Hold the sender's membership row in an uncommitted DELETE on a separate connection.
    let mut blocker =
        postgres::Client::connect(&common::db_url(), postgres::NoTls).expect("blocker connect");
    let mut removal = blocker.transaction().expect("removal txn");
    removal
        .execute(
            "DELETE FROM conversation_members WHERE conversation_id = $1 AND device_id = $2",
            &[&conversation_id.as_slice(), &sender.as_bytes()],
        )
        .expect("stage the removal");

    let finished = Arc::new(AtomicBool::new(false));
    let handle = {
        let relay = relay.clone();
        let finished = finished.clone();
        let idempotency_key: [u8; 16] = DeviceId::random().as_bytes().try_into().expect("16");
        std::thread::spawn(move || {
            let outcome = relay
                .fanout_message(
                    &conversation_id,
                    &sender,
                    b"opaque ciphertext",
                    &idempotency_key,
                )
                .expect("fanout");
            finished.store(true, Ordering::SeqCst);
            outcome
        })
    };

    std::thread::sleep(std::time::Duration::from_millis(400));
    assert!(
        !finished.load(Ordering::SeqCst),
        "fanout completed while the sender's removal was still uncommitted: the membership \
         check took no row lock, so a concurrent removal cannot stop the send"
    );

    removal.commit().expect("commit the removal");
    let outcome = handle.join().expect("fanout thread");
    assert!(
        matches!(outcome, FanoutOutcome::Forbidden),
        "once the removal commits the fanout must refuse the non-member sender"
    );

    let queued: i64 = postgres::Client::connect(&common::db_url(), postgres::NoTls)
        .expect("verify connect")
        .query_one(
            "SELECT count(*) FROM envelopes WHERE conversation_id = $1",
            &[&conversation_id.as_slice()],
        )
        .expect("count envelopes")
        .get(0);
    assert_eq!(queued, 0, "a removed sender must queue no envelopes");
}

/// A blocked pair must never also be friends. A stale friendship is not cosmetic: it is a live
/// authorization credential — `add_member` gates group additions on `are_friends`, so a friendship
/// surviving a block lets the blocked party be pulled into a group.
///
/// `blocks` and `friendships` are different tables, so no row lock covers the invariant, and at
/// READ COMMITTED neither transaction sees the other's uncommitted write — textbook write skew.
/// `accept_friend_request` makes it worse by never reading `blocks` at all, so it needs no timing
/// window: it simply relies on `block()` having deleted the pending request first.
#[test]
fn block_and_friendship_never_coexist() {
    let social = common::shared_social();
    const TRIALS: usize = 40;

    for trial in 0..TRIALS {
        let a = AccountId::random();
        let b = AccountId::random();

        // B asks to be A's friend, leaving a pending request for A to accept.
        social
            .send_friend_request(&b, &a)
            .expect("send friend request");

        // A accepts while B blocks A, at maximum contention.
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let accepter = {
            let social = social.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                social.accept_friend_request(&a, &b).expect("accept");
            })
        };
        let blocker = {
            let social = social.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                social.block(&b, &a).expect("block");
            })
        };
        accepter.join().expect("accept thread");
        blocker.join().expect("block thread");

        let blocked = social.is_blocked_between(&a, &b).expect("is_blocked");
        let friends = social.are_friends(&a, &b).expect("are_friends");
        assert!(
            !(blocked && friends),
            "trial {trial}: pair is simultaneously blocked and friends — the friendship is a \
             live authorization credential that survived the block"
        );
    }
}

/// A populated group must never be left with zero admins. `demote` refuses to remove the LAST
/// admin, but that guard is a `count(*)` with no lock: two concurrent demotes of two DIFFERENT
/// admins each read the same count, each conclude they are not removing the last one, and each
/// delete a different row — so no row-level conflict ever occurs and both commit.
///
/// The result is permanent: `promote` requires the caller to already be an admin, and nothing
/// bootstraps an admin retroactively, so the group becomes unmanageable forever.
#[test]
fn concurrent_demotes_never_leave_a_group_without_an_admin() {
    let groups = common::shared_groups();
    let relay = common::shared_relay();
    const TRIALS: usize = 30;

    for trial in 0..TRIALS {
        let conversation_id: [u8; 16] = DeviceId::random().as_bytes().try_into().expect("16 bytes");
        let a = AccountId::random();
        let b = AccountId::random();

        relay
            .create_conversation(conversation_id, a, DeviceId::random(), false)
            .expect("create");
        relay
            .add_member(&conversation_id, b, DeviceId::random())
            .expect("add b");
        groups
            .bootstrap_admin(&conversation_id, &a)
            .expect("admin a");
        assert!(groups.promote(&conversation_id, &b).expect("promote b"));

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let mut handles = Vec::new();
        for target in [a, b] {
            let groups = groups.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                groups.demote(&conversation_id, &target).expect("demote");
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }

        let admins: i64 = postgres::Client::connect(&common::db_url(), postgres::NoTls)
            .expect("connect")
            .query_one(
                "SELECT count(*) FROM group_admins WHERE conversation_id = $1",
                &[&conversation_id.as_slice()],
            )
            .expect("count admins")
            .get(0);
        assert!(
            admins >= 1,
            "trial {trial}: populated group left with {admins} admins — it is now permanently \
             unmanageable, since promote itself requires an existing admin"
        );
    }
}

/// The last member to leave must delete the conversation. Concurrently, each leaver's
/// `count(*)` of the remaining members can still see the other, so both take the "someone is
/// left" branch and neither cleans up — leaving a memberless `conversations` row that
/// `list_conversations` cannot surface (it joins through `conversation_members`) and no endpoint
/// can reach or purge.
#[test]
fn concurrent_leaves_leave_no_orphan_conversation() {
    let groups = common::shared_groups();
    let relay = common::shared_relay();
    const TRIALS: usize = 30;

    for trial in 0..TRIALS {
        let conversation_id: [u8; 16] = DeviceId::random().as_bytes().try_into().expect("16 bytes");
        let a = AccountId::random();
        let b = AccountId::random();

        relay
            .create_conversation(conversation_id, a, DeviceId::random(), false)
            .expect("create");
        relay
            .add_member(&conversation_id, b, DeviceId::random())
            .expect("add b");

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let mut handles = Vec::new();
        for who in [a, b] {
            let groups = groups.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                groups
                    .leave_conversation(&conversation_id, &who)
                    .expect("leave");
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }

        let mut client =
            postgres::Client::connect(&common::db_url(), postgres::NoTls).expect("connect");
        let members: i64 = client
            .query_one(
                "SELECT count(*) FROM conversation_members WHERE conversation_id = $1",
                &[&conversation_id.as_slice()],
            )
            .expect("count members")
            .get(0);
        let conversations: i64 = client
            .query_one(
                "SELECT count(*) FROM conversations WHERE conversation_id = $1",
                &[&conversation_id.as_slice()],
            )
            .expect("count conversations")
            .get(0);

        assert_eq!(members, 0, "trial {trial}: both members left");
        assert_eq!(
            conversations, 0,
            "trial {trial}: memberless conversation row survived — unreachable and unpurgeable"
        );
    }
}

/// Creating a conversation and bootstrapping its first admin must be ONE transaction.
///
/// They used to be two, on two pooled connections: the conversation committed first, so any
/// failure before the admin insert left a conversation nobody can ever administer — `promote`
/// requires an existing admin, and only a member LEAVING triggers auto-promotion.
///
/// Atomicity is tested the only way that actually proves it: fail deliberately after the first
/// write and assert the first write did not survive.
#[test]
fn create_conversation_rolls_back_when_admin_bootstrap_fails() {
    use auth_core::store::StoreError;
    use nedwons_api::relay::PgRelay;

    let pool = common::shared_relay().pool_clone();
    let conversation_id: [u8; 16] = DeviceId::random().as_bytes().try_into().expect("16 bytes");
    let creator = AccountId::random();

    let result: auth_core::store::StoreResult<()> = nedwons_api::tx::transaction(&pool, |txn| {
        PgRelay::create_conversation_in_txn(
            txn,
            conversation_id,
            creator,
            DeviceId::random(),
            false,
        )?;
        Err(StoreError(
            "simulated failure before the admin is set".into(),
        ))
    });
    assert!(result.is_err(), "the simulated failure must propagate");

    let mut client =
        postgres::Client::connect(&common::db_url(), postgres::NoTls).expect("connect");
    let conversations: i64 = client
        .query_one(
            "SELECT count(*) FROM conversations WHERE conversation_id = $1",
            &[&conversation_id.as_slice()],
        )
        .expect("count")
        .get(0);
    let members: i64 = client
        .query_one(
            "SELECT count(*) FROM conversation_members WHERE conversation_id = $1",
            &[&conversation_id.as_slice()],
        )
        .expect("count")
        .get(0);

    assert_eq!(
        conversations, 0,
        "an adminless conversation must not survive — it would be unadministrable forever"
    );
    assert_eq!(members, 0, "its routing membership must not survive either");

    // Contrast, so this test measures the fix rather than merely restating that PostgreSQL rolls
    // back: the OLD shape is still expressible through the self-committing public method, and it
    // demonstrably strands exactly the row the transactional path refuses to leave behind.
    let stranded: [u8; 16] = DeviceId::random().as_bytes().try_into().expect("16 bytes");
    common::shared_relay()
        .create_conversation(stranded, AccountId::random(), DeviceId::random(), false)
        .expect("create via the self-committing method");
    // ...a failure here (where bootstrap_admin would have run) ends the request.
    let stranded_rows: i64 = client
        .query_one(
            "SELECT count(*) FROM conversations c
             WHERE c.conversation_id = $1
               AND NOT EXISTS (SELECT 1 FROM group_admins a
                               WHERE a.conversation_id = c.conversation_id)",
            &[&stranded.as_slice()],
        )
        .expect("count")
        .get(0);
    assert_eq!(
        stranded_rows, 1,
        "sanity: the old two-transaction shape is what strands an adminless conversation, which \
         is precisely what the transactional path above prevents"
    );
}

/// Accepting an invite BURNS a use, so the resulting membership must land in the same
/// transaction. Committed separately, a failure in between spends the joiner's one chance to join
/// without joining them, and the invite's use budget is corrupted with nothing to show for it.
#[test]
fn invite_use_is_not_burned_when_the_membership_write_fails() {
    use auth_core::store::StoreError;
    use nedwons_api::groups::PgGroups;

    let groups = common::shared_groups();
    let relay = common::shared_relay();
    let pool = relay.pool_clone();

    let conversation_id: [u8; 16] = DeviceId::random().as_bytes().try_into().expect("16 bytes");
    let owner = AccountId::random();
    let joiner = AccountId::random();
    relay
        .create_conversation(conversation_id, owner, DeviceId::random(), false)
        .expect("create");

    let mut token = [0u8; 32];
    token[..16].copy_from_slice(DeviceId::random().as_bytes());
    token[16..].copy_from_slice(DeviceId::random().as_bytes());
    groups
        .create_invite(&conversation_id, &owner, token, 3600, 5)
        .expect("create invite");

    let result: auth_core::store::StoreResult<()> = nedwons_api::tx::transaction(&pool, |txn| {
        let outcome = PgGroups::accept_invite_in_txn(txn, &token, &joiner)?;
        assert!(
            matches!(outcome, nedwons_api::groups::InviteOutcome::Joined { .. }),
            "the invite should be accepted before the simulated failure"
        );
        Err(StoreError(
            "simulated failure adding routing membership".into(),
        ))
    });
    assert!(result.is_err(), "the simulated failure must propagate");

    let mut client =
        postgres::Client::connect(&common::db_url(), postgres::NoTls).expect("connect");
    let uses: i32 = client
        .query_one(
            "SELECT uses FROM group_invites WHERE token = $1",
            &[&token.as_slice()],
        )
        .expect("read uses")
        .get(0);
    assert_eq!(
        uses, 0,
        "the invite use must be returned when the membership write fails"
    );
}

/// Expired-row purge removes old challenges and access tokens (retention hygiene).
#[test]
fn purge_removes_expired_rows() {
    let (stores, _service) = setup();
    let txn_id = TxnId::random();
    stores
        .put(ChallengeRecord {
            txn_id,
            account_id: AccountId::random(),
            device_id: DeviceId::random(),
            action: Action::Login,
            nonce: [9u8; 32],
            expires_at: 1, // long past
        })
        .expect("put");
    stores.purge_expired(1_000_000).expect("purge");
    assert!(stores.consume(&txn_id).expect("consume").is_none());
}
