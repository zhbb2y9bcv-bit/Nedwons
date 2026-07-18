//! Security invariants exercised against a REAL PostgreSQL — this is the evidence that
//! closes RISK_REGISTER R-102: the SQL implementations enforce the same atomicity the
//! in-memory stores promised (ADR-0006), including under true concurrency.

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
    use auth_core::store::DeviceRecord;
    const MAX: usize = auth_core::AuthService::MAX_ACTIVE_DEVICES;
    let new_device = |account| DeviceRecord {
        device_id: DeviceId::random(),
        account_id: account,
        public_key: vec![0x04; 65],
        revoked: false,
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
