//! Blocker-6 evidence: an authenticated account cannot bulk-enumerate users or spam requests, and
//! the limit is shared across API instances rather than multiplied by them.
//!
//! The pre-existing limiter was per-IP and per-process, which is the wrong shape for abuse
//! control twice over: per-process multiplies the effective limit by the instance count behind a
//! load balancer, and per-IP is both too coarse (a carrier NAT shares one address, so one abuser
//! throttles thousands of bystanders) and too weak (addresses are cheap; rotating a proxy pool
//! resets the counter while the offending ACCOUNT is untouched).

mod common;

use axum::http::StatusCode;
use common::{
    db_url, get_auth, http_register, make_app, post_json_auth, seed_account, unique_username,
};
use nedwons_api::quota::{Quota, Quotas, FRIEND_REQUESTS, PROFILE_SEARCH};
use serde_json::json;

/// One pool for the whole test binary. A pool per test would multiply connections across
/// parallel tests and exhaust PostgreSQL, which surfaces as spurious quota errors.
fn shared_pool() -> nedwons_api::pgstore::PgPool {
    static POOL: std::sync::OnceLock<nedwons_api::pgstore::PgPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        common::migrate_once(&db_url());
        nedwons_api::build_pool(&db_url(), 24).expect("pool")
    })
    .clone()
}

fn quotas() -> Quotas {
    Quotas::new(shared_pool())
}

/// A window-aligned instant, so a test that adds a few seconds stays inside the same window.
/// (`window_start` is `floor(now / window)`, so an arbitrary `now` sits at an arbitrary offset and
/// `now + 30` can silently land in the NEXT window.)
fn window_start(window_secs: i64, nth: i64) -> i64 {
    window_secs * nth
}

/// The counter itself: exactly `limit` units pass, the rest are refused, and a later window is
/// fresh again.
#[test]
fn a_quota_admits_exactly_its_limit_then_refuses() {
    let quotas = quotas();
    let (subject, _) = seed_account();
    let quota = Quota::new("test_basic", 3, 60);
    let now = window_start(60, 20_000);

    for i in 1..=3 {
        assert!(
            quotas
                .consume_account(quota, &subject, now)
                .expect("consume"),
            "unit {i} is within the limit"
        );
    }
    assert!(
        !quotas
            .consume_account(quota, &subject, now)
            .expect("consume"),
        "the fourth unit exceeds the limit"
    );

    // Still refused later in the SAME window...
    assert!(!quotas
        .consume_account(quota, &subject, now + 30)
        .expect("consume"));
    // ...and admitted again once the window rolls over.
    assert!(quotas
        .consume_account(quota, &subject, now + 120)
        .expect("consume"));
}

/// A refused attempt still counts. Otherwise someone hammering past their limit gets a free retry
/// every time they are refused and the window never actually elapses for them.
#[test]
fn refused_attempts_still_consume_the_window() {
    let quotas = quotas();
    let (subject, _) = seed_account();
    let quota = Quota::new("test_refused_counts", 1, 3600);
    let now = window_start(3600, 600);

    assert!(quotas.consume_account(quota, &subject, now).expect("first"));
    for _ in 0..5 {
        assert!(!quotas
            .consume_account(quota, &subject, now)
            .expect("refused"));
    }

    let count: i32 = postgres::Client::connect(&db_url(), postgres::NoTls)
        .expect("db")
        .query_one(
            "SELECT count FROM rate_counters WHERE scope = $1 AND subject = $2",
            &[&quota.scope, &subject.as_bytes()],
        )
        .expect("count")
        .get(0);
    assert_eq!(count, 6, "every attempt, admitted or refused, is counted");
}

/// Quotas are per-subject: one account exhausting its budget must not throttle anyone else. This
/// is precisely what a per-IP limit gets wrong behind a shared address.
#[test]
fn one_account_exhausting_its_quota_does_not_affect_another() {
    let quotas = quotas();
    let (noisy, _) = seed_account();
    let (quiet, _) = seed_account();
    let quota = Quota::new("test_isolation", 2, 3600);
    let now = window_start(3600, 700);

    while quotas.consume_account(quota, &noisy, now).expect("consume") {}
    assert!(
        quotas.consume_account(quota, &quiet, now).expect("consume"),
        "a second account has its own budget"
    );
}

/// The counter is shared through the database, so two API instances cannot each grant a full
/// budget. Two independently built `Quotas` over the same database stand in for two instances.
#[test]
fn the_quota_is_shared_across_instances() {
    let instance_a = quotas();
    let instance_b = quotas();
    let (subject, _) = seed_account();
    let quota = Quota::new("test_shared", 4, 3600);
    let now = window_start(3600, 800);

    let mut admitted = 0;
    for i in 0..10 {
        let instance = if i % 2 == 0 { &instance_a } else { &instance_b };
        if instance
            .consume_account(quota, &subject, now)
            .expect("consume")
        {
            admitted += 1;
        }
    }
    assert_eq!(
        admitted, 4,
        "the budget is the quota, not the quota times the instance count"
    );
}

/// Concurrent racers must not oversubscribe: the increment returns its post-increment value under
/// the row lock, so the count cannot drift.
#[test]
fn concurrent_consumers_cannot_exceed_the_limit() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    let quotas = Arc::new(quotas());
    let (subject, _) = seed_account();
    let quota = Quota::new("test_concurrent", 5, 3600);
    let now = window_start(3600, 900);

    const RACERS: usize = 20;
    let admitted = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(RACERS));
    let mut handles = Vec::new();
    for _ in 0..RACERS {
        let (quotas, admitted, barrier) = (quotas.clone(), admitted.clone(), barrier.clone());
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            if quotas
                .consume_account(quota, &subject, now)
                .expect("consume")
            {
                admitted.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join().expect("racer");
    }
    assert_eq!(
        admitted.load(Ordering::SeqCst),
        5,
        "exactly the limit is admitted under contention"
    );
}

/// End to end: an authenticated account cannot walk the directory. Search is the ONLY discovery
/// surface (usernames only), so this is the enumeration bound.
#[tokio::test]
async fn search_cannot_be_used_to_bulk_enumerate() {
    let app = make_app(1_000_000).await; // per-IP limit out of the way; the ACCOUNT quota is the subject
    let (_device, me) = http_register(&app, &unique_username("enum")).await;
    let token = me["access_token"].as_str().unwrap();

    let mut refused = None;
    for i in 0..(PROFILE_SEARCH.limit + 10) {
        let (status, _) = get_auth(&app, &format!("/v1/profiles/search?q=aa{i}"), token).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            refused = Some(i);
            break;
        }
    }
    let refused = refused.expect("search must become rate limited before unlimited enumeration");
    assert!(
        refused <= PROFILE_SEARCH.limit,
        "refusal must arrive at the quota, got it after {refused} searches"
    );
}

/// End to end: friend requests are bounded, so an account cannot spray strangers.
#[tokio::test]
async fn friend_requests_are_bounded_per_account() {
    let app = make_app(1_000_000).await;
    let (_device, me) = http_register(&app, &unique_username("spam")).await;
    let token = me["access_token"].as_str().unwrap();

    // Targets need to exist, but the quota should bite well before we run out of them.
    let targets: Vec<String> = tokio::task::spawn_blocking(|| {
        (0..5)
            .map(|_| hex::encode(seed_account().0.as_bytes()))
            .collect()
    })
    .await
    .expect("seed targets");

    let mut sent = 0;
    let mut rate_limited = false;
    for i in 0..(FRIEND_REQUESTS.limit + 5) {
        let target = &targets[(i as usize) % targets.len()];
        let (status, _) = post_json_auth(
            &app,
            "/v1/friends/request",
            token,
            json!({ "account_id": target }),
        )
        .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            rate_limited = true;
            break;
        }
        sent += 1;
    }
    assert!(
        rate_limited,
        "friend requests must become rate limited; sent {sent} without refusal"
    );
    assert!(
        sent <= FRIEND_REQUESTS.limit,
        "refusal must arrive at the quota, got it after {sent}"
    );
}

/// Discovery is username-only by design: there must be no phone-number or address-book path at
/// all. Asserted against the router's own surface rather than trusting documentation.
#[tokio::test]
async fn no_phone_or_contact_discovery_endpoint_exists() {
    let app = make_app(100_000).await;
    let (_device, me) = http_register(&app, &unique_username("nophone")).await;
    let token = me["access_token"].as_str().unwrap();

    for path in [
        "/v1/contacts",
        "/v1/contacts/upload",
        "/v1/discovery/phone",
        "/v1/profiles/by-phone",
        "/v1/profiles/lookup?phone=15551234567",
        "/v1/address-book",
    ] {
        let (status, _) = get_auth(&app, path, token).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{path} must not exist: discovery is username-only (ABUSE_MODEL.md)"
        );
    }
}
