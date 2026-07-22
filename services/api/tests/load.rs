//! Load-shaped tests, bounded for CI, validating PERFORMANCE.md under concurrency: server-side
//! fan-out, idempotent dedup under a duplicate storm, and — the important one — that idle
//! long-poll waiters hold NO database connection, since more waiters than pool slots still
//! deliver where parking-with-a-connection would deadlock.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{
    befriend, db_url, get_auth, http_register, make_app, post_json_auth, unique_username,
};
use serde_json::json;

async fn count_envelopes_for(device_hex: String) -> i64 {
    tokio::task::spawn_blocking(move || {
        let mut client = postgres::Client::connect(&db_url(), postgres::NoTls).expect("db");
        let device = hex::decode(&device_hex).expect("hex");
        client
            .query_one(
                "SELECT count(*) FROM envelopes WHERE recipient_device = $1",
                &[&device],
            )
            .expect("count")
            .get::<_, i64>(0)
    })
    .await
    .expect("count task")
}

/// One upload fans out to every member device (N→1 uploads for the client).
#[tokio::test]
async fn group_fanout_delivers_to_all_members() {
    let app = make_app(100_000).await;
    let (_a, alice) = http_register(&app, &unique_username("gowner")).await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let alice_account = alice["account_id"].as_str().unwrap();
    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice_token, json!({})).await;
    let conv_id = conv["conversation_id"].as_str().unwrap().to_string();

    const MEMBERS: usize = 12;
    for i in 0..MEMBERS {
        let (_d, member) = http_register(&app, &unique_username(&format!("gm{i}"))).await;
        let account = member["account_id"].as_str().unwrap();
        let member_token = member["access_token"].as_str().unwrap();
        befriend(&app, alice_token, alice_account, member_token, account).await;
        let (status, _) = post_json_auth(
            &app,
            &format!("/v1/conversations/{conv_id}/members"),
            alice_token,
            json!({ "account_id": account }),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    let (status, receipt) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv_id}/messages"),
        alice_token,
        json!({ "ciphertext": hex::encode(b"broadcast"), "idempotency_key": hex::encode([1u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        receipt["delivered"], MEMBERS,
        "one upload fanned out to all members"
    );
}

/// A storm of concurrent duplicate sends (same idempotency key) queues exactly one envelope.
#[tokio::test]
async fn concurrent_duplicate_sends_dedup_to_one() {
    let app = make_app(100_000).await;
    let (_a, alice) = http_register(&app, &unique_username("idsend")).await;
    let (_b, bob) = http_register(&app, &unique_username("idrecv")).await;
    let alice_token = alice["access_token"].as_str().unwrap().to_string();
    let bob_device = bob["device_id"].as_str().unwrap().to_string();
    let bob_account = bob["account_id"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    let alice_account = alice["account_id"].as_str().unwrap();
    befriend(&app, &alice_token, alice_account, bob_token, bob_account).await;
    let (_, conv) = post_json_auth(&app, "/v1/conversations", &alice_token, json!({})).await;
    let conv_id = conv["conversation_id"].as_str().unwrap().to_string();
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv_id}/members"),
        &alice_token,
        json!({ "account_id": bob_account }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    const DUPES: usize = 10;
    let key = hex::encode([42u8; 16]);
    let mut handles = Vec::new();
    for _ in 0..DUPES {
        let app = app.clone();
        let token = alice_token.clone();
        let cid = conv_id.clone();
        let k = key.clone();
        handles.push(tokio::spawn(async move {
            let (status, receipt) = post_json_auth(
                &app,
                &format!("/v1/conversations/{cid}/messages"),
                &token,
                json!({ "ciphertext": hex::encode(b"dup"), "idempotency_key": k }),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            receipt["delivered"].as_u64().unwrap()
        }));
    }
    let mut total_delivered = 0u64;
    for h in handles {
        total_delivered += h.await.unwrap();
    }
    assert_eq!(
        total_delivered, 1,
        "exactly one concurrent duplicate queued the envelope"
    );
    assert_eq!(
        count_envelopes_for(bob_device).await,
        1,
        "one row in the DB"
    );
}

/// Idle long-poll waiters hold no DB connection. We park MORE waiters than the connection
/// pool (24), then deliver — which is only possible if parking is connectionless.
#[tokio::test]
async fn idle_waiters_exceed_pool_without_deadlock() {
    let app = make_app(100_000).await;
    let (_a, alice) = http_register(&app, &unique_username("wowner")).await;
    let alice_token = alice["access_token"].as_str().unwrap().to_string();
    let alice_account = alice["account_id"].as_str().unwrap().to_string();
    let (_, conv) = post_json_auth(&app, "/v1/conversations", &alice_token, json!({})).await;
    let conv_id = conv["conversation_id"].as_str().unwrap().to_string();

    const WAITERS: usize = 30; // > pool size (24)

    // Phase 1: register all members and add them to the conversation (this is the slow part —
    // Argon2 per registration — so it must NOT overlap the waiters' timeout windows).
    let mut tokens = Vec::new();
    for i in 0..WAITERS {
        let (_d, member) = http_register(&app, &unique_username(&format!("w{i}"))).await;
        let token = member["access_token"].as_str().unwrap().to_string();
        let account = member["account_id"].as_str().unwrap();
        befriend(&app, &alice_token, &alice_account, &token, account).await;
        let (status, _) = post_json_auth(
            &app,
            &format!("/v1/conversations/{conv_id}/members"),
            &alice_token,
            json!({ "account_id": account }),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        tokens.push(token);
    }

    // Phase 2: park every waiter now, so their wait windows all start fresh together.
    let mut receivers = Vec::new();
    for token in tokens {
        let app2 = app.clone();
        receivers.push(tokio::spawn(async move {
            get_auth(&app2, "/v1/inbox?wait=8", &token).await
        }));
    }

    // Let every waiter reach its parked state.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Deliver to the whole group. If idle waiters held connections, the pool (24) would be
    // exhausted by the 30 parked waiters and this send could not acquire a connection.
    let start = std::time::Instant::now();
    let (status, receipt) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv_id}/messages"),
        &alice_token,
        json!({ "ciphertext": hex::encode(b"wake"), "idempotency_key": hex::encode([7u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "send must not deadlock on the pool");
    assert_eq!(receipt["delivered"], WAITERS);

    // The first waiter wakes promptly with its message.
    let (rstatus, inbox) = tokio::time::timeout(Duration::from_secs(4), receivers.remove(0))
        .await
        .expect("waiter returned in time")
        .expect("task ok");
    assert_eq!(rstatus, StatusCode::OK);
    assert_eq!(inbox.as_array().unwrap().len(), 1);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "a waiter woke promptly despite {WAITERS} idle waiters"
    );
    // Remaining waiters time out in the background as the test ends.
}
