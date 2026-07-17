//! The end-to-end E2EE evidence for THREAT_MODEL.md INV-1 / RISK_REGISTER R-104: real MLS
//! ciphertext (from `mls-core`) is routed through the real HTTP relay backed by real
//! PostgreSQL, and a direct query of the `envelopes` table confirms the stored bytes contain
//! NO plaintext. The `sentinel-api` library never links `mls-core`; only this test does.

mod common;

use axum::http::StatusCode;
use common::{db_url, get_auth, http_register, make_app, post_json_auth, unique_username};
use mls_core::{Incoming, Member};
use serde_json::json;

/// Query the envelopes table directly and assert none of the stored ciphertexts contain the
/// given plaintext. Runs on a blocking thread (the sync postgres client owns a runtime).
async fn assert_no_plaintext_in_db(recipient_device_hex: String, plaintext: Vec<u8>) {
    tokio::task::spawn_blocking(move || {
        let mut client = postgres::Client::connect(&db_url(), postgres::NoTls).expect("db connect");
        let device = hex::decode(&recipient_device_hex).expect("hex");
        let rows = client
            .query(
                "SELECT ciphertext FROM envelopes WHERE recipient_device = $1",
                &[&device],
            )
            .expect("query");
        assert!(!rows.is_empty(), "expected stored envelopes to inspect");
        for row in rows {
            let ciphertext: Vec<u8> = row.get(0);
            assert!(
                !contains(&ciphertext, &plaintext),
                "server DB envelope must not contain plaintext (INV-1)"
            );
        }
    })
    .await
    .expect("db inspection task");
}

#[tokio::test]
async fn mls_message_routed_through_relay_leaves_no_plaintext() {
    let app = make_app(100_000).await;

    // Two registered users, each with an access token.
    let (_alice_dev, alice) = http_register(&app, &unique_username("alice")).await;
    let (_bob_dev, bob) = http_register(&app, &unique_username("bob")).await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    let bob_device_hex = bob["device_id"].as_str().unwrap().to_string();
    let bob_account_hex = bob["account_id"].as_str().unwrap();

    // MLS identities.
    let alice_mls = Member::new(b"alice-mls").expect("alice mls");
    let bob_mls = Member::new(b"bob-mls").expect("bob mls");

    // Bob publishes his key package to the relay.
    let (status, _) = post_json_auth(
        &app,
        "/v1/keypackages",
        bob_token,
        json!({ "key_package": hex::encode(bob_mls.key_package_bytes().unwrap()) }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Alice claims Bob's key package to add him.
    let (status, claimed) = post_json_auth(
        &app,
        "/v1/keypackages/claim",
        alice_token,
        json!({ "account_id": bob_account_hex }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "claim: {claimed}");
    let bob_key_package = hex::decode(claimed["key_package"].as_str().unwrap()).unwrap();

    // Alice builds the MLS group and adds Bob (produces the Welcome).
    let mut alice_group = alice_mls.create_group().expect("group");
    let add = alice_group
        .add_member(&alice_mls, &bob_key_package)
        .expect("add bob");

    // Alice creates the relay conversation and adds Bob to routing.
    let (status, conv) = post_json_auth(&app, "/v1/conversations", alice_token, json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let conversation_id = conv["conversation_id"].as_str().unwrap().to_string();
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/members"),
        alice_token,
        json!({ "account_id": bob_account_hex }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Alice sends the Welcome (targeted to Bob), then an encrypted application message
    // (fanned out server-side to all other members — here just Bob).
    let plaintext = b"the exchange point is under the north bridge".to_vec();
    let ciphertext = alice_group
        .encrypt(&alice_mls, &plaintext)
        .expect("encrypt");

    let (status, receipt) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/welcome"),
        alice_token,
        json!({
            "recipient_device": bob_device_hex,
            "ciphertext": hex::encode(&add.welcome),
            "idempotency_key": hex::encode([1u8; 16]),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "welcome: {receipt}");

    let (status, receipt) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/messages"),
        alice_token,
        json!({ "ciphertext": hex::encode(&ciphertext), "idempotency_key": hex::encode([2u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "message: {receipt}");
    assert_eq!(receipt["delivered"], 1, "fanned out to Bob");

    // Idempotent retry of the same message is a no-op (0 newly delivered).
    let (status, retry) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/messages"),
        alice_token,
        json!({ "ciphertext": hex::encode(&ciphertext), "idempotency_key": hex::encode([2u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(retry["delivered"], 0, "idempotent retry queues nothing new");

    // INV-1 EVIDENCE: the plaintext is nowhere in the stored envelopes.
    assert_no_plaintext_in_db(bob_device_hex.clone(), plaintext.clone()).await;

    // Bob fetches his inbox: the Welcome first, then the message.
    let (status, inbox) = get_auth(&app, "/v1/inbox", bob_token).await;
    assert_eq!(status, StatusCode::OK);
    let envelopes = inbox.as_array().expect("array");
    assert_eq!(envelopes.len(), 2, "welcome + message");

    let welcome_bytes = hex::decode(envelopes[0]["ciphertext"].as_str().unwrap()).unwrap();
    let message_bytes = hex::decode(envelopes[1]["ciphertext"].as_str().unwrap()).unwrap();

    // Bob joins from the Welcome and decrypts the application message.
    let mut bob_group = bob_mls
        .join_from_welcome(&welcome_bytes)
        .expect("bob joins");
    match bob_group
        .process(&bob_mls, &message_bytes)
        .expect("process")
    {
        Incoming::Application(bytes) => assert_eq!(bytes, plaintext),
        Incoming::StateAdvanced => panic!("expected the application message"),
    }

    // At-least-once: a peek does NOT drain. Re-peeking returns the same envelopes until Bob
    // acks — so a crash between peek and persist loses nothing.
    let (status, inbox_again) = get_auth(&app, "/v1/inbox", bob_token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        inbox_again.as_array().unwrap().len(),
        2,
        "peek is non-destructive until ack"
    );

    // Bob persisted the messages; now he acks them.
    let ids: Vec<i64> = envelopes
        .iter()
        .map(|e| e["id"].as_i64().unwrap())
        .collect();
    let (status, _) = post_json_auth(&app, "/v1/inbox/ack", bob_token, json!({ "ids": ids })).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Now the inbox is drained.
    let (status, inbox_final) = get_auth(&app, "/v1/inbox", bob_token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inbox_final.as_array().unwrap().len(), 0);
}

/// At-least-once delivery: peeking is non-destructive, and only an explicit ack removes mail
/// from the queue. This is the anti-message-loss guarantee — a client that crashes after
/// peeking but before persisting re-fetches the same envelopes.
#[tokio::test]
async fn peek_is_non_destructive_until_ack() {
    let app = make_app(100_000).await;
    let (_a, alice) = http_register(&app, &unique_username("relsend")).await;
    let (_b, bob) = http_register(&app, &unique_username("relrecv")).await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    let bob_account = bob["account_id"].as_str().unwrap();

    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice_token, json!({})).await;
    let conversation_id = conv["conversation_id"].as_str().unwrap();
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/members"),
        alice_token,
        json!({ "account_id": bob_account }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/messages"),
        alice_token,
        json!({ "ciphertext": hex::encode(b"opaque"), "idempotency_key": hex::encode([5u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Two peeks in a row return the same envelope (simulating a crash before persist).
    let (_, first) = get_auth(&app, "/v1/inbox", bob_token).await;
    let (_, second) = get_auth(&app, "/v1/inbox", bob_token).await;
    assert_eq!(first.as_array().unwrap().len(), 1);
    assert_eq!(second.as_array().unwrap().len(), 1);
    assert_eq!(first[0]["id"], second[0]["id"], "same envelope re-served");

    // A device cannot ack another device's mail: alice acking bob's id is a no-op.
    let bob_id = first[0]["id"].as_i64().unwrap();
    let (status, _) = post_json_auth(
        &app,
        "/v1/inbox/ack",
        alice_token,
        json!({ "ids": [bob_id] }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, still_there) = get_auth(&app, "/v1/inbox", bob_token).await;
    assert_eq!(
        still_there.as_array().unwrap().len(),
        1,
        "cross-device ack is a no-op"
    );

    // Bob's own ack drains it.
    let (status, _) =
        post_json_auth(&app, "/v1/inbox/ack", bob_token, json!({ "ids": [bob_id] })).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, drained) = get_auth(&app, "/v1/inbox", bob_token).await;
    assert_eq!(drained.as_array().unwrap().len(), 0);
}

/// A non-member cannot post into a conversation (object-level authz, no IDOR).
#[tokio::test]
async fn non_member_cannot_send_to_conversation() {
    let app = make_app(100_000).await;
    let (_a, alice) = http_register(&app, &unique_username("owner")).await;
    let (_b, bob) = http_register(&app, &unique_username("intruder")).await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();

    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice_token, json!({})).await;
    let conversation_id = conv["conversation_id"].as_str().unwrap();

    // Bob is not a member; his send is forbidden.
    let (status, body) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/messages"),
        bob_token,
        json!({ "ciphertext": hex::encode(b"x"), "idempotency_key": hex::encode([9u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
}

/// Long-poll: a waiting inbox returns promptly when a message is sent, without the client
/// polling — near-zero idle delivery latency. Also proves the notify path wakes the waiter.
#[tokio::test]
async fn inbox_long_poll_wakes_on_delivery() {
    let app = make_app(100_000).await;
    let (_a, alice) = http_register(&app, &unique_username("lpsender")).await;
    let (_b, bob) = http_register(&app, &unique_username("lprecv")).await;
    let alice_token = alice["access_token"].as_str().unwrap().to_string();
    let bob_token = bob["access_token"].as_str().unwrap().to_string();
    let bob_account = bob["account_id"].as_str().unwrap().to_string();

    // Bob publishes a key package; Alice sets up a conversation with Bob.
    let bob_mls = Member::new(b"bob-lp").expect("bob mls");
    let (status, _) = post_json_auth(
        &app,
        "/v1/keypackages",
        &bob_token,
        json!({ "key_package": hex::encode(bob_mls.key_package_bytes().unwrap()) }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, conv) = post_json_auth(&app, "/v1/conversations", &alice_token, json!({})).await;
    let conversation_id = conv["conversation_id"].as_str().unwrap().to_string();
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/members"),
        &alice_token,
        json!({ "account_id": bob_account }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Bob starts a long-poll (up to 10s). Alice sends shortly after; Bob should return well
    // under the timeout.
    let app_bob = app.clone();
    let poll = tokio::spawn(async move {
        let start = std::time::Instant::now();
        let (status, inbox) = get_auth(&app_bob, "/v1/inbox?wait=10", &bob_token).await;
        (status, inbox, start.elapsed())
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/messages"),
        &alice_token,
        json!({ "ciphertext": hex::encode(b"ping"), "idempotency_key": hex::encode([7u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, inbox, elapsed) = poll.await.expect("poll task");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        inbox.as_array().unwrap().len(),
        1,
        "long-poll returned the message"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "long-poll should wake on delivery, not wait out the timeout (took {elapsed:?})"
    );
}

/// Relay endpoints require authentication.
#[tokio::test]
async fn relay_requires_auth() {
    let app = make_app(100_000).await;
    let (status, _) = get_auth(&app, "/v1/inbox", "deadbeef").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// DATA_RETENTION.md: an ack must PURGE the envelope row (the device is the store — the server
/// must not retain delivered ciphertext), and undelivered envelopes past the queue TTL are
/// deleted by the retention job.
#[tokio::test]
async fn ack_deletes_rows_and_ttl_purges_stale_mail() {
    let app = make_app(100_000).await;
    let (_a, alice) = http_register(&app, &unique_username("reta")).await;
    let (_b, bob) = http_register(&app, &unique_username("retb")).await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    let bob_account = bob["account_id"].as_str().unwrap();
    let bob_device_hex = bob["device_id"].as_str().unwrap().to_string();

    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice_token, json!({})).await;
    let conversation_id = conv["conversation_id"].as_str().unwrap();
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/members"),
        alice_token,
        json!({ "account_id": bob_account }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // First message: peek + ack, then the row must be GONE from the DB (not merely hidden).
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/messages"),
        alice_token,
        json!({ "ciphertext": hex::encode(b"acked-away"), "idempotency_key": hex::encode([11u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, inbox) = get_auth(&app, "/v1/inbox", bob_token).await;
    let id = inbox[0]["id"].as_i64().unwrap();
    let (status, _) =
        post_json_auth(&app, "/v1/inbox/ack", bob_token, json!({ "ids": [id] })).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let device_hex = bob_device_hex.clone();
    tokio::task::spawn_blocking(move || {
        let mut client = postgres::Client::connect(&db_url(), postgres::NoTls).expect("db");
        let device = hex::decode(&device_hex).expect("hex");
        let rows = client
            .query(
                "SELECT 1 FROM envelopes WHERE recipient_device = $1",
                &[&device],
            )
            .expect("query");
        assert!(
            rows.is_empty(),
            "acked envelope must be DELETED, not retained"
        );
    })
    .await
    .expect("db check");

    // Second message: never acked. Backdate past the 30-day TTL and run the retention purge.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/messages"),
        alice_token,
        json!({ "ciphertext": hex::encode(b"stale"), "idempotency_key": hex::encode([12u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let device_hex = bob_device_hex.clone();
    let purged = tokio::task::spawn_blocking(move || {
        let mut client = postgres::Client::connect(&db_url(), postgres::NoTls).expect("db");
        let device = hex::decode(&device_hex).expect("hex");
        client
            .execute(
                "UPDATE envelopes SET created_at = now() - interval '31 days'
                 WHERE recipient_device = $1",
                &[&device],
            )
            .expect("backdate");
        common::shared_relay()
            .purge_stale_envelopes(30)
            .expect("purge")
    })
    .await
    .expect("purge task");
    assert!(purged >= 1, "TTL purge must remove the stale envelope");

    let (_, drained) = get_auth(&app, "/v1/inbox", bob_token).await;
    assert_eq!(
        drained.as_array().unwrap().len(),
        0,
        "stale envelope must be gone after TTL purge"
    );
}
