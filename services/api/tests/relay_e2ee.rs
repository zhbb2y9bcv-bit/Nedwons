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

    // Alice sends the Welcome, then an encrypted application message — both opaque envelopes.
    let plaintext = b"the exchange point is under the north bridge".to_vec();
    let ciphertext = alice_group
        .encrypt(&alice_mls, &plaintext)
        .expect("encrypt");

    for envelope in [add.welcome.clone(), ciphertext.clone()] {
        let (status, receipt) = post_json_auth(
            &app,
            &format!("/v1/conversations/{conversation_id}/messages"),
            alice_token,
            json!({ "recipient_device": bob_device_hex, "ciphertext": hex::encode(&envelope) }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "send: {receipt}");
        assert!(receipt["envelope_id"].is_i64() || receipt["envelope_id"].is_u64());
    }

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

    // Inbox is now drained (envelopes were marked delivered).
    let (status, inbox2) = get_auth(&app, "/v1/inbox", bob_token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inbox2.as_array().unwrap().len(), 0);
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
        json!({ "recipient_device": alice["device_id"], "ciphertext": hex::encode(b"x") }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
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
