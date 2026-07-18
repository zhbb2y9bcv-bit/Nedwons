//! Scale-stability tests: idempotency-key misuse must conflict (never silently drop), the
//! retention purge must drain in bounded batches, and the pool must carry overload guards.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{
    befriend, db_url, http_register, make_app, post_json_auth, shared_relay, unique_username,
};
use serde_json::json;

/// Reusing an idempotency key with a different payload (or conversation) is a client bug or an
/// attack; silently deduping would drop the new message while reporting success. It must 409.
#[tokio::test]
async fn idempotency_key_reuse_with_different_payload_conflicts() {
    let app = make_app(100_000).await;
    let (_da, alice) = http_register(&app, &unique_username("idema")).await;
    let (_db_, bob) = http_register(&app, &unique_username("idemb")).await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    let alice_account = alice["account_id"].as_str().unwrap();
    let bob_account = bob["account_id"].as_str().unwrap();
    befriend(&app, alice_token, alice_account, bob_token, bob_account).await;

    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice_token, json!({})).await;
    let conv_id = conv["conversation_id"].as_str().unwrap().to_string();
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv_id}/members"),
        alice_token,
        json!({ "account_id": bob_account }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let key = hex::encode([9u8; 16]);

    // First send succeeds.
    let (status, receipt) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv_id}/messages"),
        alice_token,
        json!({ "ciphertext": hex::encode(b"payload one"), "idempotency_key": key }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["delivered"], 1);

    // Identical retry: idempotent success, nothing new queued.
    let (status, receipt) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv_id}/messages"),
        alice_token,
        json!({ "ciphertext": hex::encode(b"payload one"), "idempotency_key": key }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["delivered"], 0, "retry must not re-queue");

    // Same key, DIFFERENT ciphertext: refused, not silently deduped.
    let (status, body) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv_id}/messages"),
        alice_token,
        json!({ "ciphertext": hex::encode(b"payload TWO"), "idempotency_key": key }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "idempotency_conflict");

    // Same key reused for a DIFFERENT conversation: also refused (the key names one send).
    let (_, conv2) = post_json_auth(&app, "/v1/conversations", alice_token, json!({})).await;
    let conv2_id = conv2["conversation_id"].as_str().unwrap().to_string();
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv2_id}/members"),
        alice_token,
        json!({ "account_id": bob_account }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv2_id}/messages"),
        alice_token,
        json!({ "ciphertext": hex::encode(b"payload one"), "idempotency_key": key }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "idempotency_conflict");
}

/// The targeted (welcome) path enforces the same contract.
#[tokio::test]
async fn welcome_idempotency_key_reuse_with_different_payload_conflicts() {
    let app = make_app(100_000).await;
    let (_da, alice) = http_register(&app, &unique_username("widema")).await;
    let (_db_, bob) = http_register(&app, &unique_username("widemb")).await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_device = bob["device_id"].as_str().unwrap();

    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice_token, json!({})).await;
    let conv_id = conv["conversation_id"].as_str().unwrap().to_string();

    let key = hex::encode([11u8; 16]);
    let (status, first) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv_id}/welcome"),
        alice_token,
        json!({ "recipient_device": bob_device, "ciphertext": hex::encode(b"welcome v1"), "idempotency_key": key }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Identical retry returns the same envelope id.
    let (status, second) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv_id}/welcome"),
        alice_token,
        json!({ "recipient_device": bob_device, "ciphertext": hex::encode(b"welcome v1"), "idempotency_key": key }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["envelope_id"], second["envelope_id"]);

    // Different payload under the same key: 409.
    let (status, body) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv_id}/welcome"),
        alice_token,
        json!({ "recipient_device": bob_device, "ciphertext": hex::encode(b"welcome v2"), "idempotency_key": key }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "idempotency_conflict");
}

/// The TTL purge drains an old backlog across bounded batches and leaves fresh mail alone.
#[test]
fn purge_drains_old_envelopes_in_bounded_batches() {
    let relay = shared_relay();
    let mut client = postgres::Client::connect(&db_url(), postgres::NoTls).expect("db");

    // A private conversation with three 40-day-old envelopes and one fresh envelope.
    let conv = [0xEEu8; 16];
    let dev_a = [0xE1u8; 16];
    let dev_b = [0xE2u8; 16];
    client
        .execute(
            "INSERT INTO conversations (conversation_id) VALUES ($1) ON CONFLICT DO NOTHING",
            &[&conv.as_slice()],
        )
        .expect("conversation");
    client
        .execute(
            "DELETE FROM envelopes WHERE conversation_id = $1",
            &[&conv.as_slice()],
        )
        .expect("clean slate");
    for i in 0..3i64 {
        client
            .execute(
                "INSERT INTO envelopes
                     (conversation_id, sender_device, recipient_device, ciphertext, created_at)
                 VALUES ($1, $2, $3, $4, now() - interval '40 days')",
                &[
                    &conv.as_slice(),
                    &dev_a.as_slice(),
                    &dev_b.as_slice(),
                    &vec![i as u8; 8],
                ],
            )
            .expect("old envelope");
    }
    client
        .execute(
            "INSERT INTO envelopes
                 (conversation_id, sender_device, recipient_device, ciphertext)
             VALUES ($1, $2, $3, $4)",
            &[
                &conv.as_slice(),
                &dev_a.as_slice(),
                &dev_b.as_slice(),
                &b"fresh".as_slice(),
            ],
        )
        .expect("fresh envelope");

    // batch_size=1 forces the loop: three old rows need three batches.
    let purged = relay
        .purge_stale_envelopes(Duration::from_secs(30 * 24 * 60 * 60), 1, 10)
        .expect("purge");
    assert!(
        purged >= 3,
        "expected at least the 3 old rows, purged {purged}"
    );

    let (old_left, fresh_left) = {
        let row = client
            .query_one(
                "SELECT
                     count(*) FILTER (WHERE created_at < now() - interval '30 days'),
                     count(*) FILTER (WHERE created_at >= now() - interval '30 days')
                 FROM envelopes WHERE conversation_id = $1",
                &[&conv.as_slice()],
            )
            .expect("count");
        (row.get::<_, i64>(0), row.get::<_, i64>(1))
    };
    assert_eq!(old_left, 0, "all stale envelopes purged");
    assert_eq!(fresh_left, 1, "fresh envelope untouched");

    // A capped run stops at max_batches instead of running unbounded (drains next tick).
    for i in 0..5i64 {
        client
            .execute(
                "INSERT INTO envelopes
                     (conversation_id, sender_device, recipient_device, ciphertext, created_at)
                 VALUES ($1, $2, $3, $4, now() - interval '40 days')",
                &[
                    &conv.as_slice(),
                    &dev_a.as_slice(),
                    &dev_b.as_slice(),
                    &vec![0x40 + i as u8; 8],
                ],
            )
            .expect("old envelope");
    }
    let purged = relay
        .purge_stale_envelopes(Duration::from_secs(30 * 24 * 60 * 60), 1, 2)
        .expect("capped purge");
    assert_eq!(purged, 2, "must stop at max_batches");
}

/// The pool sets fail-fast overload guards on every connection.
#[test]
fn pool_connections_carry_statement_timeout() {
    let pool = sentinel_api::build_pool(&db_url(), 2).expect("pool");
    let mut conn = pool.get().expect("conn");
    let st: String = conn
        .query_one("SHOW statement_timeout", &[])
        .expect("show")
        .get(0);
    assert_eq!(st, "15s");
    let it: String = conn
        .query_one("SHOW idle_in_transaction_session_timeout", &[])
        .expect("show")
        .get(0);
    assert_eq!(it, "30s");
}

/// MLS key-package hygiene: a stale (expired) prekey is never claimed or counted, and is purged.
#[test]
fn key_package_hygiene_expires_stale_prekeys() {
    use auth_core::ids::{AccountId, DeviceId};
    let relay = shared_relay();
    let mut client = postgres::Client::connect(&db_url(), postgres::NoTls).expect("db");

    let account = AccountId([0xC1u8; 16]);
    let device = DeviceId([0xC2u8; 16]);
    let acct = account.0;
    let dev = device.0;
    client
        .execute(
            "DELETE FROM key_packages WHERE account_id = $1",
            &[&acct.as_slice()],
        )
        .expect("clean slate");

    // One fresh (via publish) and one 40-day-old (backdated) key package.
    relay
        .publish_key_package(account, device, b"fresh-kp")
        .expect("publish");
    client
        .execute(
            "INSERT INTO key_packages (account_id, device_id, key_package, created_at)
             VALUES ($1, $2, $3, now() - interval '40 days')",
            &[&acct.as_slice(), &dev.as_slice(), &b"stale-kp".as_slice()],
        )
        .expect("stale insert");

    let ttl = 30 * 24 * 60 * 60;
    // Only the fresh one counts.
    assert_eq!(relay.count_available_key_packages(&device, ttl).unwrap(), 1);
    // Claim returns the fresh one, never the stale.
    let claimed = relay.claim_key_package(&account, ttl).unwrap().unwrap();
    assert_eq!(claimed.key_package, b"fresh-kp");
    // The stale one is not claimable (expired).
    assert!(relay.claim_key_package(&account, ttl).unwrap().is_none());
    // Purge removes it; the device now has zero available.
    assert!(relay.purge_expired_key_packages(ttl).unwrap() >= 1);
    assert_eq!(relay.count_available_key_packages(&device, ttl).unwrap(), 0);
}
