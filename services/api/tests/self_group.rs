//! Device-linking flow for the account **self-group** (ADR-0015 option 3) over the live backend.
//!
//! A trusted device enrolls a second device (the existing ADR-0008 ceremony), then the two are
//! linked into the account's own-devices MLS group purely through the relay: discover the pending
//! sibling, claim its key package, deliver an (opaque) Welcome to it, and — once it has joined —
//! fan a (opaque) `SecretConsumed` control message out to it. The relay stays MLS-blind (it routes
//! opaque bytes by account/device only), and every endpoint is authenticated + account-scoped: a
//! stranger can neither claim a sibling's key package nor deliver into someone else's self-group.
//!
//! The MLS correctness of the self-group itself (that the fanned-out message actually consumes the
//! secret, and the conversation's sender cannot decrypt it) is proven in mls-core / mls-ffi /
//! NedwonsApp. This test proves the *transport*: the relay establishes and routes the channel.

mod common;

use axum::http::StatusCode;
use axum::Router;
use common::{
    enroll_device, get_auth, http_register, make_app, post_json_auth, unique_username, TestDevice,
};
use serde_json::{json, Value};

/// Fetch the caller's inbox and return only the **self-group** envelopes.
async fn self_group_inbox(app: &Router, token: &str) -> Vec<Value> {
    let (status, inbox) = get_auth(app, "/v1/inbox", token).await;
    assert_eq!(status, StatusCode::OK, "inbox: {inbox}");
    inbox
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["self_group"].as_bool().unwrap_or(false))
        .cloned()
        .collect()
}

#[tokio::test]
async fn devices_link_into_the_self_group_and_a_consumption_fans_out() {
    let app = make_app(100_000).await;
    let (device_a, session_a) = http_register(&app, &unique_username("selfgrp")).await;
    let token_a = session_a["access_token"].as_str().unwrap();
    let account = session_a["account_id"].as_str().unwrap();
    let device_a_id = session_a["device_id"].as_str().unwrap();

    // Enroll device B onto the same account, and get its session/token.
    let device_b = TestDevice::new();
    let session_b = enroll_device(&app, token_a, account, &device_a, &device_b).await;
    let token_b = session_b["access_token"].as_str().unwrap();
    let device_b_id = session_b["device_id"].as_str().unwrap();

    // A creates the self-group locally and registers itself as its first member.
    let (status, _) = post_json_auth(&app, "/v1/self-group/register", token_a, json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // B publishes an (opaque) key package so it can be added.
    let b_key_package = "b0b0b0b0b0b0"; // opaque to the relay
    let (status, _) = post_json_auth(
        &app,
        "/v1/keypackages",
        token_b,
        json!({ "key_package": b_key_package }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A discovers the pending sibling (B): enrolled, not yet a self-group member.
    let (status, pending) = get_auth(&app, "/v1/self-group/pending", token_a).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        pending["pending_devices"].as_array().unwrap(),
        &vec![json!(device_b_id)],
        "B is the one pending sibling"
    );

    // A claims B's key package (scoped to B specifically).
    let (status, claimed) = post_json_auth(
        &app,
        "/v1/self-group/keypackage/claim",
        token_a,
        json!({ "device_id": device_b_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "claim: {claimed}");
    assert_eq!(claimed["device_id"].as_str().unwrap(), device_b_id);
    assert_eq!(claimed["key_package"].as_str().unwrap(), b_key_package);

    // A adds B (in a real client: add_self_device -> welcome). A delivers the opaque Welcome to B.
    let welcome = "77656c636f6d65"; // "welcome" bytes, opaque to the relay
    let (status, receipt) = post_json_auth(
        &app,
        "/v1/self-group/deliver",
        token_a,
        json!({
            "recipient_device": device_b_id,
            "ciphertext": welcome,
            "idempotency_key": "00000000000000000000000000000001",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "welcome deliver: {receipt}");
    assert_eq!(receipt["delivered"].as_u64().unwrap(), 1);

    // A redelivery with the same idempotency key is a no-op (deduplicated).
    let (status, receipt) = post_json_auth(
        &app,
        "/v1/self-group/deliver",
        token_a,
        json!({
            "recipient_device": device_b_id,
            "ciphertext": welcome,
            "idempotency_key": "00000000000000000000000000000001",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        receipt["delivered"].as_u64().unwrap(),
        0,
        "idempotent retry"
    );

    // B pulls the Welcome from its inbox: a self-group envelope from A, no conversation id.
    let b_self = self_group_inbox(&app, token_b).await;
    assert_eq!(b_self.len(), 1, "exactly one self-group envelope (deduped)");
    assert_eq!(b_self[0]["ciphertext"].as_str().unwrap(), welcome);
    assert_eq!(b_self[0]["sender_device"].as_str().unwrap(), device_a_id);
    assert!(b_self[0]["conversation_id"].is_null(), "not a conversation");
    let welcome_env_id = b_self[0]["id"].as_i64().unwrap();

    // B "joins" the self-group and registers itself as a member, then acks the Welcome.
    let (status, _) = post_json_auth(&app, "/v1/self-group/register", token_b, json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = post_json_auth(
        &app,
        "/v1/inbox/ack",
        token_b,
        json!({ "ids": [], "self_group_ids": [welcome_env_id] }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Now B is a member, A has no more pending siblings.
    let (_, pending) = get_auth(&app, "/v1/self-group/pending", token_a).await;
    assert!(
        pending["pending_devices"].as_array().unwrap().is_empty(),
        "B is now a member, nothing pending"
    );

    // A reveals a secret and fans the (opaque) consumption control message out to the self-group.
    let consumption = "636f6e73756d6564"; // "consumed" bytes, opaque to the relay
    let (status, receipt) = post_json_auth(
        &app,
        "/v1/self-group/deliver",
        token_a,
        json!({
            "ciphertext": consumption,
            "idempotency_key": "000000000000000000000000000000aa",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "consumption fanout: {receipt}");
    assert_eq!(receipt["delivered"].as_u64().unwrap(), 1, "reaches B only");

    // B receives the consumption message over the self-group channel and acks it.
    let b_self = self_group_inbox(&app, token_b).await;
    assert_eq!(b_self.len(), 1);
    assert_eq!(b_self[0]["ciphertext"].as_str().unwrap(), consumption);
    assert_eq!(b_self[0]["sender_device"].as_str().unwrap(), device_a_id);
    let consume_env_id = b_self[0]["id"].as_i64().unwrap();
    let (status, _) = post_json_auth(
        &app,
        "/v1/inbox/ack",
        token_b,
        json!({ "ids": [], "self_group_ids": [consume_env_id] }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A's own inbox never received its own fanout (sender is excluded).
    let a_self = self_group_inbox(&app, token_a).await;
    assert!(
        a_self.is_empty(),
        "the sender does not receive its own fanout"
    );
}

#[tokio::test]
async fn a_stranger_cannot_touch_another_accounts_self_group() {
    let app = make_app(100_000).await;

    // Account 1: device A, plus an enrolled device B that publishes a key package.
    let (device_a, session_a) = http_register(&app, &unique_username("sgowner")).await;
    let token_a = session_a["access_token"].as_str().unwrap();
    let account_a = session_a["account_id"].as_str().unwrap();
    let device_b = TestDevice::new();
    let session_b = enroll_device(&app, token_a, account_a, &device_a, &device_b).await;
    let device_b_id = session_b["device_id"].as_str().unwrap();
    let token_b = session_b["access_token"].as_str().unwrap();
    let (status, _) = post_json_auth(
        &app,
        "/v1/keypackages",
        token_b,
        json!({ "key_package": "b0b0" }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A separate account: the stranger.
    let (_stranger_device, session_x) = http_register(&app, &unique_username("stranger")).await;
    let token_x = session_x["access_token"].as_str().unwrap();

    // The stranger cannot claim B's key package (B is not the stranger's device).
    let (status, _) = post_json_auth(
        &app,
        "/v1/self-group/keypackage/claim",
        token_x,
        json!({ "device_id": device_b_id }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "no key package is claimable for a device that isn't yours"
    );

    // The stranger cannot deliver a targeted self-group envelope to B.
    let (status, _) = post_json_auth(
        &app,
        "/v1/self-group/deliver",
        token_x,
        json!({
            "recipient_device": device_b_id,
            "ciphertext": "deadbeef",
            "idempotency_key": "000000000000000000000000000000ff",
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "cannot deliver into another account's self-group"
    );

    // B's key package is untouched by the stranger's failed claim: A can still claim it.
    let (status, claimed) = post_json_auth(
        &app,
        "/v1/self-group/keypackage/claim",
        token_a,
        json!({ "device_id": device_b_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner still claims it: {claimed}");
    assert_eq!(claimed["key_package"].as_str().unwrap(), "b0b0");

    // A stranger with no linked siblings fanning out reaches nobody.
    let (status, _) = post_json_auth(&app, "/v1/self-group/register", token_x, json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, receipt) = post_json_auth(
        &app,
        "/v1/self-group/deliver",
        token_x,
        json!({
            "ciphertext": "abcd",
            "idempotency_key": "000000000000000000000000000000ee",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        receipt["delivered"].as_u64().unwrap(),
        0,
        "a lone device's self-group fanout reaches nobody"
    );
}

/// Revoking a device drops it from its account's self-group membership (ADR-0015 option 3
/// housekeeping), so the relay stops fanning self-group traffic to it. (The cryptographic re-key is
/// a separate client action via `MlsClient.remove_self_device`.)
#[tokio::test]
async fn revoking_a_device_drops_it_from_the_self_group() {
    let app = make_app(100_000).await;
    let (phone_dev, phone) = http_register(&app, &unique_username("sgrevoke")).await;
    let phone_token = phone["access_token"].as_str().unwrap();
    let account = phone["account_id"].as_str().unwrap();
    let tablet_dev = TestDevice::new();
    let tablet = enroll_device(&app, phone_token, account, &phone_dev, &tablet_dev).await;
    let tablet_token = tablet["access_token"].as_str().unwrap();
    let tablet_device = tablet["device_id"].as_str().unwrap().to_string();

    // Both devices are self-group members.
    for token in [phone_token, tablet_token] {
        let (status, _) = post_json_auth(&app, "/v1/self-group/register", token, json!({})).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    // A fan-out reaches the tablet.
    let (status, receipt) = post_json_auth(
        &app,
        "/v1/self-group/deliver",
        phone_token,
        json!({ "ciphertext": "aa", "idempotency_key": "0000000000000000000000000000000a" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        receipt["delivered"].as_u64().unwrap(),
        1,
        "reaches the tablet"
    );

    // Revoke the tablet.
    let (status, _) = post_json_auth(
        &app,
        "/v1/devices/revoke",
        phone_token,
        json!({ "device_id": tablet_device }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A new fan-out now reaches nobody — the revoked device was dropped from the self-group.
    let (status, receipt) = post_json_auth(
        &app,
        "/v1/self-group/deliver",
        phone_token,
        json!({ "ciphertext": "bb", "idempotency_key": "0000000000000000000000000000000b" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        receipt["delivered"].as_u64().unwrap(),
        0,
        "the revoked device no longer receives self-group traffic"
    );
}
