//! The V27 MLS setup queue over the real HTTP API + PostgreSQL: multi-device membership,
//! deferred adds, and the reconcile claim protocol that makes exactly one member perform each
//! MLS add. The MLS bytes themselves are proven client-side (NedwonsApp tests); what the relay
//! owes is the QUEUE — who still needs a Welcome, who may deliver it, and when it's done.

mod common;

use axum::http::StatusCode;
use common::{
    befriend, enroll_device, get_auth, http_register, post_json_auth, unique_username, TestDevice,
};
use serde_json::json;

async fn user(app: &axum::Router, prefix: &str) -> (TestDevice, String, String, String) {
    let (device, u) = http_register(app, &unique_username(prefix)).await;
    (
        device,
        u["access_token"].as_str().unwrap().to_string(),
        u["account_id"].as_str().unwrap().to_string(),
        u["device_id"].as_str().unwrap().to_string(),
    )
}

fn targets_for<'a>(needed: &'a serde_json::Value, device: &str) -> Vec<&'a serde_json::Value> {
    needed["targets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["device_id"] == device)
        .collect()
}

/// A member with NO prekeys can still be listed at group creation: the add is deferred into the
/// setup queue, and completes (claim → prekey → confirm) once they publish one.
#[tokio::test]
async fn deferred_add_waits_for_prekeys_then_completes() {
    let app = common::make_app(100_000).await;
    let (_da, alice_tok, alice_acct, _alice_dev) = user(&app, "sqa").await;
    let (_db, bob_tok, bob_acct, bob_dev) = user(&app, "sqb").await;
    befriend(&app, &alice_tok, &alice_acct, &bob_tok, &bob_acct).await;

    // Bob has published NOTHING. Creation still succeeds; bob is queued, not failed.
    let (status, group) = post_json_auth(
        &app,
        "/v1/groups",
        &alice_tok,
        json!({ "member_account_ids": [bob_acct] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create: {group}");
    let conv = group["conversation_id"].as_str().unwrap().to_string();

    let (status, needed) = get_auth(&app, "/v1/setup/needed", &alice_tok).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(targets_for(&needed, &bob_dev).len(), 1, "{needed}");

    // Claim the work; the prekey isn't there yet — the claim simply expires later.
    let (status, _) = post_json_auth(
        &app,
        "/v1/setup/claim",
        &alice_tok,
        json!({ "conversation_id": conv, "device_id": bob_dev }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = post_json_auth(
        &app,
        "/v1/keypackages/claim-device",
        &alice_tok,
        json!({ "device_id": bob_dev }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no prekey yet: {body}");

    // Bob opens the app and publishes; the SAME claimer may retry immediately (re-claim by the
    // holder is allowed), completes the add, and confirms.
    let (status, _) = post_json_auth(
        &app,
        "/v1/keypackages",
        &bob_tok,
        json!({ "key_package": hex::encode([7u8; 64]) }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = post_json_auth(
        &app,
        "/v1/setup/claim",
        &alice_tok,
        json!({ "conversation_id": conv, "device_id": bob_dev }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, claimed) = post_json_auth(
        &app,
        "/v1/keypackages/claim-device",
        &alice_tok,
        json!({ "device_id": bob_dev }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{claimed}");
    assert_eq!(claimed["device_id"], bob_dev);
    let (status, _) = post_json_auth(
        &app,
        "/v1/setup/confirm",
        &alice_tok,
        json!({ "conversation_id": conv, "device_id": bob_dev }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, needed) = get_auth(&app, "/v1/setup/needed", &alice_tok).await;
    assert!(targets_for(&needed, &bob_dev).is_empty(), "{needed}");
}

/// The claim protocol: a second member cannot steal a live claim, an un-set-up device sees no
/// queue and cannot claim, and confirm requires holding the claim.
#[tokio::test]
async fn claims_serialize_and_gate_on_membership() {
    let app = common::make_app(100_000).await;
    let (_da, alice_tok, alice_acct, _ad) = user(&app, "sqc").await;
    let (_db, bob_tok, bob_acct, _bd) = user(&app, "sqd").await;
    let (_dc, carol_tok, carol_acct, carol_dev) = user(&app, "sqe").await;
    let (_ds, stranger_tok, _sa, _sd) = user(&app, "sqf").await;
    befriend(&app, &alice_tok, &alice_acct, &bob_tok, &bob_acct).await;
    befriend(&app, &alice_tok, &alice_acct, &carol_tok, &carol_acct).await;

    // Bob is reachable (prekey up) so his row can be confirmed; carol stays queued.
    let (status, _) = post_json_auth(
        &app,
        "/v1/keypackages",
        &bob_tok,
        json!({ "key_package": hex::encode([7u8; 64]) }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, group) = post_json_auth(
        &app,
        "/v1/groups",
        &alice_tok,
        json!({ "member_account_ids": [bob_acct, carol_acct] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{group}");
    let conv = group["conversation_id"].as_str().unwrap().to_string();

    // Bob has NOT completed setup, so he sees no queue and cannot claim carol.
    let (_, needed) = get_auth(&app, "/v1/setup/needed", &bob_tok).await;
    assert!(needed["targets"].as_array().unwrap().is_empty(), "{needed}");
    let (status, _) = post_json_auth(
        &app,
        "/v1/setup/claim",
        &bob_tok,
        json!({ "conversation_id": conv, "device_id": carol_dev }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "un-set-up member cannot claim"
    );

    // Alice (set up — she created the group) claims carol; a stranger cannot confirm, and even
    // alice cannot confirm a row someone else... here: a second claim by a NON-holder conflicts.
    let (status, _) = post_json_auth(
        &app,
        "/v1/setup/claim",
        &alice_tok,
        json!({ "conversation_id": conv, "device_id": carol_dev }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = post_json_auth(
        &app,
        "/v1/setup/confirm",
        &stranger_tok,
        json!({ "conversation_id": conv, "device_id": carol_dev }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "only the claim holder confirms"
    );

    // A stranger with the exact device id cannot claim its prekey (no shared conversation).
    let (status, _) = post_json_auth(
        &app,
        "/v1/keypackages/claim-device",
        &stranger_tok,
        json!({ "device_id": carol_dev }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Linking a second device seeds it into every one of the account's conversations, queued for
/// setup — and the account's OWN first device is allowed to claim its prekey and set it up.
#[tokio::test]
async fn linked_sibling_joins_all_conversations_via_the_queue() {
    let app = common::make_app(100_000).await;
    let (device_a, alice_tok, alice_acct, alice_dev) = user(&app, "sqg").await;
    let (_db, bob_tok, bob_acct, _bd) = user(&app, "sqh").await;
    befriend(&app, &alice_tok, &alice_acct, &bob_tok, &bob_acct).await;
    let (status, _) = post_json_auth(
        &app,
        "/v1/keypackages",
        &bob_tok,
        json!({ "key_package": hex::encode([7u8; 64]) }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, group) = post_json_auth(
        &app,
        "/v1/groups",
        &alice_tok,
        json!({ "member_account_ids": [bob_acct] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{group}");
    let conv = group["conversation_id"].as_str().unwrap().to_string();

    // Enroll a second device for alice (ADR-0008 ceremony), then LINK it (self-group register)
    // — enrollment alone deliberately grants no conversation routing.
    let sibling = TestDevice::new();
    let session_b = enroll_device(&app, &alice_tok, &alice_acct, &device_a, &sibling).await;
    let sib_tok = session_b["access_token"].as_str().unwrap().to_string();
    let sib_dev = session_b["device_id"].as_str().unwrap().to_string();
    let (_, needed) = get_auth(&app, "/v1/setup/needed", &alice_tok).await;
    assert!(
        targets_for(&needed, &sib_dev).is_empty(),
        "enrolled-but-unlinked gets nothing: {needed}"
    );

    let (status, _) = post_json_auth(&app, "/v1/self-group/register", &sib_tok, json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Now the sibling is queued for the conversation, and alice's primary can set it up.
    let (_, needed) = get_auth(&app, "/v1/setup/needed", &alice_tok).await;
    let rows = targets_for(&needed, &sib_dev);
    assert_eq!(rows.len(), 1, "{needed}");
    assert_eq!(rows[0]["conversation_id"], conv.as_str());
    assert_eq!(rows[0]["account_id"], alice_acct.as_str());

    let (status, _) = post_json_auth(
        &app,
        "/v1/keypackages",
        &sib_tok,
        json!({ "key_package": hex::encode([9u8; 64]) }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = post_json_auth(
        &app,
        "/v1/setup/claim",
        &alice_tok,
        json!({ "conversation_id": conv, "device_id": sib_dev }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Same-account ownership authorizes the prekey claim even without the shared-conversation row.
    let (status, claimed) = post_json_auth(
        &app,
        "/v1/keypackages/claim-device",
        &alice_tok,
        json!({ "device_id": sib_dev }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{claimed}");
    let (status, _) = post_json_auth(
        &app,
        "/v1/setup/confirm",
        &alice_tok,
        json!({ "conversation_id": conv, "device_id": sib_dev }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The sibling is now a routed member: a fan-out from bob reaches it.
    let (status, sent) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/messages"),
        &bob_tok,
        json!({ "ciphertext": hex::encode([1u8; 32]), "idempotency_key": hex::encode([3u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    let (status, inbox) = get_auth(&app, "/v1/inbox", &sib_tok).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        inbox.as_array().unwrap().len(),
        1,
        "sibling receives conversation mail: {inbox}"
    );
    let _ = alice_dev;
}

/// An invite joiner's devices land in the queue for the members to reconcile — the server-side
/// half of "encryption completes automatically" (the client half is the coordinator's loop).
#[tokio::test]
async fn invite_join_queues_the_joiner_for_setup() {
    let app = common::make_app(100_000).await;
    let (_da, alice_tok, alice_acct, _ad) = user(&app, "sqi").await;
    let (_db, bob_tok, bob_acct, _bd) = user(&app, "sqj").await;
    let (_dc, joiner_tok, _joiner_acct, joiner_dev) = user(&app, "sqk").await;
    befriend(&app, &alice_tok, &alice_acct, &bob_tok, &bob_acct).await;
    let (status, _) = post_json_auth(
        &app,
        "/v1/keypackages",
        &bob_tok,
        json!({ "key_package": hex::encode([7u8; 64]) }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, group) = post_json_auth(
        &app,
        "/v1/groups",
        &alice_tok,
        json!({ "member_account_ids": [bob_acct] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let conv = group["conversation_id"].as_str().unwrap().to_string();

    let (status, invite) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/invites"),
        &alice_tok,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{invite}");
    let token = invite["invite_token"].as_str().unwrap();
    let (status, joined) = post_json_auth(
        &app,
        "/v1/invites/accept",
        &joiner_tok,
        json!({ "invite_token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{joined}");
    assert_eq!(joined["status"], "joined");

    let (_, needed) = get_auth(&app, "/v1/setup/needed", &alice_tok).await;
    assert_eq!(targets_for(&needed, &joiner_dev).len(), 1, "{needed}");
}
