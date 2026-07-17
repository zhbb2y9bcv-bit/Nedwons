//! Group governance (ADR-0009) end to end over the real HTTP API + PostgreSQL: admin roles,
//! invite links (expiry/uses/revocation), join-request approval, admin removal, auto-promotion,
//! and block enforcement on the invite path.

mod common;

use axum::http::StatusCode;
use common::{
    befriend, db_url, get_auth, http_register, make_app, post_json_auth, unique_username,
};
use serde_json::json;

/// Register a user; returns (token, account_id).
async fn user(app: &axum::Router, prefix: &str) -> (String, String) {
    let (_d, u) = http_register(app, &unique_username(prefix)).await;
    (
        u["access_token"].as_str().unwrap().to_string(),
        u["account_id"].as_str().unwrap().to_string(),
    )
}

/// Create a group of creator + one befriended member; returns conversation id.
async fn group_of_two(
    app: &axum::Router,
    creator: &(String, String),
    member: &(String, String),
) -> String {
    befriend(app, &creator.0, &creator.1, &member.0, &member.1).await;
    let (status, group) = post_json_auth(
        app,
        "/v1/groups",
        &creator.0,
        json!({ "member_account_ids": [member.1] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "group create: {group}");
    group["conversation_id"].as_str().unwrap().to_string()
}

/// Invite links: strangers join by their own consent; uses are counted; revocation and
/// exhaustion refuse; a joiner can't double-join; fan-out reaches the joiner.
#[tokio::test]
async fn invite_link_join_revoke_and_exhaustion() {
    let app = make_app(100_000).await;
    let alice = user(&app, "inva").await;
    let bob = user(&app, "invb").await;
    let conv = group_of_two(&app, &alice, &bob).await;

    // Non-admin (Bob) cannot mint invites.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/invites"),
        &bob.0,
        json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-admin cannot create invites"
    );

    // Admin creates a single-use invite.
    let (status, invite) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/invites"),
        &alice.0,
        json!({ "max_uses": 1 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "invite: {invite}");
    let token = invite["invite_token"].as_str().unwrap().to_string();

    // A stranger (no friendship with anyone) joins with the token — their own consent.
    let carol = user(&app, "invc").await;
    let (status, joined) = post_json_auth(
        &app,
        "/v1/invites/accept",
        &carol.0,
        json!({ "invite_token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "join: {joined}");
    assert_eq!(joined["status"], "joined");
    assert_eq!(joined["conversation_id"], conv.as_str());

    // Fan-out now reaches Bob and Carol.
    let (status, receipt) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/messages"),
        &alice.0,
        json!({ "ciphertext": hex::encode(b"welcome"), "idempotency_key": hex::encode([21u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["delivered"], 2);

    // The single use is exhausted: the next stranger is refused.
    let dave = user(&app, "invd").await;
    let (status, _) = post_json_auth(
        &app,
        "/v1/invites/accept",
        &dave.0,
        json!({ "invite_token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "exhausted invite refused");

    // A second invite, revoked before use, refuses too.
    let (_, invite2) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/invites"),
        &alice.0,
        json!({}),
    )
    .await;
    let token2 = invite2["invite_token"].as_str().unwrap().to_string();
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/invites/revoke"),
        &alice.0,
        json!({ "invite_token": token2 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = post_json_auth(
        &app,
        "/v1/invites/accept",
        &dave.0,
        json!({ "invite_token": token2 }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "revoked invite refused");

    // Expired invites refuse (backdate via SQL).
    let (_, invite3) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/invites"),
        &alice.0,
        json!({}),
    )
    .await;
    let token3 = invite3["invite_token"].as_str().unwrap().to_string();
    let t3 = token3.clone();
    tokio::task::spawn_blocking(move || {
        let mut client = postgres::Client::connect(&db_url(), postgres::NoTls).expect("db");
        let tok = hex::decode(&t3).expect("hex");
        client
            .execute(
                "UPDATE group_invites SET expires_at = now() - interval '1 minute' WHERE token = $1",
                &[&tok],
            )
            .expect("backdate");
    })
    .await
    .expect("backdate task");
    let (status, _) = post_json_auth(
        &app,
        "/v1/invites/accept",
        &dave.0,
        json!({ "invite_token": token3 }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "expired invite refused");

    // A member re-presenting a valid token is refused (no double-join, no use burned).
    let (_, invite4) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/invites"),
        &alice.0,
        json!({}),
    )
    .await;
    let token4 = invite4["invite_token"].as_str().unwrap().to_string();
    let (status, _) = post_json_auth(
        &app,
        "/v1/invites/accept",
        &carol.0,
        json!({ "invite_token": token4 }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "already-member join refused");
}

/// Join approval: with the setting on, a token files a request; admins approve (with block
/// re-check) or deny; approval adds the member.
#[tokio::test]
async fn join_approval_flow() {
    let app = make_app(100_000).await;
    let alice = user(&app, "japa").await;
    let bob = user(&app, "japb").await;
    let conv = group_of_two(&app, &alice, &bob).await;

    // Only admins can change settings.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/settings"),
        &bob.0,
        json!({ "join_approval": true }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/settings"),
        &alice.0,
        json!({ "join_approval": true }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, invite) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/invites"),
        &alice.0,
        json!({}),
    )
    .await;
    let token = invite["invite_token"].as_str().unwrap().to_string();

    // Carol's accept becomes a pending request.
    let carol = user(&app, "japc").await;
    let (status, res) = post_json_auth(
        &app,
        "/v1/invites/accept",
        &carol.0,
        json!({ "invite_token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(res["status"], "requested");

    // Admin sees it; denies it; it is gone.
    let (status, reqs) = get_auth(
        &app,
        &format!("/v1/conversations/{conv}/requests"),
        &alice.0,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(reqs
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == &json!(carol.1)));
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/requests/deny"),
        &alice.0,
        json!({ "account_id": carol.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, reqs) = get_auth(
        &app,
        &format!("/v1/conversations/{conv}/requests"),
        &alice.0,
    )
    .await;
    assert!(reqs.as_array().unwrap().is_empty());

    // Carol requests again; admin approves; she is now a routed member.
    let (_, res) = post_json_auth(
        &app,
        "/v1/invites/accept",
        &carol.0,
        json!({ "invite_token": token }),
    )
    .await;
    assert_eq!(res["status"], "requested");
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/requests/approve"),
        &alice.0,
        json!({ "account_id": carol.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, convos) = get_auth(&app, "/v1/conversations", &carol.0).await;
    assert!(convos
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["conversation_id"] == conv.as_str()));

    // Approving again: no request left.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/requests/approve"),
        &alice.0,
        json!({ "account_id": carol.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Blocks bar the invite path: a valid token is refused when a block exists between the joiner
/// and any current member.
#[tokio::test]
async fn blocked_joiner_is_refused_on_invite() {
    let app = make_app(100_000).await;
    let alice = user(&app, "blja").await;
    let bob = user(&app, "bljb").await;
    let conv = group_of_two(&app, &alice, &bob).await;

    let (_, invite) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/invites"),
        &alice.0,
        json!({}),
    )
    .await;
    let token = invite["invite_token"].as_str().unwrap().to_string();

    // Bob (a member) blocks Eve. Her valid token is now refused.
    let eve = user(&app, "blje").await;
    let (status, _) =
        post_json_auth(&app, "/v1/blocks", &bob.0, json!({ "account_id": eve.1 })).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = post_json_auth(
        &app,
        "/v1/invites/accept",
        &eve.0,
        json!({ "invite_token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "blocked joiner refused");
}

/// Roles: promote/demote with last-admin protection; admin removal excludes the target from
/// fan-out and revokes send; when the only admin leaves, the earliest member is auto-promoted.
#[tokio::test]
async fn roles_removal_and_auto_promotion() {
    let app = make_app(100_000).await;
    let alice = user(&app, "rola").await;
    let bob = user(&app, "rolb").await;
    let carol = user(&app, "rolc").await;
    let conv = group_of_two(&app, &alice, &bob).await;

    // Add Carol too (friend of Alice, direct add by the admin).
    befriend(&app, &alice.0, &alice.1, &carol.0, &carol.1).await;
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/members"),
        &alice.0,
        json!({ "account_id": carol.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Non-admin cannot remove members or promote.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/members/remove"),
        &bob.0,
        json!({ "account_id": carol.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/admins"),
        &bob.0,
        json!({ "account_id": bob.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Demoting the last admin is refused (409).
    let (status, body) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/admins/demote"),
        &alice.0,
        json!({ "account_id": alice.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "last_admin");

    // Promote Bob; now Bob can perform admin ops; then demote him again.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/admins"),
        &alice.0,
        json!({ "account_id": bob.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/invites"),
        &bob.0,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "promoted member can mint invites");
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/admins/demote"),
        &alice.0,
        json!({ "account_id": bob.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Promoting a non-member is a 404.
    let mallory = user(&app, "rolm").await;
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/admins"),
        &alice.0,
        json!({ "account_id": mallory.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Admin removes Carol: fan-out excludes her and she cannot send.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/members/remove"),
        &alice.0,
        json!({ "account_id": carol.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, receipt) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/messages"),
        &alice.0,
        json!({ "ciphertext": hex::encode(b"post-remove"), "idempotency_key": hex::encode([22u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        receipt["delivered"], 1,
        "removed member excluded from fan-out"
    );
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/messages"),
        &carol.0,
        json!({ "ciphertext": hex::encode(b"ghost"), "idempotency_key": hex::encode([23u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "removed member cannot send");

    // The only admin (Alice) leaves: Bob — the earliest remaining member — is auto-promoted
    // and can immediately perform admin operations.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/leave"),
        &alice.0,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/invites"),
        &bob.0,
        json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "earliest member auto-promoted to admin after the last admin left"
    );
}
