//! The report → review → ban pipeline (V28, docs/MODERATION.md) over the real HTTP API +
//! PostgreSQL: reporters submit exactly what they chose to (text and/or decrypted media), the
//! review surface exists only behind the ops token, resolving a report as "ban" locks the
//! account out at the auth gate immediately, and unbanning restores it.

mod common;

use axum::http::StatusCode;
use common::{get_auth, http_register, make_app_with_moderation, post_json_auth, unique_username};
use serde_json::json;

const TOKEN: &str = "test-moderation-token-0123456789abcdef";

async fn user(app: &axum::Router, prefix: &str) -> (String, String) {
    let (_d, u) = http_register(app, &unique_username(prefix)).await;
    (
        u["access_token"].as_str().unwrap().to_string(),
        u["account_id"].as_str().unwrap().to_string(),
    )
}

/// GET with the moderation token header.
async fn mod_get(app: &axum::Router, path: &str, token: &str) -> (StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method("GET")
        .uri(path)
        .header("x-moderation-token", token)
        .body(axum::body::Body::empty())
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

async fn mod_post(
    app: &axum::Router,
    path: &str,
    token: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("x-moderation-token", token)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// A report with category, location, and media evidence lands in the review queue with
/// everything the reporter submitted — and nothing else.
#[tokio::test]
async fn report_with_evidence_reaches_the_review_queue() {
    let app = make_app_with_moderation(100_000, TOKEN).await;
    let (reporter_tok, reporter_acct) = user(&app, "mra").await;
    let (_target_tok, target_acct) = user(&app, "mrb").await;

    let media = vec![0xFFu8, 0xD8, 0xFF, 0xE0, 1, 2, 3, 4]; // "a JPEG", as far as the relay knows
    let (status, created) = post_json_auth(
        &app,
        "/v1/reports",
        &reporter_tok,
        json!({
            "account_id": target_acct,
            "reason": "sent an illegal image in our chat",
            "category": "illegal_content",
            "evidence": "the message said: look at this",
            "conversation_id": hex::encode([5u8; 16]),
            "message_id": hex::encode([6u8; 16]),
            "evidence_media": hex::encode(&media),
            "evidence_media_mime": "image/jpeg",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let id = created["report_id"].as_i64().unwrap();

    // The queue endpoint serves (oldest-first; the shared test database holds a long backlog,
    // so the specific row is asserted via the direct fetch below).
    let (status, queue) = mod_get(&app, "/v1/moderation/reports", TOKEN).await;
    assert_eq!(status, StatusCode::OK);
    assert!(queue["reports"].is_array());

    // The full fetch returns everything the reporter submitted — and nothing else.
    let (status, full) = mod_get(&app, &format!("/v1/moderation/reports/{id}"), TOKEN).await;
    assert_eq!(status, StatusCode::OK);
    let row = &full["report"];
    assert_eq!(row["category"], "illegal_content");
    assert_eq!(row["reported"], target_acct.as_str());
    assert_eq!(row["reporter"], reporter_acct.as_str());
    assert_eq!(row["has_media"], true);
    assert_eq!(row["status"], "open");
    assert_eq!(row["conversation_id"], hex::encode([5u8; 16]).as_str());
    assert_eq!(row["message_id"], hex::encode([6u8; 16]).as_str());
    assert_eq!(full["evidence_media"], hex::encode(&media).as_str());
    assert_eq!(full["evidence_media_mime"], "image/jpeg");
}

/// The review surface is invisible without the deployment token and refused with a wrong one;
/// an ordinary USER token is not a reviewer credential.
#[tokio::test]
async fn review_surface_is_gated() {
    let app = make_app_with_moderation(100_000, TOKEN).await;
    let (user_tok, _) = user(&app, "mrg").await;

    let (status, _) = mod_get(
        &app,
        "/v1/moderation/reports",
        "wrong-token-wrong-token-wrong!!",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = mod_get(&app, "/v1/moderation/reports", &user_tok).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a user token is not a reviewer token"
    );

    // Unconfigured deployment: the surface does not exist at all.
    let bare = common::make_app(100_000).await;
    let (status, _) = mod_get(&bare, "/v1/moderation/reports", TOKEN).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Resolving a report as "ban" locks the account out everywhere, immediately: held tokens stop
/// working at the auth gate, new logins are refused, and the report carries the audit trail.
/// Unban restores access. Dismissals action nothing.
#[tokio::test]
async fn ban_locks_out_immediately_and_unban_restores() {
    let app = make_app_with_moderation(100_000, TOKEN).await;
    let (reporter_tok, _) = user(&app, "mbc").await;
    let (target_tok, target_acct) = user(&app, "mbd").await;

    let (status, created) = post_json_auth(
        &app,
        "/v1/reports",
        &reporter_tok,
        json!({
            "account_id": target_acct,
            "reason": "credible threat of violence",
            "category": "threats_violence",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let id = created["report_id"].as_i64().unwrap();

    // Before the ban, the target's token works.
    let (status, _) = get_auth(&app, "/v1/session/whoami", &target_tok).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = mod_post(
        &app,
        &format!("/v1/moderation/reports/{id}/resolve"),
        TOKEN,
        json!({ "action": "ban", "reviewer": "reviewer-1", "note": "verified threat" }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Held token: refused at the gate with the honest code.
    let (status, body) = get_auth(&app, "/v1/session/whoami", &target_tok).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "account_banned");

    // A second resolve of the same report loses to the first (audit stays single-writer).
    let (status, _) = mod_post(
        &app,
        &format!("/v1/moderation/reports/{id}/resolve"),
        TOKEN,
        json!({ "action": "dismiss", "reviewer": "reviewer-2" }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // The ban is listed with its provenance.
    let (_, bans) = mod_get(&app, "/v1/moderation/bans", TOKEN).await;
    let ban = bans["bans"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["account_id"] == target_acct.as_str())
        .expect("ban listed")
        .clone();
    assert_eq!(ban["banned_by"], "reviewer-1");
    assert_eq!(ban["report_id"].as_i64(), Some(id));

    // Unban restores the very same token (devices were never revoked — a lifted ban must not
    // strand the person's enrollment).
    let (status, _) = mod_post(
        &app,
        "/v1/moderation/unban",
        TOKEN,
        json!({ "account_id": target_acct }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = get_auth(&app, "/v1/session/whoami", &target_tok).await;
    assert_eq!(status, StatusCode::OK, "unban restores access");
}

/// Reporting a group message by its sender DEVICE: the server resolves the account (the client
/// only knows the MLS credential identity), and a dismissal leaves the account untouched.
#[tokio::test]
async fn report_by_device_resolves_and_dismissal_bans_nobody() {
    let app = make_app_with_moderation(100_000, TOKEN).await;
    let (reporter_tok, _) = user(&app, "mde").await;
    let (target_tok, target_acct) = user(&app, "mdf").await;
    let (_, whoami) = get_auth(&app, "/v1/session/whoami", &target_tok).await;
    let target_device = whoami["device_id"].as_str().unwrap();

    let (status, created) = post_json_auth(
        &app,
        "/v1/reports",
        &reporter_tok,
        json!({
            "device_id": target_device,
            "reason": "spam links in the group",
            "category": "spam_fraud",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let id = created["report_id"].as_i64().unwrap();

    let (_, full) = mod_get(&app, &format!("/v1/moderation/reports/{id}"), TOKEN).await;
    assert_eq!(
        full["report"]["reported"],
        target_acct.as_str(),
        "device resolved to its account server-side"
    );

    let (status, _) = mod_post(
        &app,
        &format!("/v1/moderation/reports/{id}/resolve"),
        TOKEN,
        json!({ "action": "dismiss", "reviewer": "reviewer-1", "note": "not actionable" }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = get_auth(&app, "/v1/session/whoami", &target_tok).await;
    assert_eq!(status, StatusCode::OK, "dismissal must never ban");
}
