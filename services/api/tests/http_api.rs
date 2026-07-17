//! End-to-end HTTP tests for the auth API: a simulated client drives the real axum router
//! backed by real PostgreSQL stores. In-process via `oneshot`, no network socket. Shared
//! client helpers live in `common`.

mod common;

use auth_core::crypto::sha256;
use auth_core::ids::{AccountId, DeviceId};
use auth_core::refresh_txn_id;
use auth_core::transcript::{Action, Transcript};
use axum::http::StatusCode;
use common::{
    get_auth, http_register, id16_from_hex, make_app, post_json, sign_challenge, unique_username,
    TestDevice, PASSWORD,
};
use serde_json::json;

#[tokio::test]
async fn full_http_flow_register_login_whoami_refresh_logout() {
    let app = make_app(100_000).await;
    let username = unique_username("web");
    let (device, session) = http_register(&app, &username).await;

    // whoami with the fresh access token.
    let (status, who) = get_auth(
        &app,
        "/v1/session/whoami",
        session["access_token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(who["account_id"], session["account_id"]);

    // Full login round-trip.
    let (status, challenge) = post_json(
        &app,
        "/v1/login/begin",
        json!({ "username": username, "password": PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let signature = sign_challenge(&device, &challenge, Action::Login);
    let (status, login_session) = post_json(
        &app,
        "/v1/login/finish",
        json!({ "txn_id": challenge["txn_id"], "signature": signature }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login finish: {login_session}");

    // Refresh: token + device signature.
    let refresh_token = hex::decode(login_session["refresh_token"].as_str().unwrap()).unwrap();
    let old_hash = sha256(&refresh_token);
    let txn = refresh_txn_id(&old_hash);
    let account_id = AccountId(id16_from_hex(login_session["account_id"].as_str().unwrap()));
    let device_id = DeviceId(id16_from_hex(login_session["device_id"].as_str().unwrap()));
    let refresh_transcript = Transcript {
        action: Action::Refresh,
        account_id: &account_id,
        device_id: &device_id,
        public_key: &device.public_key,
        challenge: &old_hash,
        expires_at: 0,
        txn_id: &txn,
    };
    let refresh_sig = hex::encode(device.sign(&refresh_transcript.encode()));
    let (status, rotated) = post_json(
        &app,
        "/v1/session/refresh",
        json!({ "refresh_token": login_session["refresh_token"], "signature": refresh_sig }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "refresh: {rotated}");
    assert_ne!(rotated["refresh_token"], login_session["refresh_token"]);

    // Replaying the OLD refresh token is denied (and burns the family).
    let (status, _) = post_json(
        &app,
        "/v1/session/refresh",
        json!({ "refresh_token": login_session["refresh_token"], "signature": refresh_sig }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Logout with the registration session's refresh token → its access token dies.
    let (status, _) = post_json(
        &app,
        "/v1/session/logout",
        json!({ "refresh_token": session["refresh_token"] }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = get_auth(
        &app,
        "/v1/session/whoami",
        session["access_token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// INV-2 over the wire: correct credentials, wrong device key → 401 with the generic body.
#[tokio::test]
async fn http_login_denied_without_device_key() {
    let app = make_app(100_000).await;
    let username = unique_username("victim");
    let (_device, _session) = http_register(&app, &username).await;

    let attacker = TestDevice::new();
    let (status, challenge) = post_json(
        &app,
        "/v1/login/begin",
        json!({ "username": username, "password": PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let signature = sign_challenge(&attacker, &challenge, Action::Login);
    let (status, body) = post_json(
        &app,
        "/v1/login/finish",
        json!({ "txn_id": challenge["txn_id"], "signature": signature }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "denied");
}

/// Nonexistent accounts get the same generic answer as wrong passwords.
#[tokio::test]
async fn http_login_begin_is_enumeration_resistant() {
    let app = make_app(100_000).await;
    let (status, body) = post_json(
        &app,
        "/v1/login/begin",
        json!({ "username": unique_username("ghost"), "password": PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["txn_id"].is_string());
    assert!(body["nonce"].is_string());
}

#[tokio::test]
async fn http_validation_rejects_malformed_input() {
    let app = make_app(100_000).await;

    let (status, _) = post_json(
        &app,
        "/v1/login/begin",
        json!({ "username": "abc", "password": "x", "extra": true }),
    )
    .await;
    assert!(status.is_client_error());

    let (status, _) = post_json(
        &app,
        "/v1/login/finish",
        json!({ "txn_id": "abcd", "signature": "12" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Weak password → specific, client-correctable error.
    let (status, challenge) = post_json(&app, "/v1/register/begin", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let device = TestDevice::new();
    let signature = sign_challenge(&device, &challenge, Action::Register);
    let (status, body) = post_json(
        &app,
        "/v1/register/finish",
        json!({
            "username": unique_username("weak"),
            "password": "password1234",
            "device_public_key": hex::encode(&device.public_key),
            "txn_id": challenge["txn_id"],
            "signature": signature,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "weak_password");

    let (status, _) = get_auth(&app, "/v1/session/whoami", "zz").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn http_duplicate_username_is_conflict() {
    let app = make_app(100_000).await;
    let username = unique_username("dup");
    let (_d, _s) = http_register(&app, &username).await;

    let device = TestDevice::new();
    let (_, challenge) = post_json(&app, "/v1/register/begin", json!({})).await;
    let signature = sign_challenge(&device, &challenge, Action::Register);
    let (status, body) = post_json(
        &app,
        "/v1/register/finish",
        json!({
            "username": username,
            "password": PASSWORD,
            "device_public_key": hex::encode(&device.public_key),
            "txn_id": challenge["txn_id"],
            "signature": signature,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "username_unavailable");
}

#[tokio::test]
async fn http_rate_limit_trips() {
    let app = make_app(2).await; // 2 requests/minute
    let mut last = StatusCode::OK;
    for _ in 0..4 {
        let (status, _) = post_json(&app, "/v1/register/begin", json!({})).await;
        last = status;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}
