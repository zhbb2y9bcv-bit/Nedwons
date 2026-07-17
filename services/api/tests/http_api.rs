//! End-to-end HTTP tests: a simulated client drives the real axum router backed by real
//! PostgreSQL stores — the same wire flow the iOS app will use. Uses in-process
//! `tower::ServiceExt::oneshot`, no network socket.

mod common;

use std::sync::Arc;

use auth_core::crypto::sha256;
use auth_core::ids::{AccountId, DeviceId, TxnId};
use auth_core::memstore::SystemClock;
use auth_core::transcript::{Action, Transcript};
use auth_core::{refresh_txn_id, AuthService, Config};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use common::{unique_username, TestDevice, PASSWORD};
use http_body_util::BodyExt;
use sentinel_api::http::build_router;
use tower::ServiceExt;

/// Built on a blocking thread: the sync `postgres` client hosts its own runtime, which
/// must never be entered from async context (see lib.rs `build_pool`).
async fn make_app(per_ip_per_minute: u32) -> Router {
    tokio::task::spawn_blocking(move || {
        let stores = common::shared_stores();
        let service = Arc::new(AuthService::new(
            stores.clone(),
            stores.clone(),
            stores.clone(),
            stores.clone(),
            stores.clone(),
            Arc::new(SystemClock),
            Config::default(),
        ));
        build_router(service, per_ip_per_minute)
    })
    .await
    .expect("app setup")
}

async fn post_json(
    app: &Router,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json = if bytes.is_empty() {
        serde_json::json!(null)
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::json!(null))
    };
    (status, json)
}

async fn get_bearer(app: &Router, path: &str, token: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::get(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::json!(null));
    (status, json)
}

fn id16_from_hex(s: &str) -> [u8; 16] {
    hex::decode(s).expect("hex").try_into().expect("16 bytes")
}

fn nonce32_from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

/// Sign a challenge JSON (from begin endpoints) with the given device for `action`.
fn sign_challenge(device: &TestDevice, challenge: &serde_json::Value, action: Action) -> String {
    let account_id = AccountId(id16_from_hex(challenge["account_id"].as_str().unwrap()));
    let device_id = DeviceId(id16_from_hex(challenge["device_id"].as_str().unwrap()));
    let txn_id = TxnId(id16_from_hex(challenge["txn_id"].as_str().unwrap()));
    let nonce = nonce32_from_hex(challenge["nonce"].as_str().unwrap());
    let transcript = Transcript {
        action,
        account_id: &account_id,
        device_id: &device_id,
        public_key: &device.public_key,
        challenge: &nonce,
        expires_at: challenge["expires_at"].as_u64().unwrap(),
        txn_id: &txn_id,
    };
    hex::encode(device.sign(&transcript.encode()))
}

/// Register over HTTP; returns (device, session JSON).
async fn http_register(app: &Router, username: &str) -> (TestDevice, serde_json::Value) {
    let device = TestDevice::new();
    let (status, challenge) = post_json(app, "/v1/register/begin", serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let signature = sign_challenge(&device, &challenge, Action::Register);
    let (status, session) = post_json(
        app,
        "/v1/register/finish",
        serde_json::json!({
            "username": username,
            "password": PASSWORD,
            "device_public_key": hex::encode(&device.public_key),
            "txn_id": challenge["txn_id"],
            "signature": signature,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register finish: {session}");
    (device, session)
}

#[tokio::test]
async fn full_http_flow_register_login_whoami_refresh_logout() {
    let app = make_app(100_000).await;
    let username = unique_username("web");
    let (device, session) = http_register(&app, &username).await;

    // whoami with the fresh access token.
    let (status, who) = get_bearer(
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
        serde_json::json!({ "username": username, "password": PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let signature = sign_challenge(&device, &challenge, Action::Login);
    let (status, login_session) = post_json(
        &app,
        "/v1/login/finish",
        serde_json::json!({ "txn_id": challenge["txn_id"], "signature": signature }),
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
        serde_json::json!({
            "refresh_token": login_session["refresh_token"],
            "signature": refresh_sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "refresh: {rotated}");
    assert_ne!(rotated["refresh_token"], login_session["refresh_token"]);

    // Replaying the OLD refresh token is denied (and burns the family).
    let (status, body) = post_json(
        &app,
        "/v1/session/refresh",
        serde_json::json!({
            "refresh_token": login_session["refresh_token"],
            "signature": refresh_sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "replay: {body}");

    // Logout with the registration session's refresh token → its access token dies.
    let (status, _) = post_json(
        &app,
        "/v1/session/logout",
        serde_json::json!({ "refresh_token": session["refresh_token"] }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = get_bearer(
        &app,
        "/v1/session/whoami",
        session["access_token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// INV-2 over the wire: correct username+password, wrong device key → 401 with the
/// generic body, indistinguishable from any other failure.
#[tokio::test]
async fn http_login_denied_without_device_key() {
    let app = make_app(100_000).await;
    let username = unique_username("victim");
    let (_device, _session) = http_register(&app, &username).await;

    let attacker = TestDevice::new();
    let (status, challenge) = post_json(
        &app,
        "/v1/login/begin",
        serde_json::json!({ "username": username, "password": PASSWORD }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "begin always answers with a challenge"
    );
    let signature = sign_challenge(&attacker, &challenge, Action::Login);
    let (status, body) = post_json(
        &app,
        "/v1/login/finish",
        serde_json::json!({ "txn_id": challenge["txn_id"], "signature": signature }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "denied");
}

/// Nonexistent accounts get the same generic answer as wrong passwords (enumeration
/// resistance over the wire).
#[tokio::test]
async fn http_login_begin_is_enumeration_resistant() {
    let app = make_app(100_000).await;
    let (status_a, body_a) = post_json(
        &app,
        "/v1/login/begin",
        serde_json::json!({ "username": unique_username("ghost"), "password": PASSWORD }),
    )
    .await;
    assert_eq!(status_a, StatusCode::OK);
    // Same shape as a real challenge; nothing marks it as a decoy.
    assert!(body_a["txn_id"].is_string());
    assert!(body_a["nonce"].is_string());
}

#[tokio::test]
async fn http_validation_rejects_malformed_input() {
    let app = make_app(100_000).await;

    // Unknown JSON fields are rejected (schema strictness).
    let (status, _) = post_json(
        &app,
        "/v1/login/begin",
        serde_json::json!({ "username": "abc", "password": "x", "extra": true }),
    )
    .await;
    assert!(
        status.is_client_error(),
        "unknown field must be rejected: {status}"
    );

    // Wrong-length hex is rejected without hitting crypto.
    let (status, _) = post_json(
        &app,
        "/v1/login/finish",
        serde_json::json!({ "txn_id": "abcd", "signature": "12" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Weak password → specific, client-correctable error.
    let (status, challenge) = post_json(&app, "/v1/register/begin", serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let device = TestDevice::new();
    let signature = sign_challenge(&device, &challenge, Action::Register);
    let (status, body) = post_json(
        &app,
        "/v1/register/finish",
        serde_json::json!({
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

    // Garbage bearer token → 401.
    let (status, _) = get_bearer(&app, "/v1/session/whoami", "zz").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Duplicate usernames are refused with 409 (registration is the one place where
/// username existence is inherently observable).
#[tokio::test]
async fn http_duplicate_username_is_conflict() {
    let app = make_app(100_000).await;
    let username = unique_username("dup");
    let (_d, _s) = http_register(&app, &username).await;

    let device = TestDevice::new();
    let (_, challenge) = post_json(&app, "/v1/register/begin", serde_json::json!({})).await;
    let signature = sign_challenge(&device, &challenge, Action::Register);
    let (status, body) = post_json(
        &app,
        "/v1/register/finish",
        serde_json::json!({
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

/// The per-IP limiter answers 429 once the quota is exhausted.
#[tokio::test]
async fn http_rate_limit_trips() {
    let app = make_app(2).await; // 2 requests/minute
    let mut last = StatusCode::OK;
    for _ in 0..4 {
        let (status, _) = post_json(&app, "/v1/register/begin", serde_json::json!({})).await;
        last = status;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}
