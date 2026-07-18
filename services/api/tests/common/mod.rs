// Each test binary compiles this module independently, so helpers used by only one binary
// are "dead" in the others — a false positive inherent to shared test modules.
#![allow(dead_code)]

//! Shared helpers for the Postgres-backed integration tests.
//!
//! These tests require a running PostgreSQL with a test database:
//!   `TEST_DATABASE_URL` (default `postgres://localhost/sentinel_test`).
//! They use randomized usernames instead of truncation so parallel tests and repeated
//! runs never collide, and they run real migrations (idempotent via refinery).

use std::sync::Arc;

use auth_core::memstore::SystemClock;
use auth_core::transcript::{Action, Transcript};
use auth_core::{AuthService, Config, RegisterRequest, Session};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand_core::{OsRng, RngCore};
use sentinel_api::pgstore::PgStores;
use sentinel_api::relay::PgRelay;

pub const PASSWORD: &str = "battery staple orbit lantern";

pub fn db_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/sentinel_test".to_string())
}

/// Parallel tests must not race refinery's schema-history bootstrap: run migrations
/// exactly once per test process (Once blocks the other callers until done).
pub fn migrate_once(url: &str) {
    static MIGRATE: std::sync::Once = std::sync::Once::new();
    MIGRATE.call_once(|| {
        sentinel_api::run_migrations(url).expect(
            "migrations require a running PostgreSQL with the sentinel_test database \
             (TEST_DATABASE_URL)",
        );
    });
}

/// Process-lifetime shared stores. Never dropped, deliberately: the sync `postgres`
/// client's Drop runs `block_on`, which panics if the last pool handle is released inside
/// an async context (as at the end of a #[tokio::test]). A OnceLock keeps one handle alive
/// for the whole test process, so per-test drops are never the last.
pub fn shared_stores() -> Arc<PgStores> {
    static STORES: std::sync::OnceLock<Arc<PgStores>> = std::sync::OnceLock::new();
    STORES
        .get_or_init(|| {
            let url = db_url();
            migrate_once(&url);
            Arc::new(PgStores::new(
                sentinel_api::build_pool(&url, 24).expect("pool"),
            ))
        })
        .clone()
}

/// Migrated PgStores handle + AuthService over it.
pub fn setup() -> (Arc<PgStores>, AuthService) {
    let stores = shared_stores();
    let service = make_service(&stores);
    (stores, service)
}

pub fn make_service(stores: &Arc<PgStores>) -> AuthService {
    AuthService::new(
        stores.clone(),
        stores.clone(),
        stores.clone(),
        stores.clone(),
        stores.clone(),
        Arc::new(SystemClock),
        Config::default(),
    )
}

/// Relay store over the shared pool.
pub fn shared_relay() -> Arc<PgRelay> {
    Arc::new(PgRelay::new(shared_stores().pool_clone()))
}

/// Social store (profiles/friends/blocks) over the shared pool.
pub fn shared_social() -> Arc<sentinel_api::social::PgSocial> {
    Arc::new(sentinel_api::social::PgSocial::new(
        shared_stores().pool_clone(),
    ))
}

/// Group governance store (roles/invites/join requests) over the shared pool.
pub fn shared_groups() -> Arc<sentinel_api::groups::PgGroups> {
    Arc::new(sentinel_api::groups::PgGroups::new(
        shared_stores().pool_clone(),
    ))
}

/// Membership-commit store (ADR-0010 epoch CAS + audit log) over the shared pool.
#[allow(dead_code)]
pub fn shared_membership() -> Arc<sentinel_api::membership::PgMembership> {
    Arc::new(sentinel_api::membership::PgMembership::new(
        shared_stores().pool_clone(),
    ))
}

/// Transparency store over the shared pool, with a process-stable log signing key (so STH
/// signatures verify against a consistent public key across a test's requests).
pub fn shared_transparency() -> Arc<sentinel_api::transparency::PgTransparency> {
    static KEY: std::sync::OnceLock<p256::ecdsa::SigningKey> = std::sync::OnceLock::new();
    let key = KEY
        .get_or_init(|| p256::ecdsa::SigningKey::random(&mut OsRng))
        .clone();
    Arc::new(sentinel_api::transparency::PgTransparency::new(
        shared_stores().pool_clone(),
        key,
    ))
}

/// Random username, unique per call, satisfying the normalization policy.
pub fn unique_username(prefix: &str) -> String {
    let mut bytes = [0u8; 6];
    OsRng.fill_bytes(&mut bytes);
    let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}{suffix}")
}

/// A test stand-in for a device: holds the private key (Secure Enclave in production).
pub struct TestDevice {
    signing_key: SigningKey,
    pub public_key: Vec<u8>,
}

impl TestDevice {
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Self {
            signing_key,
            public_key,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing_key.sign(message);
        sig.to_bytes().to_vec()
    }
}

/// Register a fresh account through the service; returns the device and its session.
pub fn register(service: &AuthService, username: &str) -> (TestDevice, Session) {
    let device = TestDevice::new();
    let challenge = service.register_begin().expect("register_begin");
    let transcript = Transcript {
        action: Action::Register,
        account_id: &challenge.account_id,
        device_id: &challenge.device_id,
        public_key: &device.public_key,
        challenge: &challenge.nonce,
        expires_at: challenge.expires_at,
        txn_id: &challenge.txn_id,
    };
    let signature = device.sign(&transcript.encode());
    let session = service
        .register_finish(RegisterRequest {
            username: username.to_string(),
            password: PASSWORD.to_string(),
            device_public_key: device.public_key.clone(),
            txn_id: challenge.txn_id,
            signature,
        })
        .expect("registration should succeed");
    (device, session)
}

// ----- shared in-process HTTP client (for http_api.rs and relay_e2ee.rs) --------------

use auth_core::ids::{AccountId, DeviceId, TxnId};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

/// Build the full app (auth + relay) over the shared pool, on a blocking thread.
pub async fn make_app(per_ip_per_minute: u32) -> Router {
    tokio::task::spawn_blocking(move || {
        let stores = shared_stores();
        let service = Arc::new(make_service(&stores));
        sentinel_api::http::build_router(
            service,
            shared_relay(),
            shared_social(),
            shared_groups(),
            shared_transparency(),
            shared_membership(),
            per_ip_per_minute,
        )
    })
    .await
    .expect("app setup")
}

/// Build the app with DPoP-style proof enforcement ON (ADR-0011, R-308), so tests can exercise
/// sender-constrained access tokens.
#[allow(dead_code)]
pub async fn make_app_with_proof(per_ip_per_minute: u32) -> Router {
    tokio::task::spawn_blocking(move || {
        let stores = shared_stores();
        let service = Arc::new(make_service(&stores));
        sentinel_api::http::build_router_cfg(
            service,
            shared_relay(),
            shared_social(),
            shared_groups(),
            shared_transparency(),
            shared_membership(),
            per_ip_per_minute,
            None,
            true,
        )
    })
    .await
    .expect("app setup")
}

/// Build the app trusting a client-IP header (`x-real-client-ip`) for rate limiting, so tests can
/// exercise per-client-IP buckets behind a proxy.
pub async fn make_app_with_trusted_ip_header(per_ip_per_minute: u32) -> Router {
    tokio::task::spawn_blocking(move || {
        let stores = shared_stores();
        let service = Arc::new(make_service(&stores));
        sentinel_api::http::build_router_cfg(
            service,
            shared_relay(),
            shared_social(),
            shared_groups(),
            shared_transparency(),
            shared_membership(),
            per_ip_per_minute,
            Some(axum::http::HeaderName::from_static("x-real-client-ip")),
            false,
        )
    })
    .await
    .expect("app setup")
}

/// Make two accounts friends (request + accept). Direct adds to a conversation require the adder
/// to be friends with the target (ADR-0009), so relay/ws/load tests befriend before adding.
pub async fn befriend(app: &Router, token_a: &str, acct_a: &str, token_b: &str, acct_b: &str) {
    let (status, _) = post_json_auth(
        app,
        "/v1/friends/request",
        token_a,
        json!({ "account_id": acct_b }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "friend request should succeed");
    let (status, _) = post_json_auth(
        app,
        "/v1/friends/accept",
        token_b,
        json!({ "account_id": acct_a }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "friend accept should succeed"
    );
}

/// POST JSON carrying an `x-real-client-ip` header (a simulated proxy-forwarded client IP).
pub async fn post_json_with_client_ip(
    app: &Router,
    path: &str,
    body: Value,
    client_ip: &str,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-real-client-ip", client_ip)
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
    let value = if bytes.is_empty() {
        json!(null)
    } else {
        serde_json::from_slice(&bytes).unwrap_or(json!(null))
    };
    (status, value)
}

/// GET a path and return the response headers (for asserting security headers).
pub async fn response_headers(app: &Router, path: &str) -> axum::http::HeaderMap {
    let response = app
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).expect("request"))
        .await
        .expect("response");
    response.headers().clone()
}

pub async fn post_json(app: &Router, path: &str, body: Value) -> (StatusCode, Value) {
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
    let value = if bytes.is_empty() {
        json!(null)
    } else {
        serde_json::from_slice(&bytes).unwrap_or(json!(null))
    };
    (status, value)
}

/// Authenticated POST/GET with a Bearer access token.
pub async fn post_json_auth(
    app: &Router,
    path: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
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
    let value = if bytes.is_empty() {
        json!(null)
    } else {
        serde_json::from_slice(&bytes).unwrap_or(json!(null))
    };
    (status, value)
}

pub async fn put_json_auth(
    app: &Router,
    path: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::put(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
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
    let value = if bytes.is_empty() {
        json!(null)
    } else {
        serde_json::from_slice(&bytes).unwrap_or(json!(null))
    };
    (status, value)
}

pub async fn get_auth(app: &Router, path: &str, token: &str) -> (StatusCode, Value) {
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
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(json!(null)),
    )
}

pub fn id16_from_hex(s: &str) -> [u8; 16] {
    hex::decode(s).expect("hex").try_into().expect("16 bytes")
}

/// Sign a begin-endpoint challenge JSON with the given device for `action`.
pub fn sign_challenge(device: &TestDevice, challenge: &Value, action: Action) -> String {
    let account_id = AccountId(id16_from_hex(challenge["account_id"].as_str().unwrap()));
    let device_id = DeviceId(id16_from_hex(challenge["device_id"].as_str().unwrap()));
    let txn_id = TxnId(id16_from_hex(challenge["txn_id"].as_str().unwrap()));
    let nonce = hex::decode(challenge["nonce"].as_str().unwrap()).expect("hex");
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

/// Register a fresh account over HTTP; returns (device, session JSON).
pub async fn http_register(app: &Router, username: &str) -> (TestDevice, Value) {
    let device = TestDevice::new();
    let (status, challenge) = post_json(app, "/v1/register/begin", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let signature = sign_challenge(&device, &challenge, Action::Register);
    let (status, session) = post_json(
        app,
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
    assert_eq!(status, StatusCode::OK, "register finish: {session}");
    (device, session)
}
