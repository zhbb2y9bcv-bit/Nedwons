//! Sealed-sender delivery access key registration (ADR-0014 Slice 2a, R-204). A recipient registers
//! the VERIFIER of its delivery access key; the relay stores only the hash, never the key. No
//! delivery path exists yet — this is only the gate value.

mod common;

use axum::http::StatusCode;
use common::{
    get_auth, http_register, id16_from_hex, make_app, put_json_auth, shared_relay, unique_username,
};
use serde_json::json;

/// Read a stored verifier off the async thread (the sync `postgres` client hosts its own runtime).
async fn read_verifier(account: auth_core::ids::AccountId) -> Vec<u8> {
    tokio::task::spawn_blocking(move || shared_relay().delivery_verifier(&account))
        .await
        .expect("join")
        .expect("query")
        .expect("verifier stored")
}

#[tokio::test]
async fn register_and_rotate_delivery_access_verifier() {
    let app = make_app(100_000).await;
    let (_device, session) = http_register(&app, &unique_username("dak")).await;
    let token = session["access_token"].as_str().unwrap();
    let account = auth_core::ids::AccountId(id16_from_hex(session["account_id"].as_str().unwrap()));

    // Register V_r = SHA-256(K_r) for a client-chosen K_r.
    let dak = [0x5Au8; auth_core::delivery_key::DAK_LEN];
    let verifier = auth_core::delivery_key::verifier(&dak);
    let (status, _) = put_json_auth(
        &app,
        "/v1/delivery-access-key",
        token,
        json!({ "verifier": hex::encode(verifier) }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The relay stored the verifier, and the original K_r verifies against it (but only the hash is
    // stored — never K_r itself). The sync store hosts its own runtime, so read off the async thread.
    let stored = read_verifier(account).await;
    assert_eq!(stored, verifier.to_vec());
    assert!(auth_core::delivery_key::verify(&dak, &stored));
    assert!(!auth_core::delivery_key::verify(&[0x00u8; 32], &stored));

    // Rotation: a new key replaces the old verifier, revoking the old key at the relay.
    let dak2 = [0xA5u8; auth_core::delivery_key::DAK_LEN];
    let verifier2 = auth_core::delivery_key::verifier(&dak2);
    let (status, _) = put_json_auth(
        &app,
        "/v1/delivery-access-key",
        token,
        json!({ "verifier": hex::encode(verifier2) }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let rotated = read_verifier(account).await;
    assert_eq!(rotated, verifier2.to_vec());
    assert!(
        !auth_core::delivery_key::verify(&dak, &rotated),
        "old key revoked"
    );
    assert!(auth_core::delivery_key::verify(&dak2, &rotated));
}

#[tokio::test]
async fn malformed_verifier_is_rejected() {
    let app = make_app(100_000).await;
    let (_device, session) = http_register(&app, &unique_username("dakbad")).await;
    let token = session["access_token"].as_str().unwrap();

    // Not 32 bytes of hex → 400.
    let (status, _) = put_json_auth(
        &app,
        "/v1/delivery-access-key",
        token,
        json!({ "verifier": "abcd" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn registration_requires_auth() {
    let app = make_app(100_000).await;
    // Unauthenticated GET on the route's namespace is a good enough auth probe; the PUT handler
    // authenticates first, so a bad token is rejected before any store touch.
    let (status, _) = get_auth(&app, "/v1/session/whoami", "zz").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = put_json_auth(
        &app,
        "/v1/delivery-access-key",
        "zz",
        json!({ "verifier": "00" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
