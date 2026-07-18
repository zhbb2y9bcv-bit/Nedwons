//! App Attest (#10): the server issues a single-use challenge, accepts an attestation that echoes
//! it (anti-replay), stores it bound to the device (unverified — the Apple-root crypto verification
//! is the hardware-gated step), and refuses a wrong/replayed challenge.

mod common;

use axum::http::StatusCode;
use common::{get_auth, http_register, make_app, post_json_auth, shared_relay, unique_username};
use serde_json::json;

use auth_core::ids::DeviceId;

fn id16(hex_str: &str) -> [u8; 16] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

async fn stored_attestation(device: DeviceId) -> Option<(String, bool)> {
    tokio::task::spawn_blocking(move || shared_relay().attestation_for_device(&device).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn attest_challenge_then_submit_stores_unverified() {
    let app = make_app(100_000).await;
    let (_dev, session) = http_register(&app, &unique_username("attest")).await;
    let token = session["access_token"].as_str().unwrap();
    let device = DeviceId(id16(session["device_id"].as_str().unwrap()));

    // Issue a challenge.
    let (status, ch) = get_auth(&app, "/v1/attest/challenge", token).await;
    assert_eq!(status, StatusCode::OK);
    let challenge = ch["challenge"].as_str().unwrap().to_string();
    assert_eq!(challenge.len(), 64, "32-byte challenge in hex");

    // Submit an attestation that echoes the challenge → stored (unverified).
    let (status, _) = post_json_auth(
        &app,
        "/v1/attest/key",
        token,
        json!({ "key_id": "abc-key-id", "challenge": challenge, "attestation": "cafebabe" }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let stored = stored_attestation(device).await;
    assert_eq!(stored, Some(("abc-key-id".to_string(), false)));

    // The challenge is single-use: replaying it now fails (it was consumed).
    let (status, _) = post_json_auth(
        &app,
        "/v1/attest/key",
        token,
        json!({ "key_id": "abc-key-id", "challenge": challenge, "attestation": "cafebabe" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a consumed challenge is refused"
    );
}

#[tokio::test]
async fn a_wrong_challenge_is_refused() {
    let app = make_app(100_000).await;
    let (_dev, session) = http_register(&app, &unique_username("attestbad")).await;
    let token = session["access_token"].as_str().unwrap();

    // Get a challenge but submit a DIFFERENT one.
    let (_, _ch) = get_auth(&app, "/v1/attest/challenge", token).await;
    let wrong = hex::encode([0xABu8; 32]);
    let (status, _) = post_json_auth(
        &app,
        "/v1/attest/key",
        token,
        json!({ "key_id": "k", "challenge": wrong, "attestation": "aa" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
