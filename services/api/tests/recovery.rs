//! Account recovery (ADR-0003, R-304): a high-entropy recovery secret set while authenticated can
//! later enroll a NEW device with no other device present. Wrong/unset secrets are refused.

mod common;

use axum::http::StatusCode;
use axum::Router;
use common::{
    get_auth, http_register, make_app, post_json, post_json_auth, unique_username, TestDevice,
};
use serde_json::{json, Value};

use auth_core::transcript::{Action, Transcript};

const SECRET: &str = "recover-code-3f9a2b8c7d1e0f4a5b6c";

/// Run the recovery ceremony onto `new_device`. Returns (status, body) of finish.
async fn recover(
    app: &Router,
    username: &str,
    secret: &str,
    new_device: &TestDevice,
) -> (StatusCode, Value) {
    let (status, ch) = post_json(app, "/v1/recover/begin", json!({ "username": username })).await;
    assert_eq!(status, StatusCode::OK, "recover begin: {ch}");

    let account: [u8; 16] = hex::decode(ch["account_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let device_id: [u8; 16] = hex::decode(ch["device_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let txn_id: [u8; 16] = hex::decode(ch["txn_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let nonce = hex::decode(ch["nonce"].as_str().unwrap()).unwrap();
    let expires_at = ch["expires_at"].as_u64().unwrap();

    // The recovering device self-signs the DeviceEnroll transcript (proof of possession).
    let transcript = Transcript {
        action: Action::DeviceEnroll,
        account_id: &auth_core::ids::AccountId(account),
        device_id: &auth_core::ids::DeviceId(device_id),
        public_key: &new_device.public_key,
        challenge: &nonce,
        expires_at,
        txn_id: &auth_core::ids::TxnId(txn_id),
    };
    let signature = new_device.sign(&transcript.encode());

    post_json(
        app,
        "/v1/recover/finish",
        json!({
            "username": username,
            "recovery_secret": secret,
            "txn_id": hex::encode(txn_id),
            "device_public_key": hex::encode(&new_device.public_key),
            "signature": hex::encode(signature),
        }),
    )
    .await
}

#[tokio::test]
async fn recovery_with_the_secret_restores_account_access() {
    let app = make_app(100_000).await;
    let username = unique_username("recovok");
    let (_device_a, session_a) = http_register(&app, &username).await;
    let token_a = session_a["access_token"].as_str().unwrap();
    let account = session_a["account_id"].as_str().unwrap();

    // Set a recovery secret while we still have a device.
    let (status, _) = post_json_auth(
        &app,
        "/v1/recovery/set",
        token_a,
        json!({ "recovery_secret": SECRET }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // "Lose" device A; recover with a brand-new device C.
    let device_c = TestDevice::new();
    let (status, session_c) = recover(&app, &username, SECRET, &device_c).await;
    assert_eq!(status, StatusCode::OK, "recover finish: {session_c}");
    assert_eq!(session_c["account_id"].as_str().unwrap(), account);
    assert_ne!(
        session_c["device_id"].as_str().unwrap(),
        session_a["device_id"].as_str().unwrap()
    );

    // The recovered device's session works.
    let token_c = session_c["access_token"].as_str().unwrap();
    let (status, who) = get_auth(&app, "/v1/session/whoami", token_c).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(who["account_id"].as_str().unwrap(), account);

    // The recovered device can now revoke the lost one (device hygiene after recovery).
    let (status, _) = post_json_auth(
        &app,
        "/v1/devices/revoke",
        token_c,
        json!({ "device_id": session_a["device_id"].as_str().unwrap() }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = get_auth(&app, "/v1/session/whoami", token_a).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the lost device is revoked"
    );
}

#[tokio::test]
async fn recovery_rejects_a_wrong_secret() {
    let app = make_app(100_000).await;
    let username = unique_username("recovwrong");
    let (_device_a, session_a) = http_register(&app, &username).await;
    let token_a = session_a["access_token"].as_str().unwrap();
    post_json_auth(
        &app,
        "/v1/recovery/set",
        token_a,
        json!({ "recovery_secret": SECRET }),
    )
    .await;

    let device_c = TestDevice::new();
    let (status, _) = recover(&app, &username, "the-wrong-secret-0000000", &device_c).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn recovery_denied_when_no_secret_set_and_for_unknown_user() {
    let app = make_app(100_000).await;
    let username = unique_username("recovnone");
    let (_device_a, _session_a) = http_register(&app, &username).await;

    // Account exists but never set a recovery secret.
    let device_c = TestDevice::new();
    let (status, _) = recover(&app, &username, SECRET, &device_c).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Unknown username: begin still returns a (decoy) challenge, finish is refused.
    let device_d = TestDevice::new();
    let (status, _) = recover(&app, &unique_username("ghost"), SECRET, &device_d).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
