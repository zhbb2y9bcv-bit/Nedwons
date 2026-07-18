//! Controlled multi-device (ADR-0008, R-903): a trusted device enrolls a second device, which
//! gets a working session; devices are listable and revocable; a stolen username/password can
//! never add a device.

mod common;

use axum::http::StatusCode;
use axum::Router;
use common::{
    get_auth, http_register, make_app, post_json, post_json_auth, unique_username, TestDevice,
};
use serde_json::{json, Value};

use auth_core::transcript::{Action, Transcript};

/// Enroll `new_device` onto `trusted`'s account. Returns the new device's session JSON.
async fn enroll_device(
    app: &Router,
    trusted_token: &str,
    trusted_account_hex: &str,
    trusted_signer: &TestDevice,
    new_device: &TestDevice,
) -> (StatusCode, Value) {
    let (status, ch) =
        post_json_auth(app, "/v1/devices/enroll/begin", trusted_token, json!({})).await;
    assert_eq!(status, StatusCode::OK, "enroll begin: {ch}");

    let account: [u8; 16] = hex::decode(trusted_account_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let new_device_id: [u8; 16] = hex::decode(ch["device_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let txn_id: [u8; 16] = hex::decode(ch["txn_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let nonce = hex::decode(ch["nonce"].as_str().unwrap()).unwrap();
    let expires_at = ch["expires_at"].as_u64().unwrap();

    // The TRUSTED device signs the DeviceEnroll transcript authorizing the NEW device's key.
    let transcript = Transcript {
        action: Action::DeviceEnroll,
        account_id: &auth_core::ids::AccountId(account),
        device_id: &auth_core::ids::DeviceId(new_device_id),
        public_key: &new_device.public_key,
        challenge: &nonce,
        expires_at,
        txn_id: &auth_core::ids::TxnId(txn_id),
    };
    let signature = trusted_signer.sign(&transcript.encode());

    post_json_auth(
        app,
        "/v1/devices/enroll/finish",
        trusted_token,
        json!({
            "txn_id": hex::encode(txn_id),
            "device_public_key": hex::encode(&new_device.public_key),
            "signature": hex::encode(signature),
        }),
    )
    .await
}

#[tokio::test]
async fn trusted_device_enrolls_a_second_device_that_can_act() {
    let app = make_app(100_000).await;
    let username = unique_username("multidev");
    let (device_a, session_a) = http_register(&app, &username).await;
    let token_a = session_a["access_token"].as_str().unwrap();
    let account = session_a["account_id"].as_str().unwrap();
    let device_a_id = session_a["device_id"].as_str().unwrap();

    let device_b = TestDevice::new();
    let (status, session_b) = enroll_device(&app, token_a, account, &device_a, &device_b).await;
    assert_eq!(status, StatusCode::OK, "enroll finish: {session_b}");
    let token_b = session_b["access_token"].as_str().unwrap();

    // Same account, distinct device.
    assert_eq!(session_b["account_id"].as_str().unwrap(), account);
    assert_ne!(session_b["device_id"].as_str().unwrap(), device_a_id);

    // Device B's session actually works.
    let (status, who) = get_auth(&app, "/v1/session/whoami", token_b).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        who["device_id"].as_str().unwrap(),
        session_b["device_id"].as_str().unwrap()
    );

    // The device list shows both, exactly one flagged current per caller.
    let (status, list_a) = get_auth(&app, "/v1/devices", token_a).await;
    assert_eq!(status, StatusCode::OK);
    let arr = list_a.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(
        arr.iter()
            .filter(|d| d["current"].as_bool().unwrap())
            .count(),
        1
    );
    assert_eq!(
        arr.iter()
            .filter(|d| d["revoked"].as_bool().unwrap())
            .count(),
        0
    );

    // Revoke B from A; B's session is now dead, A's still works.
    let (status, _) = post_json_auth(
        &app,
        "/v1/devices/revoke",
        token_a,
        json!({ "device_id": session_b["device_id"].as_str().unwrap() }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = get_auth(&app, "/v1/session/whoami", token_b).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "revoked device's token is dead"
    );
    let (status, _) = get_auth(&app, "/v1/session/whoami", token_a).await;
    assert_eq!(status, StatusCode::OK, "trusted device still works");
}

#[tokio::test]
async fn enrollment_needs_the_trusted_device_signature() {
    let app = make_app(100_000).await;
    let (_device_a, session_a) = http_register(&app, &unique_username("multidevbad")).await;
    let token_a = session_a["access_token"].as_str().unwrap();
    let account = session_a["account_id"].as_str().unwrap();

    // An attacker (not the trusted device) signs the authorization.
    let attacker = TestDevice::new();
    let device_b = TestDevice::new();
    let (status, _) = enroll_device(&app, token_a, account, &attacker, &device_b).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Only device A remains.
    let (_, list) = get_auth(&app, "/v1/devices", token_a).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn password_alone_cannot_add_a_device() {
    let app = make_app(100_000).await;
    let username = unique_username("nopwdadd");
    let (_device_a, _session_a) = http_register(&app, &username).await;

    // Re-registering the same username (i.e. "log in a brand-new device with just credentials")
    // is refused — a device can only be added through the trusted-device ceremony (R-903).
    let (status, challenge) = post_json(&app, "/v1/register/begin", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let device_c = TestDevice::new();
    let account: [u8; 16] = hex::decode(challenge["account_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let device_id: [u8; 16] = hex::decode(challenge["device_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let txn_id: [u8; 16] = hex::decode(challenge["txn_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let nonce = hex::decode(challenge["nonce"].as_str().unwrap()).unwrap();
    let expires_at = challenge["expires_at"].as_u64().unwrap();
    let transcript = Transcript {
        action: Action::Register,
        account_id: &auth_core::ids::AccountId(account),
        device_id: &auth_core::ids::DeviceId(device_id),
        public_key: &device_c.public_key,
        challenge: &nonce,
        expires_at,
        txn_id: &auth_core::ids::TxnId(txn_id),
    };
    let signature = device_c.sign(&transcript.encode());
    let (status, body) = post_json(
        &app,
        "/v1/register/finish",
        json!({
            "username": username,
            "password": common::PASSWORD,
            "device_public_key": hex::encode(&device_c.public_key),
            "txn_id": hex::encode(txn_id),
            "signature": hex::encode(signature),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "username_unavailable");
}

/// Device enrollment publishes the new device's binding to the transparency log, so a
/// self-monitoring client sees EVERY device bound to it — a server cannot add a device undetected
/// (ADR-0008 + R-201).
#[tokio::test]
async fn enrolled_device_binding_is_logged_in_transparency() {
    let app = make_app(100_000).await;
    let (device_a, session_a) = http_register(&app, &unique_username("ktdev")).await;
    let token_a = session_a["access_token"].as_str().unwrap();
    let account = session_a["account_id"].as_str().unwrap();
    let device_a_id = session_a["device_id"].as_str().unwrap();

    let device_b = TestDevice::new();
    let (status, session_b) = enroll_device(&app, token_a, account, &device_a, &device_b).await;
    assert_eq!(status, StatusCode::OK);
    let device_b_id = session_b["device_id"].as_str().unwrap();

    // Pin the account view to the current tree size and check BOTH devices are logged bindings.
    let (_, sth) = get_auth(&app, "/v1/transparency/sth", token_a).await;
    let tree_size = sth["tree_size"].as_u64().unwrap();
    let (status, view) = get_auth(
        &app,
        &format!("/v1/transparency/account/{account}?tree_size={tree_size}"),
        token_a,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let logged: Vec<&str> = view["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["device_id"].as_str().unwrap())
        .collect();
    assert!(logged.contains(&device_a_id), "original device logged");
    assert!(logged.contains(&device_b_id), "enrolled device logged too");
}

/// Revoking a device publishes a **revocation** leaf to the transparency log, so a device *removal*
/// is auditable under the signed root — not just additions (ADR-0013 Slice 2, R-201). The original
/// binding leaf still verifies unchanged, so an existing self-monitor is undisturbed.
#[tokio::test]
async fn device_revocation_is_logged_in_transparency() {
    let app = make_app(100_000).await;
    let (device_a, session_a) = http_register(&app, &unique_username("ktrev")).await;
    let token_a = session_a["access_token"].as_str().unwrap();
    let account = session_a["account_id"].as_str().unwrap();

    let device_b = TestDevice::new();
    let (status, session_b) = enroll_device(&app, token_a, account, &device_a, &device_b).await;
    assert_eq!(status, StatusCode::OK);
    let device_b_id = session_b["device_id"].as_str().unwrap().to_string();

    // Revoke B from the trusted device A.
    let (status, _) = post_json_auth(
        &app,
        "/v1/devices/revoke",
        token_a,
        json!({ "device_id": device_b_id }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, sth) = get_auth(&app, "/v1/transparency/sth", token_a).await;
    let tree_size = sth["tree_size"].as_u64().unwrap();
    let (status, view) = get_auth(
        &app,
        &format!("/v1/transparency/account/{account}?tree_size={tree_size}"),
        token_a,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let leaves = view["bindings"].as_array().unwrap();

    // Exactly one leaf is a revocation of device B, carrying revoked_at.
    let revocations: Vec<&serde_json::Value> = leaves
        .iter()
        .filter(|b| {
            b["device_id"].as_str() == Some(device_b_id.as_str()) && b["revoked_at"].is_u64()
        })
        .collect();
    assert_eq!(revocations.len(), 1, "one revocation leaf for B: {view}");
    assert!(revocations[0]["revoked_at"].as_u64().unwrap() > 0);

    // B's original BINDING leaf is still present and is NOT marked revoked — the append-only history
    // keeps both, so an existing self-monitor (which reads the earliest leaf) is unaffected.
    let binding_for_b = leaves.iter().find(|b| {
        b["device_id"].as_str() == Some(device_b_id.as_str()) && b["revoked_at"].is_null()
    });
    assert!(binding_for_b.is_some(), "B's binding leaf still present");
}
