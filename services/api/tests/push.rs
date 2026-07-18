//! Push notifications (#4): a device registers an APNs wake token; the push service dispatches a
//! contentless wake to it (via an injected recording transport — no real APNs socket); and revoking
//! a device deletes its tokens. The relay stays E2EE-blind — the push carries no message content.

mod common;

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use common::{
    enroll_device, http_register, make_app, post_json_auth, shared_relay, unique_username,
    TestDevice,
};
use p256::ecdsa::SigningKey;
use serde_json::json;

use auth_core::ids::DeviceId;
use sentinel_api::push::{ApnsConfig, ApnsRequest, PushService, PushTransport};

/// A transport that records requests instead of opening a socket to Apple.
#[derive(Default)]
struct Recording {
    sent: Mutex<Vec<ApnsRequest>>,
}
impl PushTransport for Recording {
    fn post(&self, request: &ApnsRequest) -> Result<u16, String> {
        self.sent.lock().unwrap().push(request.clone());
        Ok(200)
    }
}

fn test_cfg() -> ApnsConfig {
    ApnsConfig {
        key_id: "ABC1234567".to_string(),
        team_id: "TEAM098765".to_string(),
        topic: "app.sentinel.messenger".to_string(),
        signing_key: SigningKey::from_slice(&[7u8; 32]).unwrap(),
    }
}

fn id16(hex_str: &str) -> [u8; 16] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

/// Read a device's registered push-token count off the async path (the sync postgres client's
/// connection drop runs `block_on`, which panics inside an async context).
async fn token_count(device: DeviceId) -> usize {
    tokio::task::spawn_blocking(move || {
        shared_relay()
            .push_tokens_for_device(&device)
            .unwrap()
            .len()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn registered_token_gets_a_contentless_wake_push() {
    let app = make_app(100_000).await;
    let (_dev, session) = http_register(&app, &unique_username("push")).await;
    let token = session["access_token"].as_str().unwrap();
    let device = DeviceId(id16(session["device_id"].as_str().unwrap()));

    // The device registers its APNs token through the endpoint.
    let (status, _) = post_json_auth(
        &app,
        "/v1/push/register",
        token,
        json!({ "platform": "apns", "token": "abc123devicetoken" }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A non-apns platform / oversize token is rejected.
    let (status, _) = post_json_auth(
        &app,
        "/v1/push/register",
        token,
        json!({ "platform": "carrier-pigeon", "token": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The push service (recording transport, over the same DB) dispatches a wake to the token.
    let recording = Arc::new(Recording::default());
    let service = PushService::new(test_cfg(), recording.clone(), shared_relay());
    tokio::task::spawn_blocking(move || service.notify_device_blocking(&device.0))
        .await
        .unwrap();

    let sent = recording.sent.lock().unwrap();
    assert_eq!(sent.len(), 1, "one wake push to the registered token");
    assert_eq!(sent[0].path, "/3/device/abc123devicetoken");
    assert!(sent[0].authorization.starts_with("bearer "));
    assert_eq!(sent[0].apns_topic, "app.sentinel.messenger");
    let body = String::from_utf8(sent[0].body.clone()).unwrap();
    assert!(
        body.contains("mutable-content") && !body.contains("abc123"),
        "push is a contentless wake — no token/content leaks into the payload"
    );
}

#[tokio::test]
async fn a_disabled_push_service_dispatches_nothing() {
    // With no APNs config, notify is a safe no-op — the wake path never fails.
    let service = PushService::disabled();
    assert!(!service.is_enabled());
    service.notify_device_blocking(&[1u8; 16]);
}

#[tokio::test]
async fn revoking_a_device_deletes_its_push_tokens() {
    let app = make_app(100_000).await;
    let (phone_dev, phone) = http_register(&app, &unique_username("pushrevoke")).await;
    let phone_token = phone["access_token"].as_str().unwrap();
    let account = phone["account_id"].as_str().unwrap();

    // Enroll a tablet and register its push token.
    let tablet_dev = TestDevice::new();
    let tablet = enroll_device(&app, phone_token, account, &phone_dev, &tablet_dev).await;
    let tablet_token = tablet["access_token"].as_str().unwrap();
    let tablet_device = DeviceId(id16(tablet["device_id"].as_str().unwrap()));
    let (status, _) = post_json_auth(
        &app,
        "/v1/push/register",
        tablet_token,
        json!({ "platform": "apns", "token": "tablettoken" }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(token_count(tablet_device).await, 1);

    // Revoke the tablet; its push tokens are deleted so it is never woken again.
    let (status, _) = post_json_auth(
        &app,
        "/v1/devices/revoke",
        phone_token,
        json!({ "device_id": tablet["device_id"].as_str().unwrap() }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        token_count(tablet_device).await,
        0,
        "a revoked device's push tokens are purged"
    );
}
