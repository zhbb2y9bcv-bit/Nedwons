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
use nedwons_api::push::{ApnsConfig, ApnsRequest, PushResponse, PushService, PushTransport};

/// A transport that records requests instead of opening a socket to Apple, and replies with
/// whatever the test scripted — so a rejection path can be driven as easily as the happy one.
#[derive(Default)]
struct Recording {
    sent: Mutex<Vec<ApnsRequest>>,
    /// The reply handed back for every dispatch. Defaults to `200 accepted`.
    reply: Mutex<Option<PushResponse>>,
}

impl Recording {
    /// Reply to every subsequent dispatch with this status and APNs error body.
    fn replying(status: u16, body: &str) -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            reply: Mutex::new(Some(PushResponse {
                status,
                body: body.as_bytes().to_vec(),
            })),
        }
    }
}

impl PushTransport for Recording {
    fn post(&self, request: &ApnsRequest) -> Result<PushResponse, String> {
        self.sent.lock().unwrap().push(request.clone());
        Ok(self
            .reply
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(PushResponse::accepted))
    }
}

fn test_cfg() -> ApnsConfig {
    ApnsConfig {
        key_id: "ABC1234567".to_string(),
        team_id: "TEAM098765".to_string(),
        topic: "app.nedwons.messenger".to_string(),
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
    assert_eq!(sent[0].apns_topic, "app.nedwons.messenger");
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

// ----- APNs reply accounting ------------------------------------------------------------------
//
// Only `200` means delivered. This used to count every `Ok(_)` as sent, so a `410 Unregistered`,
// a `400 BadDeviceToken` and a `403` from an expired provider key all incremented the SUCCESS
// counter — the push dashboard read as perfectly healthy while Apple rejected every notification.
// These tests pin the reply-to-outcome mapping, including which rejections delete the token.

/// The classification itself, exhaustively, with no database in the way.
#[test]
fn only_a_200_is_a_send_and_only_dead_tokens_are_dropped() {
    use nedwons_api::push::token_is_dead;

    let accepted = PushResponse::accepted();
    assert_eq!(accepted.status, 200);
    assert!(
        !token_is_dead(&accepted),
        "a delivered push keeps its token"
    );

    // 410 is unconditional: Apple returns it only for a token that is no longer active.
    let unregistered = PushResponse {
        status: 410,
        body: br#"{"reason":"Unregistered"}"#.to_vec(),
    };
    assert!(token_is_dead(&unregistered));
    assert_eq!(unregistered.reason(), Some("Unregistered"));

    // On 400 the REASON decides — that status also covers payload and header faults that say
    // nothing at all about the token's validity.
    for reason in ["BadDeviceToken", "DeviceTokenNotForTopic"] {
        let dead = PushResponse {
            status: 400,
            body: format!(r#"{{"reason":"{reason}"}}"#).into_bytes(),
        };
        assert!(token_is_dead(&dead), "{reason} means the token is gone");
    }
    let payload_fault = PushResponse {
        status: 400,
        body: br#"{"reason":"PayloadTooLarge"}"#.to_vec(),
    };
    assert!(
        !token_is_dead(&payload_fault),
        "our payload being wrong is not the user's token being invalid"
    );

    // Transient and operator faults must never cost a user their push registration.
    for (status, reason) in [
        (429u16, "TooManyRequests"),
        (500, "InternalServerError"),
        (503, "ServiceUnavailable"),
        (403, "ExpiredProviderToken"),
    ] {
        let transient = PushResponse {
            status,
            body: format!(r#"{{"reason":"{reason}"}}"#).into_bytes(),
        };
        assert!(
            !token_is_dead(&transient),
            "{status} {reason} is transient — deleting the token would make an outage permanent"
        );
    }

    // A body that cannot be parsed degrades to "unknown reason", which keeps the token.
    let garbled = PushResponse {
        status: 400,
        body: vec![0xff, 0xfe, 0xfd],
    };
    assert_eq!(garbled.reason(), None);
    assert!(!token_is_dead(&garbled));
}

/// End to end over the real table: a token APNs calls permanently invalid is removed, so the relay
/// stops pushing into the void on every subsequent message.
#[tokio::test]
async fn an_unregistered_token_is_deleted_after_dispatch() {
    let app = make_app(100_000).await;
    let (_dev, session) = http_register(&app, &unique_username("pushdead")).await;
    let token = session["access_token"].as_str().unwrap();
    let device = DeviceId(id16(session["device_id"].as_str().unwrap()));

    let (status, _) = post_json_auth(
        &app,
        "/v1/push/register",
        token,
        json!({ "platform": "apns", "token": "staletoken0001" }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(token_count(device).await, 1);

    let recording = Arc::new(Recording::replying(410, r#"{"reason":"Unregistered"}"#));
    let service = PushService::new(test_cfg(), recording.clone(), shared_relay());
    tokio::task::spawn_blocking(move || service.notify_device_blocking(&device.0))
        .await
        .unwrap();

    assert_eq!(
        token_count(device).await,
        0,
        "a token Apple reports as Unregistered must be removed"
    );
}

/// The opposite guarantee: a transient refusal leaves the registration intact, so a brief APNs
/// outage does not silently disable push for every user who received a message during it.
#[tokio::test]
async fn a_transient_refusal_keeps_the_token() {
    let app = make_app(100_000).await;
    let (_dev, session) = http_register(&app, &unique_username("pushsoft")).await;
    let token = session["access_token"].as_str().unwrap();
    let device = DeviceId(id16(session["device_id"].as_str().unwrap()));

    let (status, _) = post_json_auth(
        &app,
        "/v1/push/register",
        token,
        json!({ "platform": "apns", "token": "livetoken0002" }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let recording = Arc::new(Recording::replying(
        503,
        r#"{"reason":"ServiceUnavailable"}"#,
    ));
    let service = PushService::new(test_cfg(), recording.clone(), shared_relay());
    tokio::task::spawn_blocking(move || service.notify_device_blocking(&device.0))
        .await
        .unwrap();

    assert_eq!(
        token_count(device).await,
        1,
        "a 503 is Apple being briefly unavailable, not the token being invalid"
    );
}

/// Deleting is scoped to the exact token: a device that re-registered a fresh token between the
/// dispatch and the cleanup must keep the working one.
#[tokio::test]
async fn dropping_a_dead_token_spares_a_freshly_registered_one() {
    let app = make_app(100_000).await;
    let (_dev, session) = http_register(&app, &unique_username("pushswap")).await;
    let token = session["access_token"].as_str().unwrap();
    let device = DeviceId(id16(session["device_id"].as_str().unwrap()));

    let (status, _) = post_json_auth(
        &app,
        "/v1/push/register",
        token,
        json!({ "platform": "apns", "token": "rotated-fresh-0003" }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Delete the token the dispatch SAW (an older one), not whatever the device holds now.
    let removed = tokio::task::spawn_blocking(move || {
        shared_relay().delete_push_token(&device, "a-token-that-is-gone")
    })
    .await
    .unwrap()
    .unwrap();

    assert_eq!(removed, 0, "a token that is not stored removes nothing");
    assert_eq!(
        token_count(device).await,
        1,
        "the freshly registered token survives cleanup aimed at a different one"
    );
}
