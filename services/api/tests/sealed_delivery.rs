//! Sealed-sender delivery (ADR-0014 Slice 2b, R-204). An unauthenticated sender presents the
//! recipient's delivery access key `K_r`; the relay stores an envelope with NO sender and NO
//! conversation, the recipient reads it via its inbox (sealed flag, no sender), and acks it. A
//! wrong/absent key or unknown device is uniformly refused.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{get_auth, http_register, make_app, put_json_auth, unique_username};
use serde_json::{json, Value};
use tower::ServiceExt;

/// POST /v1/sealed/deliver unauthenticated, presenting `dak` (raw K_r) as the delivery key.
async fn deliver_sealed(
    app: &axum::Router,
    dak_hex: Option<&str>,
    recipient_device: &str,
    ciphertext: &str,
    idempotency_key: &str,
) -> StatusCode {
    let mut req = Request::post("/v1/sealed/deliver").header("content-type", "application/json");
    if let Some(k) = dak_hex {
        req = req.header("x-delivery-key", k);
    }
    let body = json!({
        "recipient_device": recipient_device,
        "ciphertext": ciphertext,
        "idempotency_key": idempotency_key,
    })
    .to_string();
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body)).expect("request"))
        .await
        .expect("response");
    resp.status()
}

async fn register_dak(app: &axum::Router, token: &str) -> [u8; 32] {
    let dak = [0x7Cu8; auth_core::delivery_key::DAK_LEN];
    let verifier = auth_core::delivery_key::verifier(&dak);
    let (status, _) = put_json_auth(
        app,
        "/v1/delivery-access-key",
        token,
        json!({ "verifier": hex::encode(verifier) }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    dak
}

#[tokio::test]
async fn sealed_message_delivered_read_and_acked_without_a_sender() {
    let app = make_app(100_000).await;
    let (_d, session) = http_register(&app, &unique_username("seal")).await;
    let token = session["access_token"].as_str().unwrap();
    let recipient_device = session["device_id"].as_str().unwrap().to_string();
    let dak = register_dak(&app, token).await;

    // A sender who holds K_r delivers a sealed message (unauthenticated).
    let ciphertext = "aabbccdd";
    let idem = hex::encode([0x11u8; 16]);
    let status = deliver_sealed(
        &app,
        Some(&hex::encode(dak)),
        &recipient_device,
        ciphertext,
        &idem,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);

    // The recipient reads it: sealed flag set, NO sender_device / conversation_id present.
    let (status, inbox) = get_auth(&app, "/v1/inbox", token).await;
    assert_eq!(status, StatusCode::OK);
    let items = inbox.as_array().unwrap();
    let sealed: Vec<&Value> = items
        .iter()
        .filter(|e| e["sealed"] == json!(true))
        .collect();
    assert_eq!(sealed.len(), 1, "one sealed envelope: {inbox}");
    let e = sealed[0];
    assert_eq!(e["ciphertext"].as_str().unwrap(), ciphertext);
    assert!(e["sender_device"].is_null(), "relay learned no sender");
    assert!(
        e["conversation_id"].is_null(),
        "relay learned no conversation"
    );
    let sealed_id = e["id"].as_i64().unwrap();

    // A retry with the SAME idempotency key is deduplicated (still one in the inbox).
    let status = deliver_sealed(
        &app,
        Some(&hex::encode(dak)),
        &recipient_device,
        ciphertext,
        &idem,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (_, inbox) = get_auth(&app, "/v1/inbox", token).await;
    let sealed_count = inbox
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["sealed"] == json!(true))
        .count();
    assert_eq!(sealed_count, 1, "idempotent retry did not duplicate");

    // Ack it via sealed_ids (separate id space); the inbox is then empty of sealed mail.
    let (status, _) = common::post_json_auth(
        &app,
        "/v1/inbox/ack",
        token,
        json!({ "ids": [], "sealed_ids": [sealed_id] }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, inbox) = get_auth(&app, "/v1/inbox", token).await;
    assert!(inbox
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["sealed"] != json!(true)));
}

#[tokio::test]
async fn wrong_or_absent_key_and_unknown_device_are_uniformly_refused() {
    let app = make_app(100_000).await;
    let (_d, session) = http_register(&app, &unique_username("sealbad")).await;
    let token = session["access_token"].as_str().unwrap();
    let recipient_device = session["device_id"].as_str().unwrap().to_string();
    let _dak = register_dak(&app, token).await;

    let ciphertext = "0102";
    let idem = hex::encode([0x22u8; 16]);

    // Wrong key → 403.
    let wrong = hex::encode([0x00u8; 32]);
    let status = deliver_sealed(&app, Some(&wrong), &recipient_device, ciphertext, &idem).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Absent key → same 403 (no oracle).
    let status = deliver_sealed(&app, None, &recipient_device, ciphertext, &idem).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Unknown recipient device → same 403 (no existence oracle), even with a syntactically valid key.
    let unknown_device = hex::encode([0xEEu8; 16]);
    let status = deliver_sealed(&app, Some(&wrong), &unknown_device, ciphertext, &idem).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Nothing was enqueued.
    let (_, inbox) = get_auth(&app, "/v1/inbox", token).await;
    assert!(inbox.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn sealed_delivery_needs_a_registered_verifier() {
    // A recipient that never registered a DAK cannot receive sealed mail (uniform 403), so a sender
    // must fall back to identified delivery.
    let app = make_app(100_000).await;
    let (_d, session) = http_register(&app, &unique_username("nodak")).await;
    let recipient_device = session["device_id"].as_str().unwrap().to_string();
    let any_key = hex::encode([0x33u8; 32]);
    let status = deliver_sealed(
        &app,
        Some(&any_key),
        &recipient_device,
        "00",
        &hex::encode([0x44u8; 16]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
