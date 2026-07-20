//! Sender-constrained access tokens (ADR-0011, R-308): with enforcement ON, a bearer token is
//! only honored alongside a valid per-request device proof. A stolen token alone is inert.

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use common::{http_register, make_app_with_proof, unique_username, TestDevice};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Build an `X-Nedwons-Proof` header value by signing the canonical request-proof transcript with
/// `device`'s key.
fn make_proof(
    device: &TestDevice,
    token_hex: &str,
    method: &str,
    path: &str,
    ts: u64,
    nonce: [u8; 16],
) -> String {
    let token = hex::decode(token_hex).unwrap();
    let token_hash = auth_core::crypto::sha256(&token);
    let proof = auth_core::request_proof::RequestProof {
        method: method.as_bytes(),
        path: path.as_bytes(),
        access_token_hash: &token_hash,
        timestamp: ts,
        nonce: &nonce,
    };
    let sig = device.sign(&proof.encode());
    format!(
        "v1;ts={ts};nonce={};sig={}",
        hex::encode(nonce),
        hex::encode(sig)
    )
}

async fn get_status(app: &Router, path: &str, token: &str, proof: Option<&str>) -> StatusCode {
    let mut builder = Request::get(path).header(header::AUTHORIZATION, format!("Bearer {token}"));
    if let Some(p) = proof {
        builder = builder.header("x-nedwons-proof", p);
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    // Drain the body so the connection future completes cleanly.
    let _ = resp.into_body().collect().await;
    status
}

#[tokio::test]
async fn access_token_requires_a_valid_device_proof() {
    let app = make_app_with_proof(100_000).await;
    let (device, session) = http_register(&app, &unique_username("dpop")).await;
    let token = session["access_token"].as_str().unwrap();
    let path = "/v1/session/whoami";
    let t = now();

    // A bearer token with NO proof is refused (this is the point — a stolen token is inert).
    assert_eq!(
        get_status(&app, path, token, None).await,
        StatusCode::UNAUTHORIZED
    );

    // A valid proof from the enrolled device is accepted.
    let proof = make_proof(&device, token, "GET", path, t, [1u8; 16]);
    assert_eq!(
        get_status(&app, path, token, Some(&proof)).await,
        StatusCode::OK
    );

    // Replaying the SAME proof is refused (single-use nonce).
    assert_eq!(
        get_status(&app, path, token, Some(&proof)).await,
        StatusCode::UNAUTHORIZED
    );

    // A proof bound to a DIFFERENT path cannot be used here (request binding).
    let wrong_path = make_proof(&device, token, "GET", "/v1/inbox", t, [2u8; 16]);
    assert_eq!(
        get_status(&app, path, token, Some(&wrong_path)).await,
        StatusCode::UNAUTHORIZED
    );

    // A proof bound to a DIFFERENT method is refused.
    let wrong_method = make_proof(&device, token, "POST", path, t, [3u8; 16]);
    assert_eq!(
        get_status(&app, path, token, Some(&wrong_method)).await,
        StatusCode::UNAUTHORIZED
    );

    // A stale timestamp is refused (outside the freshness window).
    let stale = make_proof(&device, token, "GET", path, t - 3600, [4u8; 16]);
    assert_eq!(
        get_status(&app, path, token, Some(&stale)).await,
        StatusCode::UNAUTHORIZED
    );

    // A proof signed by a DIFFERENT device key is refused (proof-of-possession) — the core
    // property: a token thief without the non-exportable key cannot forge a proof.
    let attacker = TestDevice::new();
    let forged = make_proof(&attacker, token, "GET", path, t, [5u8; 16]);
    assert_eq!(
        get_status(&app, path, token, Some(&forged)).await,
        StatusCode::UNAUTHORIZED
    );

    // A fresh, correctly-bound proof with a NEW nonce still works (the token is fine; only the
    // per-request proof is consumed).
    let fresh = make_proof(&device, token, "GET", path, now(), [6u8; 16]);
    assert_eq!(
        get_status(&app, path, token, Some(&fresh)).await,
        StatusCode::OK
    );
}

/// Unauthenticated endpoints are unaffected by proof enforcement (no Authorization ⇒ no proof
/// required): registration and health still work.
#[tokio::test]
async fn unauthenticated_endpoints_need_no_proof() {
    let app = make_app_with_proof(100_000).await;
    // http_register drives /v1/register/begin + /finish, neither of which sends Authorization.
    let (_device, session) = http_register(&app, &unique_username("dpopreg")).await;
    assert!(session["access_token"].is_string());

    let resp = app
        .clone()
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
