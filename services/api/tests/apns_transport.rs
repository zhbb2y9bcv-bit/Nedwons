//! The REAL APNs transport (#4 gap closure): `HttpPushTransport` speaks HTTP/2 — proven end to end
//! against a local server (h2c prior knowledge; production `https://` uses ALPN with rustls) — and
//! the provider key loads straight from Apple's `.p8` PKCS#8 PEM.

mod common;

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri, Version};
use axum::routing::post;
use axum::Router;
use p256::ecdsa::SigningKey;

use sentinel_api::push::{
    build_push, signing_key_from_p8, ApnsConfig, HttpPushTransport, PushTransport,
};

/// What the mock APNs server observed for one request.
#[derive(Clone, Debug)]
struct Seen {
    version: Version,
    path: String,
    authorization: String,
    topic: String,
    push_type: String,
    body: Vec<u8>,
}

fn test_cfg() -> ApnsConfig {
    ApnsConfig {
        key_id: "ABC1234567".to_string(),
        team_id: "TEAM098765".to_string(),
        topic: "app.sentinel.messenger".to_string(),
        signing_key: SigningKey::from_slice(&[7u8; 32]).unwrap(),
    }
}

#[tokio::test]
async fn http_push_transport_speaks_http2_end_to_end() {
    // A local "APNs": records the request (including the negotiated HTTP version) and returns 200.
    let seen: Arc<Mutex<Option<Seen>>> = Arc::new(Mutex::new(None));
    let app = Router::new()
        .route(
            "/3/device/{token}",
            post(
                |State(seen): State<Arc<Mutex<Option<Seen>>>>,
                 version: Version,
                 uri: Uri,
                 headers: HeaderMap,
                 body: axum::body::Bytes| async move {
                    let h = |k: &str| {
                        headers
                            .get(k)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_string()
                    };
                    *seen.lock().unwrap() = Some(Seen {
                        version,
                        path: uri.path().to_string(),
                        authorization: h("authorization"),
                        topic: h("apns-topic"),
                        push_type: h("apns-push-type"),
                        body: body.to_vec(),
                    });
                    StatusCode::OK
                },
            ),
        )
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    // The real transport, pointed at the local server (http:// ⇒ HTTP/2 prior knowledge).
    let transport = HttpPushTransport::new(format!("http://{addr}"));
    let request = build_push(&test_cfg(), "deadbeefcafe", 1_700_000_000);
    let status = tokio::task::spawn_blocking(move || transport.post(&request))
        .await
        .unwrap()
        .expect("post succeeds");
    assert_eq!(status, 200);

    let seen = seen.lock().unwrap().clone().expect("server saw the push");
    // The APNs contract requires HTTP/2 — assert the connection actually negotiated it.
    assert_eq!(seen.version, Version::HTTP_2, "APNs requires HTTP/2");
    assert_eq!(seen.path, "/3/device/deadbeefcafe");
    assert!(seen.authorization.starts_with("bearer "));
    assert_eq!(seen.topic, "app.sentinel.messenger");
    assert_eq!(seen.push_type, "alert");
    let body = String::from_utf8(seen.body).unwrap();
    assert!(
        body.contains("mutable-content") && body.contains("New message"),
        "contentless wake payload"
    );
}

#[tokio::test]
async fn transport_reports_a_non_200_apns_status() {
    // APNs signals token errors via status codes (e.g. 410 Unregistered); the transport must
    // surface them, not swallow them.
    let app = Router::new().route("/3/device/{token}", post(|| async { StatusCode::GONE }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    let transport = HttpPushTransport::new(format!("http://{addr}"));
    let request = build_push(&test_cfg(), "gonetoken", 1_700_000_000);
    let status = tokio::task::spawn_blocking(move || transport.post(&request))
        .await
        .unwrap()
        .expect("request completes");
    assert_eq!(status, 410, "410 Unregistered surfaces to the caller");
}

#[test]
fn provider_key_loads_from_a_p8_pem() {
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::EncodePrivateKey;

    // A `.p8` as Apple ships it: a PKCS#8 PEM of a P-256 key.
    let key = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let pem = key.to_pkcs8_pem(Default::default()).unwrap().to_string();

    let parsed = signing_key_from_p8(&pem).expect("verbatim .p8 parses");
    // Same key: a signature from the parsed key verifies under the original public key.
    use p256::ecdsa::signature::Signer;
    let sig: p256::ecdsa::Signature = parsed.sign(b"jwt-signing-input");
    key.verifying_key()
        .verify(b"jwt-signing-input", &sig)
        .unwrap();

    // Env-file style with escaped newlines parses too.
    let escaped = pem.replace('\n', "\\n");
    assert!(
        signing_key_from_p8(&escaped).is_some(),
        "escaped-newline .p8 parses"
    );

    // Garbage fails closed.
    assert!(signing_key_from_p8("not a pem").is_none());
}
