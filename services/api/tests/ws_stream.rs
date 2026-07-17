//! WebSocket streaming delivery: proves `GET /v1/stream` pushes new envelopes to a connected
//! device the instant they are sent (no polling), with the same at-least-once ack semantics.
//! Needs a real socket (WS upgrades can't go through in-process `oneshot`), so it binds a
//! loopback listener and serves the SAME router the setup requests use (shared notifier).

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{befriend, get_auth, http_register, make_app, post_json_auth, unique_username};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

async fn recv_json<S>(ws: &mut S) -> Value
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("timely message")
            .expect("stream open")
            .expect("ws ok");
        match msg {
            Message::Text(t) => return serde_json::from_str(t.as_str()).expect("json"),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("unexpected ws frame: {other:?}"),
        }
    }
}

#[tokio::test]
async fn websocket_pushes_new_envelopes_instantly() {
    let app = make_app(100_000).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let served = app.clone(); // shares AppState (notifier, relay) with the oneshot `app`
    tokio::spawn(async move {
        let _ = axum::serve(listener, served.into_make_service()).await;
    });

    // Setup over the shared router.
    let (_a, alice) = http_register(&app, &unique_username("wssend")).await;
    let (_b, bob) = http_register(&app, &unique_username("wsrecv")).await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap().to_string();
    let bob_account = bob["account_id"].as_str().unwrap();
    let alice_account = alice["account_id"].as_str().unwrap();
    befriend(&app, alice_token, alice_account, &bob_token, bob_account).await;
    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice_token, json!({})).await;
    let conversation_id = conv["conversation_id"].as_str().unwrap().to_string();
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/members"),
        alice_token,
        json!({ "account_id": bob_account }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let send = |ciphertext: &'static [u8], key: u8| {
        let app = app.clone();
        let token = alice_token.to_string();
        let conv = conversation_id.clone();
        async move {
            post_json_auth(
                &app,
                &format!("/v1/conversations/{conv}/messages"),
                &token,
                json!({ "ciphertext": hex::encode(ciphertext), "idempotency_key": hex::encode([key; 16]) }),
            )
            .await
        }
    };

    // Part A: message queued BEFORE connect → delivered by the initial peek on connect.
    let (status, _) = send(b"first", 1).await;
    assert_eq!(status, StatusCode::OK);

    let mut request = format!("ws://{addr}/v1/stream")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {bob_token}").parse().unwrap(),
    );
    let (mut ws, _resp) = tokio_tungstenite::connect_async(request)
        .await
        .expect("ws connect");

    let push = recv_json(&mut ws).await;
    let envs = push["envelopes"].as_array().expect("array");
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0]["ciphertext"], hex::encode(b"first"));
    let first_id = envs[0]["id"].as_i64().unwrap();
    ws.send(Message::Text(
        json!({ "ack": [first_id] }).to_string().into(),
    ))
    .await
    .unwrap();

    // Part B: message sent WHILE connected → pushed near-instantly via the notifier wake.
    tokio::time::sleep(Duration::from_millis(100)).await; // let the ack land
    let start = std::time::Instant::now();
    let (status, _) = send(b"second", 2).await;
    assert_eq!(status, StatusCode::OK);
    let push2 = recv_json(&mut ws).await;
    let elapsed = start.elapsed();
    assert_eq!(push2["envelopes"][0]["ciphertext"], hex::encode(b"second"));
    assert!(
        elapsed < Duration::from_secs(2),
        "streamed push should be near-instant, took {elapsed:?}"
    );
    let second_id = push2["envelopes"][0]["id"].as_i64().unwrap();
    ws.send(Message::Text(
        json!({ "ack": [second_id] }).to_string().into(),
    ))
    .await
    .unwrap();

    // After both acks, the HTTP inbox is drained (same at-least-once queue).
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (_, inbox) = get_auth(&app, "/v1/inbox", &bob_token).await;
    assert_eq!(inbox.as_array().unwrap().len(), 0, "both messages acked");

    let _ = ws.close(None).await;
}

/// The stream requires authentication: an upgrade without a valid Bearer token is rejected.
#[tokio::test]
async fn websocket_requires_auth() {
    let app = make_app(100_000).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    let request = format!("ws://{addr}/v1/stream")
        .into_client_request()
        .unwrap();
    // No Authorization header → the handshake must fail (server returns 401, not 101).
    let result = tokio_tungstenite::connect_async(request).await;
    assert!(
        result.is_err(),
        "unauthenticated ws upgrade must be rejected"
    );
}
