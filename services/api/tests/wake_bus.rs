//! The cross-instance delivery wake (Postgres LISTEN/NOTIFY): a long-poll parked on ONE API
//! instance wakes when a DIFFERENT instance queues its mail — the property that lets the relay
//! scale horizontally without a client noticing anything but its message arriving.

mod common;

use axum::http::StatusCode;
use common::{
    befriend, get_auth, http_register, make_app_with_wake_bus, post_json_auth, unique_username,
};
use serde_json::json;

#[tokio::test]
async fn long_poll_on_one_instance_wakes_from_a_send_on_another() {
    // Two ROUTERS = two instances: separate in-process notifiers, shared database + bus.
    let instance_a = make_app_with_wake_bus(100_000).await;
    let instance_b = make_app_with_wake_bus(100_000).await;

    let (_da, u1) = http_register(&instance_a, &unique_username("wba")).await;
    let (_db, u2) = http_register(&instance_a, &unique_username("wbb")).await;
    let (alice_tok, alice_acct) = (
        u1["access_token"].as_str().unwrap().to_string(),
        u1["account_id"].as_str().unwrap().to_string(),
    );
    let (bob_tok, bob_acct) = (
        u2["access_token"].as_str().unwrap().to_string(),
        u2["account_id"].as_str().unwrap().to_string(),
    );
    befriend(&instance_a, &alice_tok, &alice_acct, &bob_tok, &bob_acct).await;
    let (status, group) = post_json_auth(
        &instance_a,
        "/v1/groups",
        &alice_tok,
        json!({ "member_account_ids": [bob_acct] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{group}");
    let conv = group["conversation_id"].as_str().unwrap().to_string();

    // Give both listeners a moment to connect and LISTEN (startup, not steady-state).
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;

    // Bob parks a long-poll on INSTANCE B while alice sends through INSTANCE A.
    let poll = tokio::spawn({
        let instance_b = instance_b.clone();
        let bob_tok = bob_tok.clone();
        async move {
            let started = std::time::Instant::now();
            let (status, inbox) = get_auth(&instance_b, "/v1/inbox?wait=8", &bob_tok).await;
            (status, inbox, started.elapsed())
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await; // let the poll park
    let (status, sent) = post_json_auth(
        &instance_a,
        &format!("/v1/conversations/{conv}/messages"),
        &alice_tok,
        json!({ "ciphertext": hex::encode([9u8; 32]), "idempotency_key": hex::encode([4u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");

    let (status, inbox, elapsed) = poll.await.expect("poll task");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        inbox.as_array().map(|a| a.len()),
        Some(1),
        "the cross-instance wake delivered the envelope: {inbox}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "woken by the bus, not by the 8s timeout (took {elapsed:?})"
    );
}
