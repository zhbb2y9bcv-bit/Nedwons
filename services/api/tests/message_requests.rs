//! Message requests end to end over the real HTTP API + PostgreSQL: a NON-friend may open one
//! quarantined conversation with you; you accept (and become friends), or decline (and optionally
//! block). The conversation itself is ordinary MLS — this only governs the friend-gate and the
//! Requests folder, never message content.

mod common;

use axum::http::StatusCode;
use common::{befriend, get_auth, http_register, make_app, post_json_auth, unique_username};
use serde_json::json;

/// (access_token, account_id) for a freshly registered account.
async fn account(app: &axum::Router, prefix: &str) -> (String, String) {
    let (_d, u) = http_register(app, &unique_username(prefix)).await;
    (
        u["access_token"].as_str().unwrap().to_string(),
        u["account_id"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn request_lands_in_the_recipients_folder_then_accept_makes_friends() {
    let app = make_app(100_000).await;
    let (a_tok, a_acct) = account(&app, "mra").await;
    let (b_tok, b_acct) = account(&app, "mrb").await;

    // A (a stranger to B) opens a request.
    let (status, req) = post_json_auth(
        &app,
        "/v1/message-requests",
        &a_tok,
        json!({ "account_id": b_acct }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{req}");
    let conversation_id = req["conversation_id"].as_str().unwrap().to_string();

    // It appears in B's Requests folder, naming A — and NOT in A's own folder.
    let (status, mine) = get_auth(&app, "/v1/message-requests", &b_tok).await;
    assert_eq!(status, StatusCode::OK);
    let list = mine.as_array().unwrap();
    assert_eq!(list.len(), 1, "one pending request: {mine}");
    assert_eq!(
        list[0]["conversation_id"].as_str().unwrap(),
        conversation_id
    );
    assert_eq!(list[0]["from"]["account_id"].as_str().unwrap(), a_acct);

    let (status, senders) = get_auth(&app, "/v1/message-requests", &a_tok).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        senders.as_array().unwrap().len(),
        0,
        "the sender sees no incoming request"
    );

    // A cannot pile on a second request to the same person.
    let (status, _) = post_json_auth(
        &app,
        "/v1/message-requests",
        &a_tok,
        json!({ "account_id": b_acct }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "one outstanding request per pair"
    );

    // B accepts: the folder empties and the two are now friends.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/message-requests/{conversation_id}/accept"),
        &b_tok,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_status, mine) = get_auth(&app, "/v1/message-requests", &b_tok).await;
    assert_eq!(
        mine.as_array().unwrap().len(),
        0,
        "accepted request leaves the folder"
    );

    let (_status, friends) = get_auth(&app, "/v1/friends", &b_tok).await;
    assert!(
        friends
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["account_id"] == a_acct),
        "accepting befriends the sender: {friends}"
    );

    // And a fresh request is now refused — they are friends, so the ordinary flow applies.
    let (status, _) = post_json_auth(
        &app,
        "/v1/message-requests",
        &a_tok,
        json!({ "account_id": b_acct }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "already friends");
}

#[tokio::test]
async fn decline_with_block_stops_further_requests() {
    let app = make_app(100_000).await;
    let (a_tok, _a_acct) = account(&app, "mrc").await;
    let (b_tok, b_acct) = account(&app, "mrd").await;

    let (status, req) = post_json_auth(
        &app,
        "/v1/message-requests",
        &a_tok,
        json!({ "account_id": b_acct }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{req}");
    let conversation_id = req["conversation_id"].as_str().unwrap().to_string();

    // B declines AND blocks.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/message-requests/{conversation_id}/decline"),
        &b_tok,
        json!({ "block": true }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The folder is empty, and A can no longer reach B at all.
    let (_status, mine) = get_auth(&app, "/v1/message-requests", &b_tok).await;
    assert_eq!(mine.as_array().unwrap().len(), 0);

    let (status, _) = post_json_auth(
        &app,
        "/v1/message-requests",
        &a_tok,
        json!({ "account_id": b_acct }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a blocked sender cannot request again"
    );
}

#[tokio::test]
async fn requesting_a_friend_or_yourself_is_refused() {
    let app = make_app(100_000).await;
    let (a_tok, a_acct) = account(&app, "mre").await;
    let (b_tok, b_acct) = account(&app, "mrf").await;

    // Yourself: a request to your own account is nonsense.
    let (status, _) = post_json_auth(
        &app,
        "/v1/message-requests",
        &a_tok,
        json!({ "account_id": a_acct }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // An existing friend goes through the ordinary conversation flow, not a request.
    befriend(&app, &a_tok, &a_acct, &b_tok, &b_acct).await;
    let (status, _) = post_json_auth(
        &app,
        "/v1/message-requests",
        &a_tok,
        json!({ "account_id": b_acct }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "already friends");
}

#[tokio::test]
async fn accepting_a_nonexistent_request_is_not_found() {
    let app = make_app(100_000).await;
    let (_a_tok, _a) = account(&app, "mrg").await;
    let (b_tok, _b) = account(&app, "mrh").await;
    let bogus = "aa".repeat(16);
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/message-requests/{bogus}/accept"),
        &b_tok,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
