//! Profiles, friendship graph, and clique-gated group creation, end to end over the real
//! HTTP API + PostgreSQL.

mod common;

use axum::http::StatusCode;
use common::{get_auth, http_register, make_app, post_json_auth, unique_username};
use serde_json::json;

async fn put_auth(
    app: &axum::Router,
    path: &str,
    token: &str,
    body: serde_json::Value,
) -> StatusCode {
    use axum::body::Body;
    use axum::http::{header, Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let resp = app
        .clone()
        .oneshot(
            Request::put(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let _ = resp.into_body().collect().await;
    status
}

#[tokio::test]
async fn profile_update_get_and_search() {
    let app = make_app(100_000).await;
    let uname = unique_username("prof");
    let (_d, me) = http_register(&app, &uname).await;
    let token = me["access_token"].as_str().unwrap();

    // Default profile exists with empty display name.
    let (status, profile) = get_auth(&app, "/v1/profile", token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(profile["username"], uname);
    assert_eq!(profile["display_name"], "");

    // Update it.
    let status = put_auth(
        &app,
        "/v1/profile",
        token,
        json!({ "display_name": "Ada L.", "bio": "cryptographer" }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, profile) = get_auth(&app, "/v1/profile", token).await;
    assert_eq!(profile["display_name"], "Ada L.");
    assert_eq!(profile["bio"], "cryptographer");

    // Search by username prefix finds it.
    let (status, results) = get_auth(
        &app,
        &format!("/v1/profiles/search?q={}", &uname[..5]),
        token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let found = results
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["username"] == uname);
    assert!(found, "search should find the user by username prefix");

    // Too-short search query is rejected.
    let (status, _) = get_auth(&app, "/v1/profiles/search?q=a", token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn friend_request_accept_flow() {
    let app = make_app(100_000).await;
    let (_da, alice) = http_register(&app, &unique_username("frienda")).await;
    let (_db, bob) = http_register(&app, &unique_username("friendb")).await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    let alice_acct = alice["account_id"].as_str().unwrap();
    let bob_acct = bob["account_id"].as_str().unwrap();

    // Alice requests Bob.
    let (status, res) = post_json_auth(
        &app,
        "/v1/friends/request",
        alice_token,
        json!({ "account_id": bob_acct }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(res["status"], "requested");

    // Bob sees the incoming request.
    let (_, reqs) = get_auth(&app, "/v1/friends/requests", bob_token).await;
    assert!(reqs
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["account_id"] == alice_acct));

    // Bob accepts.
    let (status, _) = post_json_auth(
        &app,
        "/v1/friends/accept",
        bob_token,
        json!({ "account_id": alice_acct }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Both now list each other as friends.
    let (_, alice_friends) = get_auth(&app, "/v1/friends", alice_token).await;
    let (_, bob_friends) = get_auth(&app, "/v1/friends", bob_token).await;
    assert!(alice_friends
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["account_id"] == bob_acct));
    assert!(bob_friends
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["account_id"] == alice_acct));

    // Cannot friend self.
    let (status, _) = post_json_auth(
        &app,
        "/v1/friends/request",
        alice_token,
        json!({ "account_id": alice_acct }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn mutual_requests_auto_accept() {
    let app = make_app(100_000).await;
    let (_da, alice) = http_register(&app, &unique_username("muta")).await;
    let (_db, bob) = http_register(&app, &unique_username("mutb")).await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    let alice_acct = alice["account_id"].as_str().unwrap();
    let bob_acct = bob["account_id"].as_str().unwrap();

    let (_, r1) = post_json_auth(
        &app,
        "/v1/friends/request",
        alice_token,
        json!({ "account_id": bob_acct }),
    )
    .await;
    assert_eq!(r1["status"], "requested");
    // Bob independently requests Alice — they already both want it → auto-friend.
    let (_, r2) = post_json_auth(
        &app,
        "/v1/friends/request",
        bob_token,
        json!({ "account_id": alice_acct }),
    )
    .await;
    assert_eq!(r2["status"], "friended");

    let (_, bob_friends) = get_auth(&app, "/v1/friends", bob_token).await;
    assert!(bob_friends
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["account_id"] == alice_acct));
}

/// Helper: register N users and make them ALL mutually friends (a clique). Returns their
/// (token, account_id).
async fn make_clique(app: &axum::Router, n: usize, prefix: &str) -> Vec<(String, String)> {
    let mut users = Vec::new();
    for i in 0..n {
        let (_d, u) = http_register(app, &unique_username(&format!("{prefix}{i}"))).await;
        users.push((
            u["access_token"].as_str().unwrap().to_string(),
            u["account_id"].as_str().unwrap().to_string(),
        ));
    }
    // Every pair befriends (i requests j, j accepts).
    for i in 0..n {
        for j in (i + 1)..n {
            let (status, _) = post_json_auth(
                app,
                "/v1/friends/request",
                &users[i].0,
                json!({ "account_id": users[j].1 }),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let (status, _) = post_json_auth(
                app,
                "/v1/friends/accept",
                &users[j].0,
                json!({ "account_id": users[i].1 }),
            )
            .await;
            assert_eq!(status, StatusCode::NO_CONTENT);
        }
    }
    users
}

/// A group of mutually-friended people can be created and its messages reach everyone.
#[tokio::test]
async fn group_of_all_friends_is_allowed_and_reaches_everyone() {
    let app = make_app(100_000).await;
    let clique = make_clique(&app, 4, "grp").await;
    let creator_token = &clique[0].0;
    let member_ids: Vec<&str> = clique[1..].iter().map(|(_, id)| id.as_str()).collect();

    let (status, group) = post_json_auth(
        &app,
        "/v1/groups",
        creator_token,
        json!({ "member_account_ids": member_ids }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "clique group allowed: {group}");
    let conversation_id = group["conversation_id"].as_str().unwrap().to_string();

    // Creator sends one message; it fans out to every other member (3 others).
    let (status, receipt) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/messages"),
        creator_token,
        json!({ "ciphertext": hex::encode(b"group hello"), "idempotency_key": hex::encode([3u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        receipt["delivered"],
        member_ids.len(),
        "reached every member"
    );

    // Each other member sees the message in their inbox.
    for (token, _) in &clique[1..] {
        let (_, inbox) = get_auth(&app, "/v1/inbox", token).await;
        assert_eq!(
            inbox.as_array().unwrap().len(),
            1,
            "member received the group message"
        );
    }

    // The group appears in every member's conversation list (Chats tab), with all members.
    for (token, _) in &clique {
        let (status, convos) = get_auth(&app, "/v1/conversations", token).await;
        assert_eq!(status, StatusCode::OK);
        let group = convos
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["conversation_id"] == conversation_id.as_str())
            .expect("group present in the member's conversation list");
        assert_eq!(
            group["member_account_ids"].as_array().unwrap().len(),
            clique.len(),
            "conversation lists all members"
        );
    }
}

/// A group is REJECTED if not every pair is mutually friends.
#[tokio::test]
async fn group_requires_all_pairs_to_be_friends() {
    let app = make_app(100_000).await;
    // Make a clique of 3, then add a 4th who is friends with only ONE of them.
    let mut clique = make_clique(&app, 3, "part").await;
    let (_d, outsider) = http_register(&app, &unique_username("outsider")).await;
    let outsider_token = outsider["access_token"].as_str().unwrap().to_string();
    let outsider_acct = outsider["account_id"].as_str().unwrap().to_string();

    // Outsider befriends only clique[0], not the others.
    let (status, _) = post_json_auth(
        &app,
        "/v1/friends/request",
        &clique[0].0,
        json!({ "account_id": outsider_acct }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = post_json_auth(
        &app,
        "/v1/friends/accept",
        &outsider_token,
        json!({ "account_id": clique[0].1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    clique.push((outsider_token, outsider_acct));
    let creator_token = &clique[0].0;
    let member_ids: Vec<&str> = clique[1..].iter().map(|(_, id)| id.as_str()).collect();

    // The group includes the outsider, who is not friends with everyone → 403.
    let (status, body) = post_json_auth(
        &app,
        "/v1/groups",
        creator_token,
        json!({ "member_account_ids": member_ids }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "not all friends: {body}");
    assert_eq!(body["error"], "not_all_friends");
}
