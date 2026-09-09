//! In-app account deletion (App Store requirement): a fully populated account is erased across
//! every store, its way back in is closed, and other people's data is left intact.
//!
//! The interesting assertions are the negative ones. Only `devices` and `profiles` cascade from
//! `accounts`, so a deletion that merely dropped the account row would appear to succeed while
//! orphaning tokens, the social graph, group membership, key packages, push tokens and queued
//! mail. This test therefore walks the account-bearing tables explicitly.

mod common;

use auth_core::transcript::Action;
use axum::http::StatusCode;
use common::{
    befriend, db_url, delete_json_auth, get_auth, http_register, make_app, post_json,
    post_json_auth, put_json_auth, sign_challenge, unique_username, PASSWORD,
};
use serde_json::json;

fn hex16(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

/// Count rows matching a single bytea parameter.
///
/// The sync `postgres` client hosts its own runtime, so it must be created on a blocking thread —
/// constructing it inside the async test panics.
async fn count_by(sql: &'static str, param: &[u8]) -> i64 {
    let param = param.to_vec();
    tokio::task::spawn_blocking(move || {
        let mut client = postgres::Client::connect(&db_url(), postgres::NoTls).expect("connect");
        client
            .query_one(sql, &[&param])
            .expect("count query")
            .get::<_, i64>(0)
    })
    .await
    .expect("db task")
}

#[tokio::test]
async fn deleting_an_account_erases_it_everywhere_and_spares_everyone_else() {
    let app = make_app(100_000).await;

    let (alice_device, alice) = http_register(&app, &unique_username("alicedel")).await;
    let (_bob_device, bob) = http_register(&app, &unique_username("bobdel")).await;
    let (_carol_device, carol) = http_register(&app, &unique_username("caroldel")).await;

    let alice_username = alice["username"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_default();
    let alice_token = alice["access_token"].as_str().unwrap().to_string();
    let bob_token = bob["access_token"].as_str().unwrap().to_string();
    let alice_account = hex16(alice["account_id"].as_str().unwrap());
    let alice_device_id = hex16(alice["device_id"].as_str().unwrap());
    let bob_account_hex = bob["account_id"].as_str().unwrap().to_string();
    let bob_device = hex16(bob["device_id"].as_str().unwrap());
    let carol_account_hex = carol["account_id"].as_str().unwrap().to_string();

    // ---- populate Alice across as many stores as the API exposes -------------------------
    let (status, body) = put_json_auth(
        &app,
        "/v1/profile",
        &alice_token,
        json!({"display_name": "Alice", "bio": "here briefly"}),
    )
    .await;
    assert!(status.is_success(), "profile PUT should succeed: {body}");

    befriend(
        &app,
        &alice_token,
        alice["account_id"].as_str().unwrap(),
        &bob_token,
        &bob_account_hex,
    )
    .await;

    let (status, _) = post_json_auth(
        &app,
        "/v1/blocks",
        &alice_token,
        json!({"account_id": carol_account_hex}),
    )
    .await;
    assert!(status.is_success(), "block endpoint responded {status}");

    let (status, _) = post_json_auth(
        &app,
        "/v1/reports",
        &alice_token,
        json!({"account_id": carol_account_hex, "reason": "spam"}),
    )
    .await;
    assert!(status.is_success(), "report endpoint responded {status}");

    let (status, _) = post_json_auth(
        &app,
        "/v1/push/register",
        &alice_token,
        json!({"platform": "apns", "token": "aa".repeat(32)}),
    )
    .await;
    assert!(status.is_success(), "push register responded {status}");

    // A conversation Alice and Bob share, plus mail in BOTH directions.
    let (status, conv) = post_json_auth(&app, "/v1/conversations", &alice_token, json!({})).await;
    assert_eq!(status, StatusCode::OK, "create conversation: {conv}");
    let conversation_id = conv["conversation_id"].as_str().unwrap().to_string();

    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/members"),
        &alice_token,
        json!({"account_id": bob_account_hex}),
    )
    .await;
    assert!(status.is_success(), "add bob to conversation: {status}");

    // Alice -> Bob. This must SURVIVE her deletion: erasing an account is not a retraction of
    // messages other people are already queued to receive.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/messages"),
        &alice_token,
        json!({"ciphertext": hex::encode(b"from alice"), "idempotency_key": "11".repeat(16)}),
    )
    .await;
    assert!(status.is_success(), "alice sends: {status}");

    // Bob -> Alice. This must be DELETED: with her devices gone nothing can decrypt it.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conversation_id}/messages"),
        &bob_token,
        json!({"ciphertext": hex::encode(b"from bob"), "idempotency_key": "22".repeat(16)}),
    )
    .await;
    assert!(status.is_success(), "bob sends: {status}");

    let to_bob_before = count_by(
        "SELECT count(*) FROM envelopes WHERE recipient_device = $1",
        &bob_device,
    )
    .await;
    assert!(to_bob_before > 0, "Bob should be holding Alice's message");

    // Prove the account really is populated first: otherwise "0 rows afterwards" would pass
    // trivially on a test that never created anything.
    for (table, sql) in [
        (
            "profiles",
            "SELECT count(*) FROM profiles WHERE account_id = $1",
        ),
        (
            "friendships",
            "SELECT count(*) FROM friendships WHERE account_lo = $1 OR account_hi = $1",
        ),
        (
            "blocks",
            "SELECT count(*) FROM blocks WHERE blocker = $1 OR blocked = $1",
        ),
        (
            "conversation_members",
            "SELECT count(*) FROM conversation_members WHERE account_id = $1",
        ),
        (
            "group_admins",
            "SELECT count(*) FROM group_admins WHERE account_id = $1",
        ),
        (
            "access_tokens",
            "SELECT count(*) FROM access_tokens WHERE account_id = $1",
        ),
        (
            "reports",
            "SELECT count(*) FROM reports WHERE reporter = $1",
        ),
    ] {
        assert!(
            count_by(sql, &alice_account).await > 0,
            "precondition: {table} should hold rows for Alice before deletion"
        );
    }
    assert!(
        count_by(
            "SELECT count(*) FROM device_push_tokens WHERE device_id = $1",
            &alice_device_id
        )
        .await
            > 0,
        "precondition: a push token should be registered before deletion"
    );

    // ---- delete ---------------------------------------------------------------------------
    let (status, challenge) =
        post_json_auth(&app, "/v1/account/delete/begin", &alice_token, json!({})).await;
    assert_eq!(status, StatusCode::OK, "delete challenge: {challenge}");
    let signature = sign_challenge(&alice_device, &challenge, Action::AccountDelete);

    // A wrong password must not destroy the account, even with a valid device signature.
    let (status, _) = delete_json_auth(
        &app,
        "/v1/account",
        &alice_token,
        json!({"txn_id": challenge["txn_id"], "signature": signature, "password": "not the password"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a wrong password must be refused"
    );
    assert_eq!(
        count_by(
            "SELECT count(*) FROM accounts WHERE account_id = $1",
            &alice_account
        )
        .await,
        1,
        "the refused attempt must not have deleted anything"
    );

    // That attempt consumed the challenge (single-use), so take a fresh one.
    let (status, challenge) =
        post_json_auth(&app, "/v1/account/delete/begin", &alice_token, json!({})).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "second delete challenge: {challenge}"
    );
    let signature = sign_challenge(&alice_device, &challenge, Action::AccountDelete);
    let (status, body) = delete_json_auth(
        &app,
        "/v1/account",
        &alice_token,
        json!({"txn_id": challenge["txn_id"], "signature": signature, "password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete failed: {body}");

    // ---- the way back in is closed --------------------------------------------------------
    let (status, _) = get_auth(&app, "/v1/session/whoami", &alice_token).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the access token must stop working"
    );

    // `/v1/login/begin` answers 200 even for accounts that do not exist — deliberate enumeration
    // resistance, and a deleted account MUST keep looking exactly like one that never existed,
    // otherwise deletion itself becomes an oracle. So the meaningful assertion is that the
    // ceremony cannot be completed: `login/finish` is where authentication actually happens.
    let (status, challenge) = post_json(
        &app,
        "/v1/login/begin",
        json!({"username": alice_username, "password": PASSWORD}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a deleted account must stay indistinguishable from a nonexistent one"
    );
    let signature = sign_challenge(&alice_device, &challenge, Action::Login);
    let (status, _) = post_json(
        &app,
        "/v1/login/finish",
        json!({"txn_id": challenge["txn_id"], "signature": signature}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "login must not complete for a deleted account"
    );

    // ---- not discoverable -----------------------------------------------------------------
    if !alice_username.is_empty() {
        let (status, results) = get_auth(
            &app,
            &format!("/v1/profiles/search?q={alice_username}"),
            &bob_token,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "search should still work for Bob");
        let hits = results["results"].as_array().cloned().unwrap_or_default();
        assert!(
            !hits
                .iter()
                .any(|r| r["username"].as_str() == Some(alice_username.as_str())),
            "a deleted account must not be searchable: {results}"
        );
    }

    // ---- every account-bearing table is clear ---------------------------------------------
    for (table, sql) in [
        (
            "accounts",
            "SELECT count(*) FROM accounts WHERE account_id = $1",
        ),
        (
            "devices",
            "SELECT count(*) FROM devices WHERE account_id = $1",
        ),
        (
            "profiles",
            "SELECT count(*) FROM profiles WHERE account_id = $1",
        ),
        (
            "access_tokens",
            "SELECT count(*) FROM access_tokens WHERE account_id = $1",
        ),
        (
            "refresh_families",
            "SELECT count(*) FROM refresh_families WHERE account_id = $1",
        ),
        (
            "challenges",
            "SELECT count(*) FROM challenges WHERE account_id = $1",
        ),
        (
            "key_packages",
            "SELECT count(*) FROM key_packages WHERE account_id = $1",
        ),
        (
            "delivery_access_keys",
            "SELECT count(*) FROM delivery_access_keys WHERE account_id = $1",
        ),
        (
            "self_group_members",
            "SELECT count(*) FROM self_group_members WHERE account_id = $1",
        ),
        (
            "conversation_members",
            "SELECT count(*) FROM conversation_members WHERE account_id = $1",
        ),
        (
            "group_admins",
            "SELECT count(*) FROM group_admins WHERE account_id = $1",
        ),
        (
            "group_join_requests",
            "SELECT count(*) FROM group_join_requests WHERE account_id = $1",
        ),
        (
            "group_invites",
            "SELECT count(*) FROM group_invites WHERE created_by = $1",
        ),
        (
            "friendships",
            "SELECT count(*) FROM friendships WHERE account_lo = $1 OR account_hi = $1",
        ),
        (
            "friend_requests",
            "SELECT count(*) FROM friend_requests WHERE from_account = $1 OR to_account = $1",
        ),
        (
            "blocks",
            "SELECT count(*) FROM blocks WHERE blocker = $1 OR blocked = $1",
        ),
    ] {
        assert_eq!(
            count_by(sql, &alice_account).await,
            0,
            "{table} still holds rows for the deleted account"
        );
    }

    for (table, sql) in [
        (
            "device_push_tokens",
            "SELECT count(*) FROM device_push_tokens WHERE device_id = $1",
        ),
        (
            "app_attest_keys",
            "SELECT count(*) FROM app_attest_keys WHERE device_id = $1",
        ),
        (
            "app_attest_challenges",
            "SELECT count(*) FROM app_attest_challenges WHERE device_id = $1",
        ),
        (
            "self_group_members(device)",
            "SELECT count(*) FROM self_group_members WHERE device_id = $1",
        ),
        (
            "envelopes(to alice)",
            "SELECT count(*) FROM envelopes WHERE recipient_device = $1",
        ),
        (
            "sealed_envelopes",
            "SELECT count(*) FROM sealed_envelopes WHERE recipient_device = $1",
        ),
    ] {
        assert_eq!(
            count_by(sql, &alice_device_id).await,
            0,
            "{table} still holds rows for the deleted account's device"
        );
    }

    // ---- abuse history is retained, but anonymized ----------------------------------------
    assert_eq!(
        count_by(
            "SELECT count(*) FROM reports WHERE reporter = $1 OR reported = $1",
            &alice_account
        )
        .await,
        0,
        "reports must no longer identify the deleted account"
    );

    // ---- other people are untouched --------------------------------------------------------
    assert_eq!(
        count_by(
            "SELECT count(*) FROM envelopes WHERE recipient_device = $1",
            &bob_device
        )
        .await,
        to_bob_before,
        "Bob's queued mail from Alice must survive: deleting an account is not a retraction"
    );
    assert_eq!(
        count_by(
            "SELECT count(*) FROM accounts WHERE account_id = $1",
            &hex16(&bob_account_hex)
        )
        .await,
        1,
        "Bob's account must be untouched"
    );
    assert_eq!(
        count_by(
            "SELECT count(*) FROM conversation_members WHERE account_id = $1",
            &hex16(&bob_account_hex)
        )
        .await,
        1,
        "Bob keeps his membership; the shared conversation still has a member, so it survives"
    );
    let (status, _) = get_auth(&app, "/v1/session/whoami", &bob_token).await;
    assert_eq!(status, StatusCode::OK, "Bob's session must still work");
}
