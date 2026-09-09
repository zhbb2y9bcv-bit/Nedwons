//! Group moderation (ADR-0009 third slice) end to end over the real HTTP API + PostgreSQL:
//! per-member mutes, announcement mode ("mute all"), admin-only enforcement, and the invariants
//! `V25__group_moderation.sql` puts in the schema.
//!
//! What these tests are actually proving, stated precisely: that the RELAY refuses to distribute a
//! muted member's ciphertext on every path that accepts ciphertext for a conversation. They prove
//! nothing about cryptography — a muted member still holds the group's MLS keys — and the point of
//! testing the targeted (`/welcome`) path alongside fan-out is that a gate on only one of them
//! would be bypassable by anyone willing to modify their client, which is exactly who gets muted.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use axum::http::StatusCode;
use common::{
    befriend, db_url, get_auth, http_register, make_app, post_json_auth, unique_username,
};
use serde_json::{json, Value};

/// Register a user; returns (token, account_id, device_id).
async fn user(app: &axum::Router, prefix: &str) -> (String, String, String) {
    let (_d, u) = http_register(app, &unique_username(prefix)).await;
    (
        u["access_token"].as_str().unwrap().to_string(),
        u["account_id"].as_str().unwrap().to_string(),
        u["device_id"].as_str().unwrap().to_string(),
    )
}

/// A group of creator + one befriended member. The creator is its first admin.
async fn group_of_two(
    app: &axum::Router,
    creator: &(String, String, String),
    member: &(String, String, String),
) -> String {
    befriend(app, &creator.0, &creator.1, &member.0, &member.1).await;
    let (status, group) = post_json_auth(
        app,
        "/v1/groups",
        &creator.0,
        json!({ "member_account_ids": [member.1] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "group create: {group}");
    group["conversation_id"].as_str().unwrap().to_string()
}

/// Send one application message. `key` disambiguates the idempotency key per call.
async fn send(app: &axum::Router, conv: &str, token: &str, key: u8) -> (StatusCode, Value) {
    post_json_auth(
        app,
        &format!("/v1/conversations/{conv}/messages"),
        token,
        json!({
            "ciphertext": hex::encode(format!("msg-{key}")),
            "idempotency_key": hex::encode([key; 16]),
        }),
    )
    .await
}

/// Send a targeted envelope (the `/welcome` path) to a specific member device.
async fn send_welcome(
    app: &axum::Router,
    conv: &str,
    token: &str,
    recipient_device: &str,
    key: u8,
) -> (StatusCode, Value) {
    post_json_auth(
        app,
        &format!("/v1/conversations/{conv}/welcome"),
        token,
        json!({
            "recipient_device": recipient_device,
            "ciphertext": hex::encode(format!("welcome-{key}")),
            "idempotency_key": hex::encode([key; 16]),
        }),
    )
    .await
}

async fn group_state(app: &axum::Router, conv: &str, token: &str) -> (StatusCode, Value) {
    get_auth(app, &format!("/v1/conversations/{conv}/group"), token).await
}

fn member_view<'a>(state: &'a Value, account_id: &str) -> &'a Value {
    state["members"]
        .as_array()
        .expect("members array")
        .iter()
        .find(|m| m["account_id"] == account_id)
        .expect("member present")
}

/// The core loop an admin actually performs: mute a member, watch every send path refuse them,
/// unmute, watch it resume. The refusal is specific (`muted`) rather than the generic 403, so the
/// muted member's own client can say something true.
#[tokio::test]
async fn mute_blocks_every_send_path_until_lifted() {
    let app = make_app(100_000).await;
    let alice = user(&app, "muta").await;
    let bob = user(&app, "mutb").await;
    let conv = group_of_two(&app, &alice, &bob).await;

    let (status, _) = send(&app, &conv, &bob.0, 1).await;
    assert_eq!(status, StatusCode::OK, "an unmuted member can send");

    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/mutes"),
        &alice.0,
        json!({ "account_id": bob.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "admin mutes a member");

    let (status, body) = send(&app, &conv, &bob.0, 2).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "muted member cannot fan out");
    assert_eq!(
        body["error"], "muted",
        "the reason is specific, not generic"
    );

    // The targeted path is the bypass a gate on fan-out alone would leave open.
    let (status, body) = send_welcome(&app, &conv, &bob.0, &alice.2, 3).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "muted member cannot send targeted envelopes either: {body}"
    );
    assert_eq!(body["error"], "muted");

    // Admins are unaffected by someone else's mute.
    let (status, _) = send(&app, &conv, &alice.0, 4).await;
    assert_eq!(status, StatusCode::OK, "the admin still speaks");

    // Both members see the mute — moderation is legible to the people subject to it.
    for (token, label) in [(&alice.0, "admin"), (&bob.0, "muted member")] {
        let (status, state) = group_state(&app, &conv, token).await;
        assert_eq!(status, StatusCode::OK, "{label} reads group state");
        assert_eq!(member_view(&state, &bob.1)["muted"], true, "{label} view");
    }
    let (_, bob_state) = group_state(&app, &conv, &bob.0).await;
    assert_eq!(bob_state["can_send"], false, "the muted member is told so");
    assert_eq!(bob_state["is_admin"], false);
    let (_, alice_state) = group_state(&app, &conv, &alice.0).await;
    assert_eq!(alice_state["can_send"], true);

    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/mutes/remove"),
        &alice.0,
        json!({ "account_id": bob.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(&app, &conv, &bob.0, 5).await;
    assert_eq!(status, StatusCode::OK, "unmute restores sending");
    // Idempotent: unmuting an unmuted member is a no-op, so a retry after a lost response is safe.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/mutes/remove"),
        &alice.0,
        json!({ "account_id": bob.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// "Mute all": only admins may speak. The switch is group-level, so lifting it restores everyone
/// at once without touching per-member state.
#[tokio::test]
async fn announcement_mode_leaves_only_admins_speaking() {
    let app = make_app(100_000).await;
    let alice = user(&app, "anna").await;
    let bob = user(&app, "annb").await;
    let conv = group_of_two(&app, &alice, &bob).await;

    // Approval-gating first, so the partial update below can be shown not to clobber it.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/settings"),
        &alice.0,
        json!({ "join_approval": true }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/settings"),
        &alice.0,
        json!({ "announcements_only": true }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, state) = group_state(&app, &conv, &alice.0).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state["announcements_only"], true);
    assert_eq!(
        state["join_approval"], true,
        "setting one switch must not silently revert the other"
    );

    let (status, body) = send(&app, &conv, &bob.0, 10).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body["error"], "announcements_only",
        "distinct from an individual mute: different feedback, different remedy"
    );
    let (status, body) = send_welcome(&app, &conv, &bob.0, &alice.2, 11).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "targeted path too: {body}");

    let (status, _) = send(&app, &conv, &alice.0, 12).await;
    assert_eq!(status, StatusCode::OK, "admins are exempt");

    let (_, bob_state) = group_state(&app, &conv, &bob.0).await;
    assert_eq!(bob_state["can_send"], false);
    assert_eq!(
        bob_state["muted"],
        Value::Null,
        "announcement mode is not an individual mute"
    );

    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/settings"),
        &alice.0,
        json!({ "announcements_only": false }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(&app, &conv, &bob.0, 13).await;
    assert_eq!(status, StatusCode::OK, "lifting it restores everyone");
}

/// Every moderation control is admin-only, and a non-member learns nothing at all.
#[tokio::test]
async fn moderation_is_admin_only() {
    let app = make_app(100_000).await;
    let alice = user(&app, "aoa").await;
    let bob = user(&app, "aob").await;
    let carol = user(&app, "aoc").await;
    let conv = group_of_two(&app, &alice, &bob).await;

    for (path, body) in [
        (
            format!("/v1/conversations/{conv}/mutes"),
            json!({ "account_id": alice.1 }),
        ),
        (
            format!("/v1/conversations/{conv}/mutes/remove"),
            json!({ "account_id": alice.1 }),
        ),
        (format!("/v1/conversations/{conv}/mutes/clear"), json!({})),
        (
            format!("/v1/conversations/{conv}/settings"),
            json!({ "announcements_only": true }),
        ),
    ] {
        let (status, _) = post_json_auth(&app, &path, &bob.0, body.clone()).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "member cannot moderate: {path}"
        );
        let (status, _) = post_json_auth(&app, &path, &carol.0, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "stranger cannot moderate: {path}"
        );
    }

    // A stranger cannot even read the panel: it would disclose the group's membership.
    let (status, _) = group_state(&app, &conv, &carol.0).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // An ordinary member reads it, minus the admin-only lists.
    let (status, state) = group_state(&app, &conv, &bob.0).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state["is_admin"], false);
    assert_eq!(state["invites"].as_array().unwrap().len(), 0);
    assert_eq!(state["join_requests"].as_array().unwrap().len(), 0);
    assert_eq!(state["members"].as_array().unwrap().len(), 2);

    // Muting yourself is refused rather than honoured: with one admin it would lock the group's
    // own moderation out of its only voice.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/mutes"),
        &alice.0,
        json!({ "account_id": alice.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// The role/mute invariant, from both directions: an admin cannot be muted, and promoting a muted
/// member lifts the mute rather than leaving two tables asserting contradictory things.
#[tokio::test]
async fn admins_are_never_muted() {
    let app = make_app(100_000).await;
    let alice = user(&app, "adma").await;
    let bob = user(&app, "admb").await;
    let conv = group_of_two(&app, &alice, &bob).await;

    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/mutes"),
        &alice.0,
        json!({ "account_id": bob.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Promotion lifts it (schema trigger, so no code path can forget).
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/admins"),
        &alice.0,
        json!({ "account_id": bob.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, state) = group_state(&app, &conv, &alice.0).await;
    let bob_view = member_view(&state, &bob.1);
    assert_eq!(bob_view["is_admin"], true);
    assert_eq!(bob_view["muted"], false, "promotion lifted the mute");
    let (status, _) = send(&app, &conv, &bob.0, 20).await;
    assert_eq!(status, StatusCode::OK, "the promoted member speaks again");

    // And an admin cannot be muted at all: demote first, deliberately.
    let (status, body) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/mutes"),
        &alice.0,
        json!({ "account_id": bob.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "target_is_admin");

    // Muting a non-member is refused too, so a stale row can never wait to apply to a rejoin.
    let carol = user(&app, "admc").await;
    let (status, body) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/mutes"),
        &alice.0,
        json!({ "account_id": carol.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "not_member");
}

/// Removal ("kick") is the existing admin exit path; this pins the parts moderation adds to it —
/// the removed member's mute row goes with them, so an invite-driven rejoin does not silently land
/// them muted by a decision made about a previous membership.
#[tokio::test]
async fn removing_a_muted_member_clears_their_mute() {
    let app = make_app(100_000).await;
    let alice = user(&app, "kicka").await;
    let bob = user(&app, "kickb").await;
    let conv = group_of_two(&app, &alice, &bob).await;

    post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/mutes"),
        &alice.0,
        json!({ "account_id": bob.1, "duration_secs": 3600 }),
    )
    .await;
    assert_eq!(mute_rows(&conv), 1);

    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/members/remove"),
        &alice.0,
        json!({ "account_id": bob.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "admin removes a member");

    assert_eq!(mute_rows(&conv), 0, "the mute left with the membership");
    let (status, _) = send(&app, &conv, &bob.0, 30).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a removed member is refused as a non-member"
    );
    let (status, _) = group_state(&app, &conv, &bob.0).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A timed mute lapses on its own: no sweeper runs, so the send gate and the panel must agree that
/// an elapsed `expires_at` means unmuted. Set the expiry into the past directly rather than
/// sleeping through it.
#[tokio::test]
async fn a_timed_mute_lapses_without_anyone_lifting_it() {
    let app = make_app(100_000).await;
    let alice = user(&app, "expa").await;
    let bob = user(&app, "expb").await;
    let conv = group_of_two(&app, &alice, &bob).await;

    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/mutes"),
        &alice.0,
        json!({ "account_id": bob.1, "duration_secs": 3600 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(&app, &conv, &bob.0, 40).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "timed mute is in force");
    let (_, state) = group_state(&app, &conv, &alice.0).await;
    let view = member_view(&state, &bob.1);
    assert_eq!(view["muted"], true);
    assert!(
        view["mute_expires_at"].as_i64().is_some(),
        "a timed mute reports when it ends"
    );

    expire_mutes(&conv);

    let (status, _) = send(&app, &conv, &bob.0, 41).await;
    assert_eq!(status, StatusCode::OK, "an elapsed mute stops applying");
    let (_, state) = group_state(&app, &conv, &alice.0).await;
    assert_eq!(
        member_view(&state, &bob.1)["muted"],
        false,
        "the panel never shows a mute the gate no longer enforces"
    );
}

/// An indefinite mute reports no expiry at all, rather than a distant one a client could mistake
/// for a countdown; and "unmute everyone" clears the group in one call.
#[tokio::test]
async fn indefinite_mutes_and_bulk_unmute() {
    let app = make_app(100_000).await;
    let alice = user(&app, "bulka").await;
    let bob = user(&app, "bulkb").await;
    let carol = user(&app, "bulkc").await;
    let conv = group_of_two(&app, &alice, &bob).await;
    befriend(&app, &alice.0, &alice.1, &carol.0, &carol.1).await;
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/members"),
        &alice.0,
        json!({ "account_id": carol.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "admin adds a friend");

    for target in [&bob.1, &carol.1] {
        let (status, _) = post_json_auth(
            &app,
            &format!("/v1/conversations/{conv}/mutes"),
            &alice.0,
            json!({ "account_id": target }),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    let (_, state) = group_state(&app, &conv, &alice.0).await;
    assert_eq!(state["members"].as_array().unwrap().len(), 3);
    let bob_view = member_view(&state, &bob.1);
    assert_eq!(bob_view["muted"], true);
    assert_eq!(
        bob_view["mute_expires_at"],
        Value::Null,
        "an indefinite mute carries no expiry field"
    );
    assert_eq!(bob_view["muted_by"], alice.1, "the panel says who did it");

    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/mutes/clear"),
        &alice.0,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(mute_rows(&conv), 0);
    for member in [&bob, &carol] {
        let (status, _) = send(&app, &conv, &member.0, 50).await;
        assert_eq!(status, StatusCode::OK, "everyone speaks again");
    }
}

/// Concurrency, in the style `pg_invariants.rs` established for the other governance races: mute
/// and promote target the same person from two connections at once.
///
/// Both writes are guarded by the schema (a muted admin is rejected on the way in and cleared on
/// promotion), but the schema's remedy is an exception — a 500 where the honest answer is a 409.
/// The conversation advisory lock is what turns the race into an ordering, so the invariant holds
/// AND every call returns a real answer.
#[tokio::test]
async fn mute_racing_promotion_never_leaves_a_muted_admin() {
    const ROUNDS: usize = 12;
    let app = make_app(100_000).await;
    let alice = user(&app, "raca").await;
    let bob = user(&app, "racb").await;
    let conv = group_of_two(&app, &alice, &bob).await;

    let conv_id: [u8; 16] = hex::decode(&conv).unwrap().try_into().unwrap();
    let alice_account =
        auth_core::ids::AccountId(hex::decode(&alice.1).unwrap().try_into().unwrap());
    let bob_account = auth_core::ids::AccountId(hex::decode(&bob.1).unwrap().try_into().unwrap());
    let errors = Arc::new(AtomicUsize::new(0));

    // The store is the sync `postgres` client, so every call — including the per-round resets —
    // must run off the tokio thread, exactly as the API's `blocking_store` does.
    let errors_in = errors.clone();
    tokio::task::spawn_blocking(move || {
        let groups = common::shared_groups();
        for _ in 0..ROUNDS {
            let barrier = Arc::new(Barrier::new(2));
            let handles = [
                {
                    let (groups, errors, barrier) =
                        (groups.clone(), errors_in.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        barrier.wait();
                        if groups
                            .mute_member(&conv_id, &bob_account, &alice_account, None)
                            .is_err()
                        {
                            errors.fetch_add(1, Ordering::SeqCst);
                        }
                    })
                },
                {
                    let (groups, errors, barrier) =
                        (groups.clone(), errors_in.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        barrier.wait();
                        if groups.promote(&conv_id, &bob_account).is_err() {
                            errors.fetch_add(1, Ordering::SeqCst);
                        }
                    })
                },
            ];
            for h in handles {
                h.join().expect("thread");
            }
            // Reset for the next round.
            groups.demote(&conv_id, &bob_account).expect("demote");
            groups
                .unmute_member(&conv_id, &bob_account)
                .expect("unmute");
        }
    })
    .await
    .expect("race task");

    assert_eq!(
        errors.load(Ordering::SeqCst),
        0,
        "no racer hit a trigger exception; the lock ordered them"
    );
    assert_eq!(
        muted_admins(),
        0,
        "no account is simultaneously an admin and muted"
    );
}

/// Direct SQL for assertions the API deliberately does not expose. Runs on its own OS thread: the
/// sync `postgres` client hosts a runtime and its `Drop` calls `block_on`, which panics if it
/// happens inside a `#[tokio::test]` — the same trap `common::shared_stores` documents.
fn with_db<T: Send + 'static>(f: impl FnOnce(&mut postgres::Client) -> T + Send + 'static) -> T {
    std::thread::spawn(move || {
        let mut client = postgres::Client::connect(&db_url(), postgres::NoTls).expect("db connect");
        f(&mut client)
    })
    .join()
    .expect("db thread")
}

fn expire_mutes(conversation_hex: &str) {
    let conversation = hex::decode(conversation_hex).unwrap();
    with_db(move |db| {
        db.execute(
            "UPDATE group_mutes SET expires_at = now() - interval '1 second'
              WHERE conversation_id = $1",
            &[&conversation],
        )
        .expect("expire the mute");
    })
}

fn mute_rows(conversation_hex: &str) -> i64 {
    let conversation = hex::decode(conversation_hex).unwrap();
    with_db(move |db| {
        db.query_one(
            "SELECT count(*) FROM group_mutes WHERE conversation_id = $1",
            &[&conversation],
        )
        .expect("count mutes")
        .get(0)
    })
}

/// Repo-wide, not just this test's group: the invariant is a property of the schema.
fn muted_admins() -> i64 {
    with_db(|db| {
        db.query_one(
            "SELECT count(*) FROM group_mutes m
              JOIN group_admins a ON a.conversation_id = m.conversation_id
                                 AND a.account_id = m.account_id",
            &[],
        )
        .expect("count muted admins")
        .get(0)
    })
}
