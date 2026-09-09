//! Attachments end to end over the real HTTP API + PostgreSQL + a real blob directory.
//!
//! What these prove is deliberately narrow, because it is all the relay does: it stores bytes it
//! cannot read, serves them back to the conversation's current members, and refuses everyone else.
//! The bytes ARE ciphertext produced by `mls_core::attachment` here, so the test also demonstrates
//! the thing the design rests on — the server holds an object it has no key for, and the recipient
//! opens it with a key that only ever travelled inside an MLS message.

mod common;

use axum::http::StatusCode;
use common::{
    befriend, db_url, http_register, make_app_with_blobs, post_json_auth, unique_username,
};
use serde_json::json;

/// Register a user; returns (token, account_id, device_id).
async fn user(app: &axum::Router, prefix: &str) -> (String, String, String) {
    let (_d, u) = http_register(app, &unique_username(prefix)).await;
    (
        u["access_token"].as_str().unwrap().to_string(),
        u["account_id"].as_str().unwrap().to_string(),
        u["device_id"].as_str().unwrap().to_string(),
    )
}

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

/// A scratch blob directory of this test's own, handed directly to the router — never through the
/// environment, which is process-global and would race between parallel tests.
fn blob_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("nedwons-test-blobs-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("blob dir");
    dir
}

async fn upload(
    app: &axum::Router,
    conversation: &str,
    token: &str,
    bytes: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/conversations/{conversation}/attachments"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/octet-stream")
        .body(axum::body::Body::from(bytes))
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn download(app: &axum::Router, blob_id: &str, token: &str) -> (StatusCode, Vec<u8>) {
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/v1/attachments/{blob_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .body(axum::body::Body::empty())
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, body.to_vec())
}

/// The whole point, in one test: the file the sender encrypts is not what the server stores, a
/// member downloads the ciphertext and opens it with the key that came over MLS, and the server's
/// own copy is unreadable to it.
#[tokio::test]
async fn a_member_fetches_ciphertext_the_server_cannot_read() {
    let dir = blob_dir("roundtrip");
    let app = make_app_with_blobs(100_000, dir.clone()).await;
    let alice = user(&app, "atta").await;
    let bob = user(&app, "attb").await;
    let conv = group_of_two(&app, &alice, &bob).await;

    let file = b"the actual photo bytes, pretend".repeat(64);
    let sealed = mls_core::attachment::seal(&file).expect("seal");
    let (status, body) = upload(&app, &conv, &alice.0, sealed.ciphertext.clone()).await;
    assert_eq!(status, StatusCode::OK, "upload: {body}");
    let blob_id = body["blob_id"].as_str().expect("blob id").to_string();

    // What landed on disk is the ciphertext — not the file.
    let stored = std::fs::read(dir.join(&blob_id)).expect("blob on disk");
    assert_eq!(stored, sealed.ciphertext);
    assert!(
        !stored.windows(file.len()).any(|w| w == file),
        "the server's copy must not contain the plaintext"
    );

    // Bob is a member, so he may fetch it — and the key from the MLS message opens it.
    let (status, fetched) = download(&app, &blob_id, &bob.0).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched, sealed.ciphertext);
    assert_eq!(
        mls_core::attachment::open(&sealed.key, &sealed.digest, &fetched).expect("open"),
        file
    );
}

/// Access is conversation membership, re-checked at fetch time — not possession of the id. A
/// stranger with the exact blob id is refused, and so is someone who has left.
#[tokio::test]
async fn access_follows_membership_not_the_id() {
    let app = make_app_with_blobs(100_000, blob_dir("membership")).await;
    let alice = user(&app, "acca").await;
    let bob = user(&app, "accb").await;
    let carol = user(&app, "accc").await;
    let conv = group_of_two(&app, &alice, &bob).await;

    let sealed = mls_core::attachment::seal(b"private").expect("seal");
    let (status, body) = upload(&app, &conv, &alice.0, sealed.ciphertext).await;
    assert_eq!(status, StatusCode::OK);
    let blob_id = body["blob_id"].as_str().unwrap().to_string();

    // A stranger holding the id learns nothing — and gets the same refusal as for a blob that does
    // not exist, so this is not an existence oracle.
    let (status, _) = download(&app, &blob_id, &carol.0).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (missing, _) = download(&app, &"ab".repeat(16), &carol.0).await;
    assert_eq!(
        missing,
        StatusCode::FORBIDDEN,
        "same answer for a nonexistent blob"
    );

    // A stranger cannot upload into someone else's conversation either.
    let sealed = mls_core::attachment::seal(b"intrusion").expect("seal");
    let (status, _) = upload(&app, &conv, &carol.0, sealed.ciphertext).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Bob leaves: his access to the group's files ends with his access to its messages.
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/leave"),
        &bob.0,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = download(&app, &blob_id, &bob.0).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "leaving ends access to the files too"
    );
}

/// An upload is the first half of sending a message, so the moderation gate applies to it: a muted
/// member cannot park bytes on the relay, and nothing is written when they try.
#[tokio::test]
async fn a_muted_member_cannot_upload() {
    let dir = blob_dir("muted");
    let app = make_app_with_blobs(100_000, dir.clone()).await;
    let alice = user(&app, "muta").await;
    let bob = user(&app, "mutb").await;
    let conv = group_of_two(&app, &alice, &bob).await;

    let before = std::fs::read_dir(&dir).expect("dir").count();
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/mutes"),
        &alice.0,
        json!({ "account_id": bob.1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let sealed = mls_core::attachment::seal(b"blocked").expect("seal");
    let (status, body) = upload(&app, &conv, &bob.0, sealed.ciphertext.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body["error"], "muted",
        "the specific reason, as for a refused send"
    );
    assert_eq!(
        std::fs::read_dir(&dir).expect("dir").count(),
        before,
        "a refused upload writes nothing"
    );

    // Announcement mode refuses the same way, with its own reason.
    post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/mutes/remove"),
        &alice.0,
        json!({ "account_id": bob.1 }),
    )
    .await;
    post_json_auth(
        &app,
        &format!("/v1/conversations/{conv}/settings"),
        &alice.0,
        json!({ "announcements_only": true }),
    )
    .await;
    let (status, body) = upload(&app, &conv, &bob.0, sealed.ciphertext).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "announcements_only");
}

/// Retention: rows past the TTL are deleted with their bytes, and the store sweep also collects
/// objects whose rows went with a deleted conversation — otherwise those files would live forever.
#[tokio::test]
async fn retention_removes_rows_and_bytes() {
    use nedwons_api::blobs::BlobStore;
    let dir = blob_dir("retention");
    let app = make_app_with_blobs(100_000, dir.clone()).await;
    let alice = user(&app, "reta").await;
    let bob = user(&app, "retb").await;
    let conv = group_of_two(&app, &alice, &bob).await;

    let sealed = mls_core::attachment::seal(b"expires").expect("seal");
    let (status, body) = upload(&app, &conv, &alice.0, sealed.ciphertext).await;
    assert_eq!(status, StatusCode::OK);
    let blob_id = body["blob_id"].as_str().unwrap().to_string();
    assert!(dir.join(&blob_id).exists());

    let relay = common::shared_relay();
    let store = nedwons_api::blobs::FsBlobStore::new(&dir).expect("store");
    let url = db_url();
    let backdated_id = blob_id.clone();
    let purged = tokio::task::spawn_blocking(move || {
        // Backdate ONLY this test's row and purge with an hour-long TTL. A zero TTL would make
        // every row in the shared test database eligible — including rows other tests in this
        // binary created moments ago and are about to fetch (that raced for real: the roundtrip
        // test's download intermittently saw the uniform 403 after its row vanished here).
        let mut conn = postgres::Client::connect(&url, postgres::NoTls).expect("db");
        let raw = hex::decode(&backdated_id).expect("blob id hex");
        conn.execute(
            "UPDATE attachments SET created_at = now() - interval '2 hours' WHERE blob_id = $1",
            &[&raw],
        )
        .expect("backdate");
        let ids = relay
            .purge_stale_attachments(std::time::Duration::from_secs(3600), 100)
            .expect("purge");
        for id in &ids {
            store.delete(id).expect("delete bytes");
        }
        ids.len()
    })
    .await
    .expect("purge task");
    assert!(purged >= 1);
    assert!(!dir.join(&blob_id).exists(), "the bytes went with the row");

    // And the row is gone, so a member fetching it now gets the generic refusal.
    let (status, _) = download(&app, &blob_id, &bob.0).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Sizes are bounded at the edge: an empty upload and one past the cap are refused before anything
/// is written.
#[tokio::test]
async fn upload_sizes_are_bounded() {
    let dir = blob_dir("sizes");
    let app = make_app_with_blobs(100_000, dir.clone()).await;
    let alice = user(&app, "siza").await;
    let bob = user(&app, "sizb").await;
    let conv = group_of_two(&app, &alice, &bob).await;
    let before = std::fs::read_dir(&dir).expect("dir").count();

    let (status, _) = upload(&app, &conv, &alice.0, Vec::new()).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an empty upload is not a file"
    );

    // Past the route's own body limit: rejected by the transport layer, never reaching a handler.
    let too_big = vec![0u8; 27 * 1024 * 1024];
    let (status, _) = upload(&app, &conv, &alice.0, too_big).await;
    assert_ne!(status, StatusCode::OK, "over the cap must not be stored");
    assert_eq!(
        std::fs::read_dir(&dir).expect("dir").count(),
        before,
        "nothing was written"
    );
    let _ = db_url(); // keeps the shared-pool import honest across test binaries
}
