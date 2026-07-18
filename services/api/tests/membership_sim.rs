//! ADR-0010 headless multi-client reference simulation (R-506).
//!
//! REAL MLS clients (`mls-core`, dev-dependency — the server binary still never links it) drive
//! membership through the REAL relay: device-signed manifests, the per-group epoch CAS, atomic
//! routing + commit/welcome fan-out + removed-device cutoff, and — the part only clients can do —
//! the correspondence check that catches a lying manifest.
//!
//! MLS credential identity = the 16-byte device id, so manifests and credentials name the same
//! things and recipients can compare them.

mod common;

use axum::http::StatusCode;
use axum::Router;
use common::{get_auth, http_register, make_app, post_json_auth, unique_username, TestDevice};
use serde_json::{json, Value};

use auth_core::crypto::sha256;
use auth_core::ids::{AccountId, DeviceId};
use auth_core::membership::{ControlType, Manifest};
use mls_core::Member;

struct Actor {
    device: TestDevice,
    session: Value,
    account: [u8; 16],
    device_id: [u8; 16],
    mls: Member,
}

async fn actor(app: &Router, prefix: &str) -> Actor {
    let (device, session) = http_register(app, &unique_username(prefix)).await;
    let account: [u8; 16] = hex::decode(session["account_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let device_id: [u8; 16] = hex::decode(session["device_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mls = Member::new(&device_id).unwrap();
    Actor {
        device,
        session,
        account,
        device_id,
        mls,
    }
}

impl Actor {
    fn token(&self) -> &str {
        self.session["access_token"].as_str().unwrap()
    }
}

/// Build + sign the canonical manifest and POST the commit bundle. Returns (status, body).
#[allow(clippy::too_many_arguments)]
async fn post_commit(
    app: &Router,
    conv_hex: &str,
    actor: &Actor,
    control: ControlType,
    prev_epoch: u64,
    added: &[(AccountId, DeviceId)],
    removed: &[DeviceId],
    idem: [u8; 16],
    commit: &[u8],
    welcomes: &[Vec<u8>],
) -> (StatusCode, Value) {
    let conversation_id: [u8; 16] = hex::decode(conv_hex).unwrap().try_into().unwrap();
    let commit_hash = sha256(commit);
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;
    let manifest = Manifest {
        control,
        group_id: &conversation_id,
        prev_epoch,
        next_epoch: prev_epoch + 1,
        commit_hash: &commit_hash,
        actor_device: &DeviceId(actor.device_id),
        added,
        removed,
        idempotency_key: &idem,
        expires_at,
    };
    let signature = actor.device.sign(&manifest.encode());
    let body = json!({
        "control_type": control as u8,
        "prev_epoch": prev_epoch,
        "next_epoch": prev_epoch + 1,
        "commit_hash": hex::encode(commit_hash),
        "added": added.iter().map(|(a, d)| json!({
            "account_id": hex::encode(a.as_bytes()),
            "device_id": hex::encode(d.as_bytes()),
        })).collect::<Vec<_>>(),
        "removed": removed.iter().map(|d| hex::encode(d.as_bytes())).collect::<Vec<_>>(),
        "idempotency_key": hex::encode(idem),
        "expires_at": expires_at,
        "signature": hex::encode(&signature),
        "commit": hex::encode(commit),
        "welcomes": welcomes.iter().map(hex::encode).collect::<Vec<_>>(),
    });
    post_json_auth(
        app,
        &format!("/v1/conversations/{conv_hex}/messages").replace("/messages", "/commit"),
        actor.token(),
        body,
    )
    .await
}

async fn server_epoch(app: &Router, conv_hex: &str, token: &str) -> u64 {
    let (status, body) = get_auth(app, &format!("/v1/conversations/{conv_hex}/epoch"), token).await;
    assert_eq!(status, StatusCode::OK);
    body["epoch"].as_u64().unwrap()
}

/// Drain the caller's inbox, returning (envelope_id, ciphertext) pairs, and ack them.
async fn drain_inbox(app: &Router, token: &str) -> Vec<(i64, Vec<u8>)> {
    let (status, body) = get_auth(app, "/v1/inbox", token).await;
    assert_eq!(status, StatusCode::OK);
    let out: Vec<(i64, Vec<u8>)> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["id"].as_i64().unwrap(),
                hex::decode(e["ciphertext"].as_str().unwrap()).unwrap(),
            )
        })
        .collect();
    if !out.is_empty() {
        let ids: Vec<i64> = out.iter().map(|(id, _)| *id).collect();
        let (status, _) = post_json_auth(app, "/v1/inbox/ack", token, json!({ "ids": ids })).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    out
}

/// Full happy path: admin adds a member via a signed commit; the joiner receives the Welcome
/// through the relay, joins the real MLS group at the server's epoch, and application messages
/// flow along the updated routing.
#[tokio::test]
async fn admin_add_via_commit_flows_end_to_end() {
    let app = make_app(100_000).await;
    let alice = actor(&app, "msimaa").await;
    let bob = actor(&app, "msimab").await;

    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice.token(), json!({})).await;
    let conv_hex = conv["conversation_id"].as_str().unwrap().to_string();
    assert_eq!(server_epoch(&app, &conv_hex, alice.token()).await, 0);

    // Real MLS: alice creates the group; bob's key package; alice builds the add commit.
    let mut group_a = alice.mls.create_group().unwrap();
    let add = group_a
        .add_member(&alice.mls, &bob.mls.key_package_bytes().unwrap())
        .unwrap();

    let (status, receipt) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        0,
        &[(AccountId(bob.account), DeviceId(bob.device_id))],
        &[],
        [1u8; 16],
        &add.commit,
        &[add.welcome],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "commit refused: {receipt}");
    assert_eq!(receipt["applied"], true);
    assert_eq!(server_epoch(&app, &conv_hex, alice.token()).await, 1);

    // Bob receives the Welcome through the relay and joins the REAL group.
    let mut bob_mail = drain_inbox(&app, bob.token()).await;
    assert_eq!(bob_mail.len(), 1, "exactly the welcome");
    let (_, welcome) = bob_mail.remove(0);
    let mut group_b = bob.mls.join_from_welcome(&welcome).unwrap();
    assert_eq!(group_b.epoch(), 1, "MLS epoch equals the server epoch");

    // Application traffic now flows along the commit-updated routing.
    let envelope = group_a.encrypt(&alice.mls, b"welcome aboard").unwrap();
    let (status, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv_hex}/messages"),
        alice.token(),
        json!({ "ciphertext": hex::encode(&envelope), "idempotency_key": hex::encode([2u8; 16]) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mut mail = drain_inbox(&app, bob.token()).await;
    let (_, ct) = mail.remove(0);
    match group_b.process(&bob.mls, &ct).unwrap() {
        mls_core::Incoming::Application(pt) => assert_eq!(pt, b"welcome aboard"),
        _ => panic!("expected application message"),
    }
}

/// The epoch CAS linearizes membership: a commit built against a superseded epoch is refused
/// with `stale_epoch` and nothing is applied (the loser rebases and retries).
#[tokio::test]
async fn concurrent_commit_race_has_exactly_one_winner() {
    let app = make_app(100_000).await;
    let alice = actor(&app, "msimba").await;
    let bob = actor(&app, "msimbb").await;
    let carol = actor(&app, "msimbc").await;

    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice.token(), json!({})).await;
    let conv_hex = conv["conversation_id"].as_str().unwrap().to_string();

    let mut group_a = alice.mls.create_group().unwrap();
    let add_bob = group_a
        .add_member(&alice.mls, &bob.mls.key_package_bytes().unwrap())
        .unwrap();
    // Winner: real add of bob at prev=0.
    let (status, _) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        0,
        &[(AccountId(bob.account), DeviceId(bob.device_id))],
        &[],
        [3u8; 16],
        &add_bob.commit,
        &[add_bob.welcome],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Loser: a competing commit built against the SAME prev=0 (the relay cannot parse it — any
    // opaque bytes with a correct hash and signature stand in for the losing client's commit).
    let stale_commit = b"competing-commit-built-at-epoch-0".to_vec();
    let (status, body) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        0,
        &[(AccountId(carol.account), DeviceId(carol.device_id))],
        &[],
        [4u8; 16],
        &stale_commit,
        &[b"welcome-bytes".to_vec()],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "stale_epoch");
    assert_eq!(
        server_epoch(&app, &conv_hex, alice.token()).await,
        1,
        "loser applied nothing"
    );

    // The loser rebases at the current epoch and succeeds.
    let add_carol = group_a
        .add_member(&alice.mls, &carol.mls.key_package_bytes().unwrap())
        .unwrap();
    let (status, _) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        1,
        &[(AccountId(carol.account), DeviceId(carol.device_id))],
        &[],
        [5u8; 16],
        &add_carol.commit,
        &[add_carol.welcome],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(server_epoch(&app, &conv_hex, alice.token()).await, 2);
}

/// The honest limitation, exercised: the MLS-blind server ACCEPTS a manifest whose claimed delta
/// differs from the commit's real content — and every honest recipient client catches the lie in
/// the correspondence check and refuses to merge, so the cryptographic group never follows it.
#[tokio::test]
async fn lying_manifest_is_accepted_by_server_but_caught_by_recipient() {
    let app = make_app(100_000).await;
    let alice = actor(&app, "msimca").await;
    let bob = actor(&app, "msimcb").await;
    let carol = actor(&app, "msimcc").await;
    let mallory = actor(&app, "msimcm").await;

    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice.token(), json!({})).await;
    let conv_hex = conv["conversation_id"].as_str().unwrap().to_string();

    // Honest add of bob (epoch 0 → 1), bob joins for real.
    let mut group_a = alice.mls.create_group().unwrap();
    let add_bob = group_a
        .add_member(&alice.mls, &bob.mls.key_package_bytes().unwrap())
        .unwrap();
    let (status, _) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        0,
        &[(AccountId(bob.account), DeviceId(bob.device_id))],
        &[],
        [6u8; 16],
        &add_bob.commit,
        &[add_bob.welcome],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, welcome) = drain_inbox(&app, bob.token()).await.remove(0);
    let mut group_b = bob.mls.join_from_welcome(&welcome).unwrap();

    // THE LIE: alice's MLS commit really adds MALLORY, but the signed manifest claims CAROL.
    let add_mallory = group_a
        .add_member(&alice.mls, &mallory.mls.key_package_bytes().unwrap())
        .unwrap();
    let (status, _) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        1,
        &[(AccountId(carol.account), DeviceId(carol.device_id))], // claimed
        &[],
        [7u8; 16],
        &add_mallory.commit, // actual
        &[add_mallory.welcome],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the MLS-blind server cannot detect the lie — documented limitation"
    );

    // Bob receives the commit and runs the ADR-0010 correspondence check with the manifest's
    // claim: mismatch → refused, cryptographic state unchanged.
    let (_, commit_ct) = drain_inbox(&app, bob.token()).await.remove(0);
    let err = group_b
        .process_commit_checked(
            &bob.mls,
            &commit_ct,
            2,
            &[carol.device_id.to_vec()], // what the manifest claimed
            &[],
        )
        .unwrap_err();
    assert!(matches!(err, mls_core::MlsError::ManifestMismatch));
    assert_eq!(group_b.epoch(), 1, "honest client refused the lying commit");
}

/// Removal cuts routing and queued delivery atomically with the commit, and the group continues
/// at the new epoch for the remaining members.
#[tokio::test]
async fn remove_commit_cuts_delivery_atomically() {
    let app = make_app(100_000).await;
    let alice = actor(&app, "msimda").await;
    let bob = actor(&app, "msimdb").await;
    let carol = actor(&app, "msimdc").await;

    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice.token(), json!({})).await;
    let conv_hex = conv["conversation_id"].as_str().unwrap().to_string();

    // Build the trio via two honest commits; bob and carol join for real.
    let mut group_a = alice.mls.create_group().unwrap();
    let add_bob = group_a
        .add_member(&alice.mls, &bob.mls.key_package_bytes().unwrap())
        .unwrap();
    let (s, _) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        0,
        &[(AccountId(bob.account), DeviceId(bob.device_id))],
        &[],
        [8u8; 16],
        &add_bob.commit,
        &[add_bob.welcome],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, w) = drain_inbox(&app, bob.token()).await.remove(0);
    let mut group_b = bob.mls.join_from_welcome(&w).unwrap();

    let add_carol = group_a
        .add_member(&alice.mls, &carol.mls.key_package_bytes().unwrap())
        .unwrap();
    let (s, _) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        1,
        &[(AccountId(carol.account), DeviceId(carol.device_id))],
        &[],
        [9u8; 16],
        &add_carol.commit,
        &[add_carol.welcome],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // Bob merges carol's add (checked against the honest manifest).
    let (_, add_ct) = drain_inbox(&app, bob.token()).await.remove(0);
    group_b
        .process_commit_checked(&bob.mls, &add_ct, 2, &[carol.device_id.to_vec()], &[])
        .unwrap();
    let (_, wc) = drain_inbox(&app, carol.token()).await.remove(0);
    let mut group_c = carol.mls.join_from_welcome(&wc).unwrap();

    // Queue a message for bob, then remove him BEFORE he fetches: the removal must also purge
    // his queued mail (delivery cutoff is part of the same transaction).
    let pre_removal = group_a.encrypt(&alice.mls, b"pre-removal").unwrap();
    let (s, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv_hex}/messages"),
        alice.token(),
        json!({ "ciphertext": hex::encode(&pre_removal), "idempotency_key": hex::encode([10u8; 16]) }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let remove_bob = group_a.remove_member(&alice.mls, &bob.device_id).unwrap();
    let (s, _) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Remove,
        2,
        &[],
        &[DeviceId(bob.device_id)],
        [11u8; 16],
        &remove_bob,
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(server_epoch(&app, &conv_hex, alice.token()).await, 3);

    // Bob's queue is empty: the pre-removal message AND the removal commit are both gone (cutoff).
    assert!(drain_inbox(&app, bob.token()).await.is_empty());
    // Bob is no longer routed: the epoch endpoint refuses him generically.
    let (s, _) = get_auth(
        &app,
        &format!("/v1/conversations/{conv_hex}/epoch"),
        bob.token(),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Carol's queue holds, in order, the pre-removal application message (she was a member when it
    // was sent) then the removal commit. She reads the message, then merges the checked removal.
    let carol_mail = drain_inbox(&app, carol.token()).await;
    assert_eq!(carol_mail.len(), 2);
    match group_c.process(&carol.mls, &carol_mail[0].1).unwrap() {
        mls_core::Incoming::Application(pt) => assert_eq!(pt, b"pre-removal"),
        _ => panic!("expected the pre-removal application message"),
    }
    group_c
        .process_commit_checked(
            &carol.mls,
            &carol_mail[1].1,
            3,
            &[],
            &[bob.device_id.to_vec()],
        )
        .unwrap();
    let post_removal = group_a.encrypt(&alice.mls, b"post-removal").unwrap();
    let (s, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv_hex}/messages"),
        alice.token(),
        json!({ "ciphertext": hex::encode(&post_removal), "idempotency_key": hex::encode([12u8; 16]) }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, ct) = drain_inbox(&app, carol.token()).await.remove(0);
    match group_c.process(&carol.mls, &ct).unwrap() {
        mls_core::Incoming::Application(pt) => assert_eq!(pt, b"post-removal"),
        _ => panic!("expected application message"),
    }
    assert!(drain_inbox(&app, bob.token()).await.is_empty());
}

/// Governance + authenticity + idempotency at the endpoint: non-admins cannot add, a manifest
/// signed by the wrong key is denied, identical retries are idempotent, key reuse with a
/// different manifest conflicts, and a non-admin member CAN self-leave.
#[tokio::test]
async fn governance_signature_and_idempotency_rules_hold() {
    let app = make_app(100_000).await;
    let alice = actor(&app, "msimea").await;
    let bob = actor(&app, "msimeb").await;
    let carol = actor(&app, "msimec").await;

    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice.token(), json!({})).await;
    let conv_hex = conv["conversation_id"].as_str().unwrap().to_string();

    let mut group_a = alice.mls.create_group().unwrap();
    let add_bob = group_a
        .add_member(&alice.mls, &bob.mls.key_package_bytes().unwrap())
        .unwrap();
    let (s, _) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        0,
        &[(AccountId(bob.account), DeviceId(bob.device_id))],
        &[],
        [13u8; 16],
        &add_bob.commit,
        std::slice::from_ref(&add_bob.welcome),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    drain_inbox(&app, bob.token()).await;

    // Non-admin bob cannot add carol, even with a validly-signed manifest.
    let (s, _) = post_commit(
        &app,
        &conv_hex,
        &bob,
        ControlType::Add,
        1,
        &[(AccountId(carol.account), DeviceId(carol.device_id))],
        &[],
        [14u8; 16],
        b"any-bytes",
        &[b"welcome".to_vec()],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // A manifest whose signature does not verify under the ACTOR's enrolled key is denied.
    {
        let conversation_id: [u8; 16] = hex::decode(&conv_hex).unwrap().try_into().unwrap();
        let commit = b"any-bytes".to_vec();
        let commit_hash = sha256(&commit);
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        let added = [(AccountId(carol.account), DeviceId(carol.device_id))];
        let manifest = Manifest {
            control: ControlType::Add,
            group_id: &conversation_id,
            prev_epoch: 1,
            next_epoch: 2,
            commit_hash: &commit_hash,
            actor_device: &DeviceId(alice.device_id),
            added: &added,
            removed: &[],
            idempotency_key: &[15u8; 16],
            expires_at,
        };
        let wrong_signature = bob.device.sign(&manifest.encode()); // bob signs alice's manifest
        let body = json!({
            "control_type": 1u8,
            "prev_epoch": 1,
            "next_epoch": 2,
            "commit_hash": hex::encode(commit_hash),
            "added": [{ "account_id": hex::encode(carol.account), "device_id": hex::encode(carol.device_id) }],
            "removed": [],
            "idempotency_key": hex::encode([15u8; 16]),
            "expires_at": expires_at,
            "signature": hex::encode(&wrong_signature),
            "commit": hex::encode(&commit),
            "welcomes": [hex::encode(b"welcome")],
        });
        let (s, _) = post_json_auth(
            &app,
            &format!("/v1/conversations/{conv_hex}/commit"),
            alice.token(),
            body,
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }

    // Idempotency: an identical retry of the applied add is a durable no-op...
    let (s, receipt) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        0,
        &[(AccountId(bob.account), DeviceId(bob.device_id))],
        &[],
        [13u8; 16],
        &add_bob.commit,
        &[add_bob.welcome],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(receipt["applied"], false);
    // ...and reusing its key for a DIFFERENT manifest conflicts.
    let (s, body) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        1,
        &[(AccountId(carol.account), DeviceId(carol.device_id))],
        &[],
        [13u8; 16],
        b"different-bytes",
        &[b"welcome".to_vec()],
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(body["error"], "idempotency_conflict");

    // A non-admin member CAN withdraw consent: bob self-leaves via a Leave commit.
    let (s, _) = post_commit(
        &app,
        &conv_hex,
        &bob,
        ControlType::Leave,
        1,
        &[],
        &[DeviceId(bob.device_id)],
        [16u8; 16],
        b"leave-commit-bytes",
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = get_auth(
        &app,
        &format!("/v1/conversations/{conv_hex}/epoch"),
        bob.token(),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "left member is no longer routed");
}

/// Shape guards: expired manifests and unsorted delta lists are rejected before any state is
/// touched (canonical form is part of the protocol).
#[tokio::test]
async fn expired_and_non_canonical_manifests_are_rejected() {
    let app = make_app(100_000).await;
    let alice = actor(&app, "msimfa").await;
    let bob = actor(&app, "msimfb").await;
    let carol = actor(&app, "msimfc").await;

    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice.token(), json!({})).await;
    let conv_hex = conv["conversation_id"].as_str().unwrap().to_string();
    let conversation_id: [u8; 16] = hex::decode(&conv_hex).unwrap().try_into().unwrap();

    // Expired manifest → 400 without any lookup.
    let commit = b"bytes".to_vec();
    let commit_hash = sha256(&commit);
    let expired = 1_u64; // 1970
    let added = [(AccountId(bob.account), DeviceId(bob.device_id))];
    let manifest = Manifest {
        control: ControlType::Add,
        group_id: &conversation_id,
        prev_epoch: 0,
        next_epoch: 1,
        commit_hash: &commit_hash,
        actor_device: &DeviceId(alice.device_id),
        added: &added,
        removed: &[],
        idempotency_key: &[17u8; 16],
        expires_at: expired,
    };
    let signature = alice.device.sign(&manifest.encode());
    let body = json!({
        "control_type": 1u8, "prev_epoch": 0, "next_epoch": 1,
        "commit_hash": hex::encode(commit_hash),
        "added": [{ "account_id": hex::encode(bob.account), "device_id": hex::encode(bob.device_id) }],
        "removed": [], "idempotency_key": hex::encode([17u8; 16]), "expires_at": expired,
        "signature": hex::encode(&signature), "commit": hex::encode(&commit),
        "welcomes": [hex::encode(b"welcome")],
    });
    let (s, b) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv_hex}/commit"),
        alice.token(),
        body,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");

    // Unsorted added list → 400 (canonical order is part of the manifest's identity).
    let mut pair = vec![
        (AccountId(bob.account), DeviceId(bob.device_id)),
        (AccountId(carol.account), DeviceId(carol.device_id)),
    ];
    pair.sort_by(|a, b| (a.0.as_bytes(), a.1.as_bytes()).cmp(&(b.0.as_bytes(), b.1.as_bytes())));
    pair.reverse(); // deliberately wrong order
    let (s, _) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        0,
        &pair,
        &[],
        [18u8; 16],
        b"bytes",
        &[b"w1".to_vec(), b"w2".to_vec()],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

/// Fetch the stored membership event for `next_epoch` and return its (added, removed) device ids —
/// what a recipient feeds into the correspondence check.
async fn fetch_event_delta(
    app: &Router,
    conv_hex: &str,
    next_epoch: u64,
    token: &str,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (status, body) = get_auth(
        app,
        &format!("/v1/conversations/{conv_hex}/membership/{next_epoch}"),
        token,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "membership event {next_epoch}: {body}"
    );
    let added = body["added"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| hex::decode(a["device_id"].as_str().unwrap()).unwrap())
        .collect();
    let removed = body["removed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| hex::decode(d.as_str().unwrap()).unwrap())
        .collect();
    (added, removed)
}

/// The full client story with the REAL staged proposer flow and a REAL two-admin race:
/// stage (no local merge) → POST → merge on accept / discard + catch-up + rebase on stale_epoch.
/// A race loser must NOT desync — it discards its staged commit, processes the winner's commit to
/// catch up, then rebuilds. Also exercises the recipient's manifest fetch + correspondence check.
#[tokio::test]
async fn staged_two_admin_race_loser_discards_catches_up_and_rebases() {
    let app = make_app(100_000).await;
    let alice = actor(&app, "msimga").await;
    let bob = actor(&app, "msimgb").await;
    let carol = actor(&app, "msimgc").await;
    let dave = actor(&app, "msimgd").await;

    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice.token(), json!({})).await;
    let conv_hex = conv["conversation_id"].as_str().unwrap().to_string();

    // Alice (admin) stages + commits adding bob (epoch 0 → 1); bob joins for real.
    let mut group_a = alice.mls.create_group().unwrap();
    let add_bob = group_a
        .stage_add_member(&alice.mls, &bob.mls.key_package_bytes().unwrap())
        .unwrap();
    let (s, _) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        0,
        &[(AccountId(bob.account), DeviceId(bob.device_id))],
        &[],
        [1u8; 16],
        &add_bob.commit,
        std::slice::from_ref(&add_bob.welcome),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    group_a.merge_staged(&alice.mls).unwrap(); // server accepted → merge
    let (_, welcome) = drain_inbox(&app, bob.token()).await.remove(0);
    let mut group_b = bob.mls.join_from_welcome(&welcome).unwrap();
    assert_eq!(group_a.epoch(), 1);
    assert_eq!(group_b.epoch(), 1);

    // Promote bob to admin so both can propose. Now the race: both stage an add at epoch 1.
    let (s, _) = post_json_auth(
        &app,
        &format!("/v1/conversations/{conv_hex}/admins"),
        alice.token(),
        json!({ "account_id": hex::encode(bob.account) }),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let alice_add_carol = group_a
        .stage_add_member(&alice.mls, &carol.mls.key_package_bytes().unwrap())
        .unwrap();
    let bob_add_dave = group_b
        .stage_add_member(&bob.mls, &dave.mls.key_package_bytes().unwrap())
        .unwrap();

    // Bob posts first and wins the epoch CAS (1 → 2); bob merges.
    let (s, _) = post_commit(
        &app,
        &conv_hex,
        &bob,
        ControlType::Add,
        1,
        &[(AccountId(dave.account), DeviceId(dave.device_id))],
        &[],
        [2u8; 16],
        &bob_add_dave.commit,
        std::slice::from_ref(&bob_add_dave.welcome),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    group_b.merge_staged(&bob.mls).unwrap();

    // Alice posts her competing commit at the now-stale epoch 1 → refused, nothing applied.
    let (s, body) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        1,
        &[(AccountId(carol.account), DeviceId(carol.device_id))],
        &[],
        [3u8; 16],
        &alice_add_carol.commit,
        std::slice::from_ref(&alice_add_carol.welcome),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(body["error"], "stale_epoch");

    // Alice DISCARDS her staged commit (must not desync) and catches up by processing bob's commit,
    // fetching the manifest delta to run the correspondence check.
    group_a.clear_staged(&alice.mls).unwrap();
    assert_eq!(group_a.epoch(), 1, "discard must not advance");
    let (_, bob_commit_ct) = drain_inbox(&app, alice.token()).await.remove(0);
    let (added, removed) = fetch_event_delta(&app, &conv_hex, 2, alice.token()).await;
    assert_eq!(added, vec![dave.device_id.to_vec()]);
    assert!(removed.is_empty());
    group_a
        .process_commit_checked(&alice.mls, &bob_commit_ct, 2, &added, &removed)
        .unwrap();
    assert_eq!(group_a.epoch(), 2, "alice caught up to the winner's epoch");

    // Alice rebases at epoch 2 and her add of carol now succeeds.
    let alice_add_carol2 = group_a
        .stage_add_member(&alice.mls, &carol.mls.key_package_bytes().unwrap())
        .unwrap();
    let (s, _) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        2,
        &[(AccountId(carol.account), DeviceId(carol.device_id))],
        &[],
        [4u8; 16],
        &alice_add_carol2.commit,
        std::slice::from_ref(&alice_add_carol2.welcome),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    group_a.merge_staged(&alice.mls).unwrap();
    assert_eq!(server_epoch(&app, &conv_hex, alice.token()).await, 3);
    assert_eq!(group_a.epoch(), 3);
}

/// The membership-event endpoint is members-only and returns the correct decoded delta.
#[tokio::test]
async fn membership_event_endpoint_is_members_only() {
    let app = make_app(100_000).await;
    let alice = actor(&app, "msimha").await;
    let bob = actor(&app, "msimhb").await;
    let outsider = actor(&app, "msimho").await;

    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice.token(), json!({})).await;
    let conv_hex = conv["conversation_id"].as_str().unwrap().to_string();
    let mut group_a = alice.mls.create_group().unwrap();
    let add_bob = group_a
        .add_member(&alice.mls, &bob.mls.key_package_bytes().unwrap())
        .unwrap();
    let (s, _) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        0,
        &[(AccountId(bob.account), DeviceId(bob.device_id))],
        &[],
        [5u8; 16],
        &add_bob.commit,
        std::slice::from_ref(&add_bob.welcome),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // A member reads the decoded event.
    let (added, removed) = fetch_event_delta(&app, &conv_hex, 1, alice.token()).await;
    assert_eq!(added, vec![bob.device_id.to_vec()]);
    assert!(removed.is_empty());

    // An outsider gets a generic 403 (no oracle).
    let (s, _) = get_auth(
        &app,
        &format!("/v1/conversations/{conv_hex}/membership/1"),
        outsider.token(),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // A non-existent epoch is also a generic 403 (no oracle on which epochs exist).
    let (s, _) = get_auth(
        &app,
        &format!("/v1/conversations/{conv_hex}/membership/99"),
        alice.token(),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

/// The membership-event endpoint carries evidence a recipient can independently verify: the
/// actor's account (to locate its transparency-logged key) and a manifest signature that verifies
/// under the actor's enrolled device key — the server-side half of recipient signature checking.
#[tokio::test]
async fn membership_event_signature_verifies_under_actor_key() {
    let app = make_app(100_000).await;
    let alice = actor(&app, "msimia").await;
    let bob = actor(&app, "msimib").await;

    let (_, conv) = post_json_auth(&app, "/v1/conversations", alice.token(), json!({})).await;
    let conv_hex = conv["conversation_id"].as_str().unwrap().to_string();
    let mut group_a = alice.mls.create_group().unwrap();
    let add_bob = group_a
        .add_member(&alice.mls, &bob.mls.key_package_bytes().unwrap())
        .unwrap();
    let (s, _) = post_commit(
        &app,
        &conv_hex,
        &alice,
        ControlType::Add,
        0,
        &[(AccountId(bob.account), DeviceId(bob.device_id))],
        &[],
        [21u8; 16],
        &add_bob.commit,
        std::slice::from_ref(&add_bob.welcome),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // Bob (a member) fetches the event and independently verifies the evidence.
    let (status, body) = get_auth(
        &app,
        &format!("/v1/conversations/{conv_hex}/membership/1"),
        bob.token(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The actor account points at alice — where her device key is logged in transparency.
    assert_eq!(
        body["actor_account"].as_str().unwrap(),
        hex::encode(alice.account)
    );
    assert_eq!(
        body["actor_device"].as_str().unwrap(),
        hex::encode(alice.device_id)
    );

    // The stored signature verifies over the stored manifest bytes under alice's enrolled key.
    let manifest = hex::decode(body["manifest"].as_str().unwrap()).unwrap();
    let signature = hex::decode(body["signature"].as_str().unwrap()).unwrap();
    assert!(
        auth_core::crypto::verify_p256(&alice.device.public_key, &manifest, &signature),
        "manifest signature must verify under the actor's enrolled device key"
    );

    // A different key must NOT verify (anti-substitution).
    assert!(!auth_core::crypto::verify_p256(
        &bob.device.public_key,
        &manifest,
        &signature
    ));

    // The decoded manifest matches the structured fields (encoder/decoder agree end to end).
    let decoded = auth_core::membership::decode(&manifest).unwrap();
    assert_eq!(decoded.actor_device, alice.device_id);
    assert_eq!(decoded.added, vec![(bob.account, bob.device_id)]);
}
