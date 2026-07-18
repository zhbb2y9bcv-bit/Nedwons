//! Secret-message flow across the exact FFI surface UniFFI exports (ADR-0007) — two real Rust MLS
//! clients, driven through `MlsClient`, prove the end-to-end view-once lifecycle the Swift binding
//! marshals to: sealed on delivery, atomic reveal, 3s + 10s deadlines, expiry→tombstone, crash
//! fail-closed, replay rejection, and normal messages working alongside.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use mls_ffi::{secret_tombstone_text, InboundResult, MlsClient, MlsClientError, SecretPhase};

const KEY: [u8; 32] = [9u8; 32];

fn key() -> Vec<u8> {
    KEY.to_vec()
}

fn tmp(tag: &str) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut p = std::env::temp_dir();
    p.push(format!(
        "mls-ffi-secret-{}-{}-{}-{}",
        std::process::id(),
        tag,
        nanos,
        n
    ));
    p.to_string_lossy().into_owned()
}

fn two_party(
    alice_db: &str,
    bob_db: &str,
) -> (std::sync::Arc<MlsClient>, std::sync::Arc<MlsClient>) {
    let alice = MlsClient::create_group(b"alice-device".to_vec(), alice_db.into(), key()).unwrap();
    let bob = MlsClient::new_joiner(b"bob-device".to_vec(), bob_db.into(), key()).unwrap();
    let bob_kp = bob.key_package().unwrap();
    let add = alice.add_member(bob_kp).unwrap();
    bob.join_group(add.welcome).unwrap();
    (alice, bob)
}

/// Alice sends a secret to Bob through the FFI; returns (envelope, secret_id).
fn send_secret(alice: &MlsClient, body: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let handle = alice.enqueue_secret(body.to_vec()).unwrap();
    let envelope = alice.encrypt(handle.local_id).unwrap();
    alice.mark_sent(handle.local_id).unwrap();
    (envelope, handle.secret_id)
}

#[test]
fn end_to_end_secret_sealed_revealed_expired_over_the_ffi() {
    let (alice, bob) = two_party(&tmp("a"), &tmp("b"));
    let (envelope, sid) = send_secret(&alice, b"eyes only");

    // (2) The relay only ever sees this opaque envelope; the body is not in it.
    assert!(!envelope.windows(9).any(|w| w == b"eyes only"));

    // (3) Bob receives a SEALED placeholder — no plaintext delivered.
    match bob.process_inbound(1, envelope).unwrap() {
        InboundResult::SecretSealed { secret_id } => assert_eq!(secret_id, sid),
        other => panic!("expected SecretSealed, got {other:?}"),
    }
    assert_eq!(
        bob.secret_phase(sid.clone(), 0).unwrap(),
        SecretPhase::Sealed
    );
    // (4) Cannot reveal the body before the atomic state transition.
    assert!(bob.secret_visible_body(sid.clone(), 0).unwrap().is_none());

    // (5) Begin reveal → 3s countdown. (6) Then a 10s window.
    bob.begin_secret_reveal(sid.clone(), 0).unwrap();
    assert_eq!(
        bob.secret_phase(sid.clone(), 2_999).unwrap(),
        SecretPhase::Countdown
    );
    assert_eq!(
        bob.secret_phase(sid.clone(), 3_000).unwrap(),
        SecretPhase::Visible
    );
    assert_eq!(
        bob.secret_visible_body(sid.clone(), 3_000)
            .unwrap()
            .as_deref(),
        Some(&b"eyes only"[..])
    );
    // (7) Expires into the tombstone at exactly 3+10s.
    assert_eq!(
        bob.secret_phase(sid.clone(), 13_000).unwrap(),
        SecretPhase::Consumed
    );
    assert!(bob
        .secret_visible_body(sid.clone(), 13_000)
        .unwrap()
        .is_none());
    assert_eq!(secret_tombstone_text(), "a secret message has been sent");
}

#[test]
fn reveal_before_transition_and_replay_are_refused() {
    let (alice, bob) = two_party(&tmp("a"), &tmp("b"));
    let (envelope, sid) = send_secret(&alice, b"nope");
    bob.process_inbound(1, envelope.clone()).unwrap();

    // (8) Redelivery of the same envelope is a durable no-op; a fresh envelope id with the same
    // spent ciphertext is rejected by MLS replay protection.
    assert!(matches!(
        bob.process_inbound(1, envelope.clone()).unwrap(),
        InboundResult::Duplicate
    ));
    assert!(bob.process_inbound(2, envelope).is_err());

    // A double begin grants no second window.
    bob.begin_secret_reveal(sid.clone(), 0).unwrap();
    assert!(bob.begin_secret_reveal(sid.clone(), 500).is_err());
    assert_eq!(
        bob.secret_phase(sid, 13_000).unwrap(),
        SecretPhase::Consumed
    );
}

#[test]
fn crash_after_reveal_fails_closed_on_reopen() {
    let dba = tmp("a");
    let dbb = tmp("b");
    let (alice, bob) = two_party(&dba, &dbb);
    let (envelope, sid) = send_secret(&alice, b"burn");
    bob.process_inbound(1, envelope).unwrap();
    bob.begin_secret_reveal(sid.clone(), 0).unwrap();
    assert_eq!(
        bob.secret_phase(sid.clone(), 3_000).unwrap(),
        SecretPhase::Visible
    );

    // (9) "Crash": drop and reopen Bob from the same encrypted DB. Fail closed — consumed, no body.
    bob.close();
    drop(bob);
    let bob = MlsClient::open(dbb, key()).unwrap();
    assert_eq!(
        bob.secret_phase(sid.clone(), 3_500).unwrap(),
        SecretPhase::Consumed
    );
    assert!(bob.secret_visible_body(sid, 3_500).unwrap().is_none());
}

#[test]
fn normal_messages_work_before_during_and_after_a_secret() {
    // (10) Normal messaging is unaffected by the secret feature.
    let (alice, bob) = two_party(&tmp("a"), &tmp("b"));

    let id = alice.enqueue(b"before".to_vec()).unwrap();
    let e = alice.encrypt(id).unwrap();
    assert!(matches!(
        bob.process_inbound(1, e).unwrap(),
        InboundResult::Application { .. }
    ));

    let (secret_env, sid) = send_secret(&alice, b"secret");
    assert!(matches!(
        bob.process_inbound(2, secret_env).unwrap(),
        InboundResult::SecretSealed { .. }
    ));
    bob.begin_secret_reveal(sid.clone(), 0).unwrap();

    // A normal message arrives WHILE the secret is mid-reveal; it processes normally.
    let id2 = alice.enqueue(b"during".to_vec()).unwrap();
    let e2 = alice.encrypt(id2).unwrap();
    match bob.process_inbound(3, e2).unwrap() {
        InboundResult::Application { plaintext } => assert_eq!(plaintext, b"during"),
        other => panic!("normal delivery must keep working during a reveal: {other:?}"),
    }
    // And after the secret expires.
    assert_eq!(
        bob.secret_phase(sid, 13_000).unwrap(),
        SecretPhase::Consumed
    );
    let id3 = alice.enqueue(b"after".to_vec()).unwrap();
    let e3 = alice.encrypt(id3).unwrap();
    assert!(matches!(
        bob.process_inbound(4, e3).unwrap(),
        InboundResult::Application { .. }
    ));
}

#[test]
fn hostile_secret_id_never_panics_and_yields_typed_errors() {
    let (alice, bob) = two_party(&tmp("a"), &tmp("b"));
    let (envelope, _sid) = send_secret(&alice, b"x");
    bob.process_inbound(1, envelope).unwrap();

    // Wrong-length ids → typed error, never a panic or a reveal.
    for bad in [
        vec![],
        vec![0u8; 8],
        vec![0u8; 15],
        vec![0u8; 17],
        vec![0u8; 64],
    ] {
        assert!(matches!(
            bob.begin_secret_reveal(bad.clone(), 0),
            Err(MlsClientError::InvalidMessage)
        ));
        assert!(
            bob.secret_visible_body(bad.clone(), 0).is_err()
                || bob.secret_visible_body(bad.clone(), 0).unwrap().is_none()
        );
    }
    // An unknown (well-formed) id is simply Unknown, not a crash.
    assert_eq!(
        bob.secret_phase(vec![0xAB; 16], 0).unwrap(),
        SecretPhase::Unknown
    );
    assert!(bob
        .secret_visible_body(vec![0xAB; 16], 0)
        .unwrap()
        .is_none());
}

#[test]
fn secret_message_marshals_with_empty_plaintext_and_id() {
    let (alice, bob) = two_party(&tmp("a"), &tmp("b"));
    let (envelope, sid) = send_secret(&alice, b"hidden");
    bob.process_inbound(1, envelope).unwrap();

    // The stored-message log exposes the secret as an empty-plaintext placeholder carrying its id —
    // never the body — so a UI can render a sealed placeholder without leaking content.
    let msgs = bob.messages().unwrap();
    let secret_msg = msgs
        .iter()
        .find(|m| m.secret_id.is_some())
        .expect("a secret placeholder");
    assert!(
        secret_msg.plaintext.is_empty(),
        "no body in the message log"
    );
    assert_eq!(secret_msg.secret_id.as_deref(), Some(sid.as_slice()));

    // The sender's own log likewise holds only a tombstone placeholder.
    let amsgs = alice.messages().unwrap();
    let sender_msg = amsgs
        .iter()
        .find(|m| m.secret_id.is_some())
        .expect("sender placeholder");
    assert!(sender_msg.plaintext.is_empty());
    assert_eq!(alice.secret_phase(sid, 0).unwrap(), SecretPhase::Consumed);
}
