//! Secret-message (view-once) end-to-end behavior at the durable layer: two real MLS clients
//! exchange a secret through the SAME authenticated pipeline as normal messages, the classification
//! and body stay inside the ciphertext (relay-blind), the reveal is atomic + fail-closed, expiry
//! scrubs and tombstones, and a crash after reveal fails closed on relaunch.

use mls_core::durable::{DurableSession, InMemoryJournal, InboundOutcome};
use mls_core::secret::{SecretState, TOMBSTONE_TEXT};
use mls_core::Member;

fn pair() -> (
    DurableSession<InMemoryJournal>,
    InMemoryJournal,
    DurableSession<InMemoryJournal>,
    InMemoryJournal,
) {
    let alice = Member::new(b"alice-device").expect("alice");
    let bob = Member::new(b"bob-device").expect("bob");
    let bob_kp = bob.key_package_bytes().expect("bob kp");
    let mut alice_group = alice.create_group().expect("group");
    let add = alice_group.add_member(&alice, &bob_kp).expect("add bob");
    let bob_group = bob.join_from_welcome(&add.welcome).expect("bob joins");
    let ja = InMemoryJournal::new();
    let jb = InMemoryJournal::new();
    let da = DurableSession::adopt(alice, alice_group, ja.clone()).expect("adopt alice");
    let db = DurableSession::adopt(bob, bob_group, jb.clone()).expect("adopt bob");
    (da, ja, db, jb)
}

/// Send a secret from Alice to Bob; return (envelope bytes, secret_id).
fn send_secret(alice: &mut DurableSession<InMemoryJournal>, body: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let (local_id, secret_id) = alice.enqueue_secret(body).expect("enqueue secret");
    let envelope = alice.encrypt(local_id).expect("encrypt");
    alice.mark_sent(local_id).expect("mark sent");
    (envelope, secret_id)
}

#[test]
fn secret_travels_sealed_then_reveals_once_then_expires() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    let (envelope, secret_id) = send_secret(&mut alice, b"the launch code is 0000");

    // Bob receives a SEALED placeholder — no body is returned on delivery.
    match bob.process_inbound(1, &envelope).expect("process") {
        InboundOutcome::SecretSealed { secret_id: id } => assert_eq!(id, secret_id),
        other => panic!("expected SecretSealed, got {other:?}"),
    }
    assert_eq!(
        bob.secret_state(&secret_id, 0).unwrap(),
        Some(SecretState::Sealed)
    );
    // Delivery alone must NOT reveal or start any timer.
    assert!(bob.secret_visible_body(&secret_id, 0).unwrap().is_none());
    assert!(bob
        .secret_visible_body(&secret_id, 999_999)
        .unwrap()
        .is_none());

    // Tap: begin reveal. Countdown for exactly 3s, then visible for exactly 10s.
    bob.begin_secret_reveal(&secret_id, 0).unwrap();
    assert_eq!(
        bob.secret_state(&secret_id, 2_999).unwrap(),
        Some(SecretState::Countdown)
    );
    assert!(bob
        .secret_visible_body(&secret_id, 2_999)
        .unwrap()
        .is_none());
    assert_eq!(
        bob.secret_state(&secret_id, 3_000).unwrap(),
        Some(SecretState::Visible)
    );
    assert_eq!(
        bob.secret_visible_body(&secret_id, 3_000)
            .unwrap()
            .as_deref(),
        Some(&b"the launch code is 0000"[..])
    );
    assert!(bob
        .secret_visible_body(&secret_id, 12_999)
        .unwrap()
        .is_some());
    // At 3+10s exactly: consumed, body gone, tombstone.
    assert_eq!(
        bob.secret_state(&secret_id, 13_000).unwrap(),
        Some(SecretState::Consumed)
    );
    assert!(bob
        .secret_visible_body(&secret_id, 13_000)
        .unwrap()
        .is_none());
    assert!(bob
        .secret_visible_body(&secret_id, 100_000)
        .unwrap()
        .is_none());
}

#[test]
fn classification_and_body_stay_inside_the_ciphertext() {
    // The relay sees only these envelope bytes. They must not contain the plaintext body, and a
    // secret must be shaped like any other opaque MLS application message (no "secret" marker the
    // relay could read).
    let (mut alice, _ja, _bob, _jb) = pair();
    let body = b"cleartext-should-never-appear";
    let (secret_env, _) = send_secret(&mut alice, body);
    assert!(
        !secret_env.windows(body.len()).any(|w| w == body),
        "plaintext body must not appear in the ciphertext the relay forwards"
    );

    // A normal message and a secret message are both just opaque MLS ciphertext at the relay.
    let nid = alice.enqueue(b"ordinary").expect("enqueue");
    let normal_env = alice.encrypt(nid).expect("encrypt");
    assert!(!normal_env.windows(8).any(|w| w == b"ordinary"));
}

#[test]
fn normal_and_secret_share_the_same_pipeline() {
    let (mut alice, _ja, mut bob, _jb) = pair();

    // A normal message is delivered as visible content immediately.
    let nid = alice.enqueue(b"hi bob").expect("enqueue");
    let normal_env = alice.encrypt(nid).expect("encrypt");
    assert_eq!(
        bob.process_inbound(1, &normal_env).unwrap(),
        InboundOutcome::Application(b"hi bob".to_vec())
    );

    // A secret arrives sealed. Both used the same authenticated MLS path; normal delivery is
    // unaffected by the secret.
    let (secret_env, sid) = send_secret(&mut alice, b"shh");
    assert!(matches!(
        bob.process_inbound(2, &secret_env).unwrap(),
        InboundOutcome::SecretSealed { .. }
    ));
    assert_eq!(
        bob.secret_state(&sid, 0).unwrap(),
        Some(SecretState::Sealed)
    );

    // A second normal message still flows normally while the secret sits sealed.
    let nid2 = alice.enqueue(b"still works").expect("enqueue");
    let normal_env2 = alice.encrypt(nid2).expect("encrypt");
    assert_eq!(
        bob.process_inbound(3, &normal_env2).unwrap(),
        InboundOutcome::Application(b"still works".to_vec())
    );
}

#[test]
fn sender_holds_only_a_tombstone_no_reopenable_copy() {
    let (mut alice, _ja, _bob, _jb) = pair();
    let (_env, sid) = send_secret(&mut alice, b"sender secret");
    // The sender's stored message carries the secret id but no body; its record is a tombstone.
    let msg = alice.messages().last().expect("a message");
    assert_eq!(msg.secret_id, Some(sid));
    assert!(msg.plaintext.is_empty(), "sender retains no plaintext");
    assert_eq!(
        alice.secret_state(&sid, 0).unwrap(),
        Some(SecretState::Consumed)
    );
    // The sender can never reveal it.
    assert!(alice.begin_secret_reveal(&sid, 0).is_err());
    assert!(alice.secret_visible_body(&sid, 0).unwrap().is_none());
}

#[test]
fn reveal_is_atomic_a_failed_state_write_does_not_reveal() {
    let (mut alice, _ja, mut bob, jb) = pair();
    let (env, sid) = send_secret(&mut alice, b"atomic");
    bob.process_inbound(1, &env).unwrap();

    // The next durable commit will fail — begin_reveal must return Err and NOT reveal. The
    // InMemoryJournal is Clone and shares its backing store, so `jb` (from `pair`) is Bob's journal.
    jb.fail_next_commit();
    assert!(
        bob.begin_secret_reveal(&sid, 0).is_err(),
        "fail-closed on state-write failure"
    );
    // State is unchanged — still sealed, never revealed.
    assert_eq!(
        bob.secret_state(&sid, 0).unwrap(),
        Some(SecretState::Sealed)
    );
    assert!(bob.secret_visible_body(&sid, 5_000).unwrap().is_none());
}

#[test]
fn crash_after_reveal_fails_closed_on_relaunch() {
    let (mut alice, _ja, mut bob, jb) = pair();
    let (env, sid) = send_secret(&mut alice, b"burn after reading");
    bob.process_inbound(1, &env).unwrap();
    bob.begin_secret_reveal(&sid, 0).unwrap();
    assert_eq!(
        bob.secret_state(&sid, 3_000).unwrap(),
        Some(SecretState::Visible)
    );

    // Simulate a crash mid-view: drop without a clean consume, reopen from the journal.
    drop(bob);
    let mut bob = DurableSession::open(jb).expect("reopen");
    // Fail closed: the message is consumed, never re-viewable, even well within the old window.
    assert_eq!(
        bob.secret_state(&sid, 3_500).unwrap(),
        Some(SecretState::Consumed)
    );
    assert!(bob.secret_visible_body(&sid, 3_500).unwrap().is_none());
}

#[test]
fn double_tap_grants_no_second_opportunity() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    let (env, sid) = send_secret(&mut alice, b"once");
    bob.process_inbound(1, &env).unwrap();
    bob.begin_secret_reveal(&sid, 0).unwrap();
    // A rapid second tap is rejected and cannot restart or extend the window.
    assert!(bob.begin_secret_reveal(&sid, 1_000).is_err());
    assert_eq!(
        bob.secret_state(&sid, 13_000).unwrap(),
        Some(SecretState::Consumed)
    );
}

#[test]
fn redelivery_and_mls_replay_are_rejected() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    let (env, sid) = send_secret(&mut alice, b"dup");

    assert!(matches!(
        bob.process_inbound(1, &env).unwrap(),
        InboundOutcome::SecretSealed { .. }
    ));
    // Same envelope id again → at-least-once dedup, a no-op (no second placeholder).
    assert_eq!(
        bob.process_inbound(1, &env).unwrap(),
        InboundOutcome::Duplicate
    );
    // Same ciphertext, NEW envelope id → MLS's own replay protection rejects it (the per-message
    // key is spent). Either way, exactly one sealed secret exists.
    assert!(bob.process_inbound(2, &env).is_err());
    assert_eq!(
        bob.secret_state(&sid, 0).unwrap(),
        Some(SecretState::Sealed)
    );
}

#[test]
fn multiple_secrets_are_independent_sealed_placeholders() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    let (e1, s1) = send_secret(&mut alice, b"first");
    let (e2, s2) = send_secret(&mut alice, b"second");
    bob.process_inbound(1, &e1).unwrap();
    bob.process_inbound(2, &e2).unwrap();

    // Reveal the first; the second stays sealed and untouched (no overlapping timers).
    bob.begin_secret_reveal(&s1, 0).unwrap();
    assert_eq!(
        bob.secret_state(&s1, 3_000).unwrap(),
        Some(SecretState::Visible)
    );
    assert_eq!(
        bob.secret_state(&s2, 3_000).unwrap(),
        Some(SecretState::Sealed)
    );

    // Later reveal the second independently.
    bob.begin_secret_reveal(&s2, 20_000).unwrap();
    assert_eq!(
        bob.secret_state(&s1, 23_000).unwrap(),
        Some(SecretState::Consumed)
    );
    assert_eq!(
        bob.secret_state(&s2, 23_000).unwrap(),
        Some(SecretState::Visible)
    );
}

#[test]
fn tombstone_text_is_the_exact_string() {
    assert_eq!(TOMBSTONE_TEXT, "a secret message has been sent");
    assert_eq!(
        DurableSession::<InMemoryJournal>::secret_tombstone_text(),
        "a secret message has been sent"
    );
}
