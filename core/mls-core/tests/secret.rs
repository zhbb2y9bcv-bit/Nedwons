//! Secret-message (view-once) end-to-end behavior at the durable layer: two real MLS clients
//! exchange a secret through the SAME authenticated pipeline as normal messages, the classification
//! and body stay inside the ciphertext (relay-blind), the reveal is atomic + fail-closed, expiry
//! scrubs and tombstones, and a crash after reveal fails closed on relaunch.

use mls_core::durable::{Direction, DurableSession, InMemoryJournal, InboundOutcome};
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

/// ADR-0015 account-wide single-consumption: the phone's reveal emits an E2EE `SecretConsumed`
/// that consumes the tablet's copy too; the sender's copy no-ops; the relay sees only opaque
/// ciphertext (asserted).
#[test]
fn revealing_on_one_device_consumes_it_on_the_other() {
    use mls_core::secret::SecretState;

    // Build a 3-member group at the MLS level: alice (sender) + phone + tablet (Bob's two devices).
    let alice = Member::new(b"alice-device").unwrap();
    let phone = Member::new(b"bob-phone").unwrap();
    let tablet = Member::new(b"bob-tablet").unwrap();
    let mut ga = alice.create_group().unwrap();
    let add_phone = ga
        .add_member(&alice, &phone.key_package_bytes().unwrap())
        .unwrap();
    let mut gp = phone.join_from_welcome(&add_phone.welcome).unwrap();
    let add_tablet = ga
        .add_member(&alice, &tablet.key_package_bytes().unwrap())
        .unwrap();
    gp.process(&phone, &add_tablet.commit).unwrap(); // phone advances to the tablet-add epoch
    let gt = tablet.join_from_welcome(&add_tablet.welcome).unwrap();

    let mut da = DurableSession::adopt(alice, ga, InMemoryJournal::new()).unwrap();
    let mut dp = DurableSession::adopt(phone, gp, InMemoryJournal::new()).unwrap();
    let mut dt = DurableSession::adopt(tablet, gt, InMemoryJournal::new()).unwrap();

    // Alice sends a secret; BOTH of Bob's devices receive it sealed.
    let (env, sid) = send_secret(&mut da, b"the vault code is 7788");
    assert!(
        !env.windows(4).any(|w| w == b"7788"),
        "relay sees only ciphertext"
    );
    assert!(matches!(
        dp.process_inbound(1, &env).unwrap(),
        InboundOutcome::SecretSealed { .. }
    ));
    assert!(matches!(
        dt.process_inbound(1, &env).unwrap(),
        InboundOutcome::SecretSealed { .. }
    ));
    assert_eq!(dt.secret_state(&sid, 0).unwrap(), Some(SecretState::Sealed));

    // The PHONE reveals it, then emits the consumption control message.
    dp.begin_secret_reveal(&sid, 0).unwrap();
    let cid = dp
        .emit_secret_consumption(&sid)
        .unwrap()
        .expect("a consumption message");
    // Idempotent: a second emit returns the same outbound id (no duplicate message).
    assert_eq!(dp.emit_secret_consumption(&sid).unwrap(), Some(cid));
    let consumption_env = dp.encrypt(cid).unwrap();
    assert!(!consumption_env.windows(4).any(|w| w == b"7788"));

    // Deliver it to the TABLET: it consumes its copy — account-wide single-view.
    assert!(matches!(
        dt.process_inbound(2, &consumption_env).unwrap(),
        InboundOutcome::SecretConsumedRemotely { secret_id } if secret_id == sid
    ));
    assert_eq!(
        dt.secret_state(&sid, 0).unwrap(),
        Some(SecretState::Consumed)
    );
    assert!(
        dt.secret_visible_body(&sid, 3_000).unwrap().is_none(),
        "tablet can never open it"
    );
    assert!(
        dt.begin_secret_reveal(&sid, 0).is_err(),
        "tablet reveal is refused"
    );

    // The phone (which opened first) still views it within its window — first device wins.
    assert_eq!(
        dp.secret_state(&sid, 3_000).unwrap(),
        Some(SecretState::Visible)
    );
    assert_eq!(
        dp.secret_visible_body(&sid, 3_000).unwrap().as_deref(),
        Some(&b"the vault code is 7788"[..])
    );

    // The SENDER receiving the consumption message is a harmless idempotent no-op (already tombstone).
    assert!(matches!(
        da.process_inbound(2, &consumption_env).unwrap(),
        InboundOutcome::SecretConsumedRemotely { .. }
    ));
    assert_eq!(
        da.secret_state(&sid, 0).unwrap(),
        Some(SecretState::Consumed)
    );
}

/// A device that never held a given secret (or hasn't revealed one) does not emit a consumption
/// message, and consuming an unknown secret id is a harmless no-op.
#[test]
fn emit_and_apply_consumption_are_safe_no_ops_when_not_applicable() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    let (env, sid) = send_secret(&mut alice, b"x");
    bob.process_inbound(1, &env).unwrap();
    // Not revealed yet → nothing to emit.
    assert_eq!(bob.emit_secret_consumption(&sid).unwrap(), None);
    // The sender never emits (its copy is the sender tombstone).
    assert_eq!(alice.emit_secret_consumption(&sid).unwrap(), None);
    // An unknown id → None.
    assert_eq!(bob.emit_secret_consumption(&[0xEE; 16]).unwrap(), None);
}

#[test]
fn tombstone_text_is_the_exact_string() {
    assert_eq!(TOMBSTONE_TEXT, "a secret message has been sent");
    assert_eq!(
        DurableSession::<InMemoryJournal>::secret_tombstone_text(),
        "a secret message has been sent"
    );
}

/// ADR-0015 option 3: the consumption message rides the self-group, which the sender is NOT a
/// member of — so the sender never receives, and cannot even decrypt, the read signal (the
/// improvement over option 2, where the sender learned of the open).
#[test]
fn consumption_syncs_over_the_self_group_without_the_sender_learning() {
    // Conversation group: alice (sender) + phone + tablet (Bob's two devices).
    let alice = Member::new(b"alice-device").unwrap();
    let phone = Member::new(b"bob-phone").unwrap();
    let tablet = Member::new(b"bob-tablet").unwrap();
    let mut ga = alice.create_group().unwrap();
    let add_phone = ga
        .add_member(&alice, &phone.key_package_bytes().unwrap())
        .unwrap();
    let mut gp = phone.join_from_welcome(&add_phone.welcome).unwrap();
    let add_tablet = ga
        .add_member(&alice, &tablet.key_package_bytes().unwrap())
        .unwrap();
    gp.process(&phone, &add_tablet.commit).unwrap();
    let gt = tablet.join_from_welcome(&add_tablet.welcome).unwrap();

    let mut da = DurableSession::adopt(alice, ga, InMemoryJournal::new()).unwrap();
    let mut dp = DurableSession::adopt(phone, gp, InMemoryJournal::new()).unwrap();
    let mut dt = DurableSession::adopt(tablet, gt, InMemoryJournal::new()).unwrap();

    // Bob's two devices form their OWN self-group. Alice is not, and cannot be, a member.
    dp.create_self_group().unwrap();
    let tablet_kp = dt.key_package().unwrap();
    let (_commit, welcome) = dp.add_self_device(&tablet_kp).unwrap();
    dt.join_self_group(&welcome).unwrap();
    assert!(dp.has_self_group() && dt.has_self_group());
    assert!(
        !da.has_self_group(),
        "the sender has no place in Bob's self-group"
    );

    // Alice sends a secret; both of Bob's devices receive it sealed (over the conversation).
    let (env, sid) = send_secret(&mut da, b"the vault code is 7788");
    assert!(matches!(
        dp.process_inbound(1, &env).unwrap(),
        InboundOutcome::SecretSealed { .. }
    ));
    assert!(matches!(
        dt.process_inbound(1, &env).unwrap(),
        InboundOutcome::SecretSealed { .. }
    ));

    // The phone reveals it and emits the consumption message — now routed over the SELF-GROUP.
    dp.begin_secret_reveal(&sid, 0).unwrap();
    let cid = dp
        .emit_secret_consumption(&sid)
        .unwrap()
        .expect("a consumption message");
    assert_eq!(
        dp.emit_secret_consumption(&sid).unwrap(),
        Some(cid),
        "idempotent"
    );
    let consumption_env = dp.encrypt(cid).unwrap();
    assert!(
        !consumption_env.windows(4).any(|w| w == b"7788"),
        "relay sees only opaque ciphertext"
    );

    // The tablet applies it over its self-group inbox and consumes its copy — it can never open it.
    assert!(matches!(
        dt.process_self_inbound(2, &consumption_env).unwrap(),
        InboundOutcome::SecretConsumedRemotely { secret_id } if secret_id == sid
    ));
    assert_eq!(
        dt.secret_state(&sid, 0).unwrap(),
        Some(SecretState::Consumed)
    );
    assert!(
        dt.begin_secret_reveal(&sid, 0).is_err(),
        "the tablet's reveal is refused after remote consumption"
    );

    // THE option-3 PROPERTY: the sender is not in the self-group, so the consumption message never
    // reaches her — and even handed the raw bytes she cannot decrypt them. The read stays private.
    assert!(
        da.process_inbound(2, &consumption_env).is_err(),
        "the sender cannot decrypt a message from a group she is not in"
    );

    // The phone (first to open) still views it within its own window — first device wins.
    assert_eq!(
        dp.secret_state(&sid, 3_000).unwrap(),
        Some(SecretState::Visible)
    );
    assert_eq!(
        dp.secret_visible_body(&sid, 3_000).unwrap().as_deref(),
        Some(&b"the vault code is 7788"[..])
    );
}

/// The self-group's ratchet state is captured by the same atomic blob as the conversation, so it is
/// reloaded on reopen (crash recovery) rather than lost.
#[test]
fn self_group_persists_across_reopen() {
    let alice = Member::new(b"solo-device").unwrap();
    let group = alice.create_group().unwrap();
    let journal = InMemoryJournal::new();
    let mut d = DurableSession::adopt(alice, group, journal.clone()).unwrap();
    assert!(!d.has_self_group());
    d.create_self_group().unwrap();
    assert!(d.has_self_group());
    // A second create is refused rather than orphaning the first group.
    assert!(d.create_self_group().is_err());
    drop(d);

    let d2 = DurableSession::open(journal).unwrap();
    assert!(
        d2.has_self_group(),
        "the self-group is reloaded from the persisted blob"
    );
}

/// #7: a newly-linked device starts with no conversation history (MLS does not backfill). An
/// existing device replicates its past messages to it over the self-group (E2EE, relay-blind), and
/// the new device's message log gains them in order — with secrets excluded (view-once).
#[test]
fn history_syncs_to_a_newly_linked_device_over_the_self_group() {
    let (mut alice, _ja, mut phone, _jp) = pair();
    // Alice sends two normal messages + one secret; phone receives all three.
    for (i, body) in [b"hello one".as_slice(), b"hello two".as_slice()]
        .iter()
        .enumerate()
    {
        let id = alice.enqueue(body).unwrap();
        let env = alice.encrypt(id).unwrap();
        assert!(matches!(
            phone.process_inbound((i + 1) as u64, &env).unwrap(),
            InboundOutcome::Application(_)
        ));
    }
    let (secret_env, _sid) = send_secret(&mut alice, b"view once only");
    assert!(matches!(
        phone.process_inbound(3, &secret_env).unwrap(),
        InboundOutcome::SecretSealed { .. }
    ));

    // Link a tablet into phone's self-group (it holds its own durable session so it is Active).
    let tablet_member = Member::new(b"bob-tablet").unwrap();
    let tablet_group = tablet_member.create_group().unwrap();
    let mut tablet =
        DurableSession::adopt(tablet_member, tablet_group, InMemoryJournal::new()).unwrap();
    phone.create_self_group().unwrap();
    let (_c, w) = phone
        .add_self_device(&tablet.key_package().unwrap())
        .unwrap();
    tablet.join_self_group(&w).unwrap();
    assert!(
        tablet.messages().is_empty(),
        "a newly-linked device starts with no history"
    );

    // Phone replicates its non-secret history to the tablet over the self-group.
    let entries = phone.history_entries(100);
    assert_eq!(entries.len(), 2, "the secret is excluded from history");
    let sync_id = phone.enqueue_history_sync(entries).unwrap();
    let sync_env = phone.encrypt(sync_id).unwrap();
    assert!(
        !sync_env.windows(9).any(|w| w == b"hello one"),
        "the relay sees only opaque ciphertext"
    );
    match tablet.process_self_inbound(50, &sync_env).unwrap() {
        InboundOutcome::HistorySynced { count } => assert_eq!(count, 2),
        other => panic!("expected HistorySynced, got {other:?}"),
    }
    // The tablet now holds the two messages, in order, with the right direction (received).
    let msgs = tablet.messages();
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0].plaintext, b"hello one");
    assert_eq!(msgs[1].plaintext, b"hello two");
    assert!(msgs.iter().all(|m| m.direction == Direction::Inbound));
}

/// ADR-0014 Slice 2c: an approved contact's sealed-sender delivery key `K_r` is distributed over the
/// E2EE channel — the relay never sees it — and surfaced to the recipient to store (no message-log
/// entry, since it is a control message, not user content).
#[test]
fn delivery_key_grant_travels_e2ee_and_is_surfaced() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    let key_r = [0x7cu8; 32];

    let local_id = alice.enqueue_delivery_key_grant(&key_r).unwrap();
    let env = alice.encrypt(local_id).unwrap();
    alice.mark_sent(local_id).unwrap();

    // The relay-visible ciphertext does not contain K_r.
    assert!(
        !env.windows(32).any(|w| w == key_r),
        "K_r must not appear in the ciphertext the relay forwards"
    );
    // It is NOT a user-visible message on the sender (a control message, no message-log entry).
    assert!(
        alice.messages().is_empty(),
        "the grant creates no message on the sender"
    );

    match bob.process_inbound(1, &env).unwrap() {
        InboundOutcome::DeliveryKeyGranted { key_r: got } => assert_eq!(got, key_r),
        other => panic!("expected DeliveryKeyGranted, got {other:?}"),
    }
    // The grant is a control message — it does not appear in Bob's message log.
    assert!(
        bob.messages().is_empty(),
        "a delivery-key grant is not a user-visible message"
    );
}

/// Three-device self-group lifecycle: adding the third device commits to the existing member; a
/// consumption fans out to BOTH others; and after the laptop is REVOKED via an MLS remove-commit it
/// cannot decrypt later self-group traffic — cryptographic forward secrecy, not relay exclusion.
#[test]
fn three_device_self_group_fans_out_then_revocation_rekeys() {
    // Conversation: alice (sender) + phone + tablet + laptop (Bob's three devices).
    let alice = Member::new(b"alice-dev").unwrap();
    let phone = Member::new(b"bob-phone").unwrap();
    let tablet = Member::new(b"bob-tablet").unwrap();
    let laptop = Member::new(b"bob-laptop").unwrap();
    let mut ga = alice.create_group().unwrap();
    let add_phone = ga
        .add_member(&alice, &phone.key_package_bytes().unwrap())
        .unwrap();
    let mut gp = phone.join_from_welcome(&add_phone.welcome).unwrap();
    let add_tablet = ga
        .add_member(&alice, &tablet.key_package_bytes().unwrap())
        .unwrap();
    gp.process(&phone, &add_tablet.commit).unwrap();
    let mut gt = tablet.join_from_welcome(&add_tablet.welcome).unwrap();
    let add_laptop = ga
        .add_member(&alice, &laptop.key_package_bytes().unwrap())
        .unwrap();
    gp.process(&phone, &add_laptop.commit).unwrap();
    gt.process(&tablet, &add_laptop.commit).unwrap();
    let gl = laptop.join_from_welcome(&add_laptop.welcome).unwrap();

    let mut da = DurableSession::adopt(alice, ga, InMemoryJournal::new()).unwrap();
    let mut dp = DurableSession::adopt(phone, gp, InMemoryJournal::new()).unwrap();
    let mut dt = DurableSession::adopt(tablet, gt, InMemoryJournal::new()).unwrap();
    let mut dl = DurableSession::adopt(laptop, gl, InMemoryJournal::new()).unwrap();

    // The self-group of all THREE devices: phone creates it, adds tablet, then adds laptop — the
    // laptop-add commit must be applied by the existing self-group member (tablet).
    dp.create_self_group().unwrap();
    let (_c_tablet, w_tablet) = dp.add_self_device(&dt.key_package().unwrap()).unwrap();
    dt.join_self_group(&w_tablet).unwrap();
    let (c_laptop, w_laptop) = dp.add_self_device(&dl.key_package().unwrap()).unwrap();
    assert!(matches!(
        dt.process_self_inbound(100, &c_laptop).unwrap(),
        InboundOutcome::StateAdvanced
    ));
    dl.join_self_group(&w_laptop).unwrap();
    assert!(dp.has_self_group() && dt.has_self_group() && dl.has_self_group());

    // Alice sends secret #1; all three of Bob's devices seal it.
    let (env1, sid1) = send_secret(&mut da, b"first-secret-1111");
    for (d, id) in [(&mut dp, 1u64), (&mut dt, 1), (&mut dl, 1)] {
        assert!(matches!(
            d.process_inbound(id, &env1).unwrap(),
            InboundOutcome::SecretSealed { .. }
        ));
    }

    // Phone reveals #1; the consumption fans out over the self-group to BOTH tablet and laptop,
    // each consuming its OWN held copy — account-wide single-view across three devices.
    dp.begin_secret_reveal(&sid1, 0).unwrap();
    let cid1 = dp
        .emit_secret_consumption(&sid1)
        .unwrap()
        .expect("consume1");
    let consume1 = dp.encrypt(cid1).unwrap();
    assert!(matches!(
        dt.process_self_inbound(101, &consume1).unwrap(),
        InboundOutcome::SecretConsumedRemotely { secret_id } if secret_id == sid1
    ));
    assert!(matches!(
        dl.process_self_inbound(101, &consume1).unwrap(),
        InboundOutcome::SecretConsumedRemotely { secret_id } if secret_id == sid1
    ));
    assert_eq!(
        dt.secret_state(&sid1, 0).unwrap(),
        Some(SecretState::Consumed)
    );
    assert_eq!(
        dl.secret_state(&sid1, 0).unwrap(),
        Some(SecretState::Consumed)
    );

    // --- Revocation re-key: the laptop is revoked from the account. An existing device removes it
    // from the self-group (MLS remove-commit); the remaining member (tablet) applies it. ---
    let remove_commit = dp.remove_self_device(b"bob-laptop").unwrap();
    assert!(matches!(
        dt.process_self_inbound(102, &remove_commit).unwrap(),
        InboundOutcome::StateAdvanced
    ));

    // Alice sends secret #2; conversation membership is unchanged, so all three still seal a copy.
    let (env2, sid2) = send_secret(&mut da, b"second-secret-2222");
    for (d, id) in [(&mut dp, 2u64), (&mut dt, 2), (&mut dl, 2)] {
        assert!(matches!(
            d.process_inbound(id, &env2).unwrap(),
            InboundOutcome::SecretSealed { .. }
        ));
    }

    // Phone reveals #2; the consumption goes out on the NEW self-group epoch (phone + tablet only).
    dp.begin_secret_reveal(&sid2, 0).unwrap();
    let cid2 = dp
        .emit_secret_consumption(&sid2)
        .unwrap()
        .expect("consume2");
    let consume2 = dp.encrypt(cid2).unwrap();
    // Tablet (still a member) consumes its #2 copy.
    assert!(matches!(
        dt.process_self_inbound(103, &consume2).unwrap(),
        InboundOutcome::SecretConsumedRemotely { secret_id } if secret_id == sid2
    ));
    assert_eq!(
        dt.secret_state(&sid2, 0).unwrap(),
        Some(SecretState::Consumed)
    );

    // FORWARD SECRECY: the revoked laptop, even handed the exact ciphertext, CANNOT decrypt the
    // post-revocation self-group message — so its #2 copy is never consumed by the removed device.
    assert!(
        dl.process_self_inbound(103, &consume2).is_err(),
        "a removed device cannot decrypt self-group traffic sent after its removal"
    );
    assert_eq!(
        dl.secret_state(&sid2, 0).unwrap(),
        Some(SecretState::Sealed),
        "no valid consumption reached the removed device"
    );
}
