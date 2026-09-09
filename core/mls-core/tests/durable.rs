//! Gate 2 crash-safety: ratchet and message state advance together, redelivery is idempotent, a
//! failed commit leaves NO partial advance, a retry never re-encrypts, and MLS state survives
//! relaunch — proven by exchanging a message *after* both sides reopen from their journals.

use mls_core::durable::{Direction, DurableError, DurableSession, InMemoryJournal, InboundOutcome};
use mls_core::Member;

/// Two durable sessions in one group, plus a shared clone of each journal for "relaunch".
fn pair() -> (
    DurableSession<InMemoryJournal>,
    InMemoryJournal,
    DurableSession<InMemoryJournal>,
    InMemoryJournal,
) {
    // Bob's key package + join must share one provider, so add at the low level and adopt both.
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

/// Happy path + durability: a message survives reopening the receiver from its journal.
#[test]
fn message_round_trip_survives_reopen() {
    let (mut alice, _ja, mut bob, jb) = pair();

    let id = alice.enqueue(b"hello-bob").expect("enqueue");
    let envelope = alice.encrypt(id).expect("encrypt");

    assert_eq!(
        bob.process_inbound(1, &envelope).expect("process"),
        InboundOutcome::Application(b"hello-bob".to_vec())
    );

    // Relaunch Bob from his journal: the decrypted message and ack-eligibility are durable.
    drop(bob);
    let bob = DurableSession::open(jb).expect("reopen bob");
    assert_eq!(bob.messages().len(), 1);
    assert_eq!(bob.messages()[0].plaintext, b"hello-bob");
    assert_eq!(bob.messages()[0].direction, Direction::Inbound);
    assert_eq!(bob.ack_eligible(), vec![1]);
}

/// At-least-once redelivery is idempotent: the same envelope id processed twice yields one message.
#[test]
fn duplicate_envelope_is_idempotent() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    let id = alice.enqueue(b"hi").expect("enqueue");
    let envelope = alice.encrypt(id).expect("encrypt");

    assert!(matches!(
        bob.process_inbound(7, &envelope).expect("first"),
        InboundOutcome::Application(_)
    ));
    // Redelivery of the same id short-circuits before MLS — a durable no-op, no second message.
    assert_eq!(
        bob.process_inbound(7, &envelope).expect("redelivery"),
        InboundOutcome::Duplicate
    );
    assert_eq!(bob.messages().len(), 1);
}

/// The core crash-safety property: if the commit fails (crash before the write lands), NOTHING is
/// half-applied. The ratchet does not advance without the message; the envelope stays unprocessed
/// and is safely reprocessed on redelivery — exactly once.
#[test]
fn failed_commit_leaves_no_partial_advance() {
    let (mut alice, _ja, mut bob, jb) = pair();
    let id = alice.enqueue(b"once").expect("enqueue");
    let envelope = alice.encrypt(id).expect("encrypt");

    jb.fail_next_commit();
    assert_eq!(
        bob.process_inbound(5, &envelope),
        Err(DurableError::Journal),
        "commit failed, so process must report the error"
    );

    // Per the recovery contract, discard the session and reopen from the last durable state.
    drop(bob);
    let mut bob = DurableSession::open(jb).expect("reopen after crash");
    assert_eq!(bob.messages().len(), 0, "no message was durably recorded");
    assert!(bob.ack_eligible().is_empty(), "nothing became ack-eligible");

    // The server redelivers (it was never acked); now it processes exactly once.
    assert!(matches!(
        bob.process_inbound(5, &envelope).expect("reprocess"),
        InboundOutcome::Application(_)
    ));
    assert_eq!(bob.messages().len(), 1);
}

/// Outbound retry must never re-encrypt: the cached ciphertext is returned, so a message key is
/// never double-spent and the receiver sees one message.
#[test]
fn outbound_retry_never_reencrypts() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    let id = alice.enqueue(b"retry-me").expect("enqueue");

    let first = alice.encrypt(id).expect("encrypt");
    let retry = alice.encrypt(id).expect("retry");
    assert_eq!(
        first, retry,
        "retry must return the cached ciphertext, not re-encrypt"
    );

    // Exactly one outbound message was logged despite two encrypt calls.
    let outbound = alice
        .messages()
        .iter()
        .filter(|m| m.direction == Direction::Outbound)
        .count();
    assert_eq!(outbound, 1);

    // And it decrypts to the original exactly once.
    assert!(matches!(
        bob.process_inbound(1, &first).expect("process"),
        InboundOutcome::Application(p) if p == b"retry-me"
    ));
}

/// MLS ratchet state genuinely survives serialize→restore: after BOTH sides relaunch from their
/// journals, a fresh message still encrypts and decrypts.
#[test]
fn ratchet_survives_relaunch() {
    let (mut alice, ja, mut bob, jb) = pair();

    let id1 = alice.enqueue(b"one").expect("enqueue");
    let ct1 = alice.encrypt(id1).expect("encrypt one");
    assert!(matches!(
        bob.process_inbound(1, &ct1).expect("process one"),
        InboundOutcome::Application(p) if p == b"one"
    ));

    // Relaunch both from disk.
    drop(alice);
    drop(bob);
    let mut alice = DurableSession::open(ja).expect("reopen alice");
    let mut bob = DurableSession::open(jb).expect("reopen bob");

    // A second message, sent entirely from reloaded state.
    let id2 = alice.enqueue(b"two").expect("enqueue two");
    let ct2 = alice.encrypt(id2).expect("encrypt two");
    assert!(matches!(
        bob.process_inbound(2, &ct2).expect("process two"),
        InboundOutcome::Application(p) if p == b"two"
    ));
}

/// Out-of-order delivery: the network/queue may deliver later messages first. Both must still
/// decrypt (MLS tolerates in-epoch reordering; the durable layer must not break that).
#[test]
fn out_of_order_application_messages_decrypt() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    let id1 = alice.enqueue(b"first").expect("enqueue 1");
    let ct1 = alice.encrypt(id1).expect("encrypt 1");
    let id2 = alice.enqueue(b"second").expect("enqueue 2");
    let ct2 = alice.encrypt(id2).expect("encrypt 2");

    // Bob receives them reversed.
    assert!(matches!(
        bob.process_inbound(2, &ct2).expect("process 2 first"),
        InboundOutcome::Application(p) if p == b"second"
    ));
    assert!(matches!(
        bob.process_inbound(1, &ct1).expect("process 1 second"),
        InboundOutcome::Application(p) if p == b"first"
    ));
    assert_eq!(bob.messages().len(), 2);
}

/// Out-of-order delivery that also straddles a crash: process the later message, relaunch, then
/// the earlier one still decrypts — the secret-tree state that permits reordering is durable.
#[test]
fn out_of_order_across_relaunch() {
    let (mut alice, _ja, mut bob, jb) = pair();
    let id1 = alice.enqueue(b"first").expect("enqueue 1");
    let ct1 = alice.encrypt(id1).expect("encrypt 1");
    let id2 = alice.enqueue(b"second").expect("enqueue 2");
    let ct2 = alice.encrypt(id2).expect("encrypt 2");

    assert!(matches!(
        bob.process_inbound(2, &ct2).expect("process 2"),
        InboundOutcome::Application(p) if p == b"second"
    ));

    drop(bob);
    let mut bob = DurableSession::open(jb).expect("reopen bob");

    assert!(matches!(
        bob.process_inbound(1, &ct1).expect("process 1 after relaunch"),
        InboundOutcome::Application(p) if p == b"first"
    ));
    assert_eq!(bob.messages().len(), 2);
}

/// Deleting a conversation clears what the user sees WITHOUT touching the ratchet: after wiping the
/// log, a brand-new message from the peer still decrypts, and the deleted history stays gone.
#[test]
fn clear_visible_history_preserves_decryption() {
    let (mut alice, _ja, mut bob, _jb) = pair();

    let id = alice.enqueue(b"before-delete").expect("enqueue");
    let ct = alice.encrypt(id).expect("encrypt");
    bob.process_inbound(1, &ct).expect("process");
    assert_eq!(bob.messages().len(), 1);

    bob.clear_visible_history().expect("clear");
    assert!(bob.messages().is_empty());

    // The thread returns on the next legitimate message, carrying only post-deletion content.
    let id2 = alice.enqueue(b"after-delete").expect("enqueue 2");
    let ct2 = alice.encrypt(id2).expect("encrypt 2");
    assert_eq!(
        bob.process_inbound(2, &ct2).expect("decrypt after clear"),
        InboundOutcome::Application(b"after-delete".to_vec())
    );
    assert_eq!(bob.messages().len(), 1);
    assert_eq!(bob.messages()[0].plaintext, b"after-delete");
}

/// Clearing history must not reopen the replay window: an envelope id already processed before the
/// delete is still rejected as a duplicate afterwards.
#[test]
fn clear_visible_history_keeps_replay_protection() {
    let (mut alice, _ja, mut bob, jb) = pair();

    let id = alice.enqueue(b"replay-me").expect("enqueue");
    let ct = alice.encrypt(id).expect("encrypt");
    bob.process_inbound(7, &ct).expect("first delivery");

    bob.clear_visible_history().expect("clear");

    assert_eq!(
        bob.process_inbound(7, &ct).expect("replayed"),
        InboundOutcome::Duplicate,
        "dedup state must survive a history delete"
    );
    assert!(
        bob.messages().is_empty(),
        "a replay must not resurrect history"
    );

    // And the erasure is durable across relaunch.
    drop(bob);
    let bob = DurableSession::open(jb).expect("reopen");
    assert!(bob.messages().is_empty());
}

/// The retry set: a queued or encrypted message is "unsent" until `mark_sent`, and it survives a
/// reopen — which is what lets a relaunch resume an interrupted upload with the SAME ciphertext.
#[test]
fn unsent_outbound_tracks_the_upload_lifecycle_across_reopen() {
    let (mut alice, ja, _bob, _jb) = pair();
    assert!(alice.unsent_outbound().is_empty());

    let queued = alice.enqueue(b"one").expect("enqueue");
    let encrypted = alice.enqueue(b"two").expect("enqueue");
    let sent = alice.enqueue(b"three").expect("enqueue");
    let bytes = alice.encrypt(encrypted).expect("encrypt");
    let sent_bytes = alice.encrypt(sent).expect("encrypt");
    alice.mark_sent(sent).expect("mark sent");
    assert_eq!(alice.unsent_outbound(), vec![queued, encrypted]);

    // Reopen: the set is durable, and the encrypted entry replays byte-identically.
    drop(alice);
    let mut reopened = DurableSession::open(ja).expect("reopen alice");
    assert_eq!(reopened.unsent_outbound(), vec![queued, encrypted]);
    assert_eq!(reopened.encrypt(encrypted).expect("retry"), bytes);
    assert_ne!(bytes, sent_bytes);
    reopened.mark_sent(encrypted).expect("mark sent");
    assert_eq!(reopened.unsent_outbound(), vec![queued]);
}

/// A joiner's prekeys must survive a relaunch: the common case is a group created for you while
/// the app is closed. The pending blob is committed on creation and after every key package.
#[test]
fn pending_identity_redeems_a_prekey_after_reopen() {
    use mls_core::durable::{PendingIdentity, PendingJoinError};
    let jb = InMemoryJournal::new();
    let mut bob = PendingIdentity::create(b"bob-device", jb.clone()).expect("create pending");
    let kp = bob.key_package().expect("key package");
    drop(bob);

    // Alice adds Bob with the prekey while Bob's process is "dead".
    let alice = Member::new(b"alice-device").expect("alice");
    let mut alice_group = alice.create_group().expect("group");
    let add = alice_group.add_member(&alice, &kp).expect("add bob");

    // Bob relaunches from the journal — still pending, still holding the private key — and joins.
    let bob = PendingIdentity::open(jb.clone()).expect("reopen pending");
    assert_eq!(bob.identity(), b"bob-device");
    // A Welcome for someone else is refused and hands the identity back intact.
    let stranger = Member::new(b"stranger").expect("stranger");
    let stranger_kp = stranger.key_package_bytes().expect("kp");
    let other = alice_group
        .add_member(&alice, &stranger_kp)
        .expect("add stranger");
    let bob = match bob.join(&other.welcome) {
        Err(PendingJoinError::BadWelcome(bob, _)) => *bob,
        _ => panic!("a Welcome for another identity must be refused"),
    };
    let bob_session = bob.join(&add.welcome).expect("join with the right welcome");
    drop(bob_session);

    // The blob is now an Active session: the pending loader refuses it, the session loader works.
    assert!(matches!(
        PendingIdentity::open(jb.clone()),
        Err(mls_core::durable::DurableError::Codec)
    ));
    DurableSession::open(jb).expect("active session persisted");
}
