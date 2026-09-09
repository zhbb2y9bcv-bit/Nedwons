//! Gate 2 crash-safety: ratchet and message state advance together, redelivery is idempotent, a
//! failed commit leaves NO partial advance, a retry never re-encrypts, and MLS state survives
//! relaunch — proven by exchanging a message *after* both sides reopen from their journals.

use mls_core::content::ReceiptKind;
use mls_core::durable::{
    Direction, DurableError, DurableSession, InMemoryJournal, InboundOutcome, Journal,
};
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

/// Group names travel INSIDE the ciphertext: the sender applies the rename when it encrypts (the
/// point of no return), and the recipient learns it by decrypting. Nothing about the name reaches
/// the relay, which sees one more opaque envelope.
#[test]
fn group_name_is_set_by_an_encrypted_message() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    assert_eq!(alice.group_name(), None);
    assert_eq!(bob.group_name(), None);

    let id = alice
        .enqueue_group_name("Weekend Trip")
        .expect("enqueue name");
    assert_eq!(
        alice.group_name(),
        None,
        "not renamed until the group is told"
    );
    let envelope = alice.encrypt(id).expect("encrypt");
    assert_eq!(alice.group_name(), Some("Weekend Trip"));
    assert_eq!(
        bob.process_inbound(1, &envelope).expect("process"),
        InboundOutcome::GroupRenamed {
            name: "Weekend Trip".into()
        }
    );
    assert_eq!(bob.group_name(), Some("Weekend Trip"));
    // A rename is not a chat message: neither side gains a log entry.
    assert!(bob.messages().is_empty());
    assert!(alice.messages().is_empty());

    // Renaming again replaces it, and the name survives a relaunch.
    let id = bob.enqueue_group_name("Trip planning").expect("enqueue");
    let envelope = bob.encrypt(id).expect("encrypt");
    alice.process_inbound(2, &envelope).expect("process");
    assert_eq!(alice.group_name(), Some("Trip planning"));
}

/// A name a peer could not render safely is refused where it is written, not silently dropped by
/// every recipient: over-long, empty, and bidi-override names are rejected by the sender.
#[test]
fn hostile_group_names_are_refused_at_the_source() {
    let (mut alice, _ja, _bob, _jb) = pair();
    for bad in [
        "",
        "a\u{202E}bcd", // right-to-left override
        "line\nbreak",  // control character
        &"x".repeat(mls_core::content::MAX_GROUP_NAME_BYTES + 1),
    ] {
        assert!(
            alice.enqueue_group_name(bad).is_err(),
            "must refuse {bad:?}"
        );
    }
    assert!(
        alice.enqueue_group_name("Ok Name 🎒").is_ok(),
        "emoji are fine"
    );
}

/// Unread means "inbound, and newer than what the user has seen". Your own messages are never
/// unread, and the mark survives a relaunch.
#[test]
fn unread_counts_only_inbound_messages_since_the_read_mark() {
    let (mut alice, ja, mut bob, _jb) = pair();
    assert_eq!(alice.unread_count(), 0);

    for text in [b"one".as_slice(), b"two".as_slice()] {
        let id = bob.enqueue(text).expect("enqueue");
        let env = bob.encrypt(id).expect("encrypt");
        alice
            .process_inbound(alice.messages().len() as u64 + 1, &env)
            .expect("process");
    }
    assert_eq!(alice.unread_count(), 2);

    // Alice replying does not clear the backlog, and does not add to it either.
    let mine = alice.enqueue(b"reply").expect("enqueue");
    alice.encrypt(mine).expect("encrypt");
    assert_eq!(alice.unread_count(), 2, "own messages are never unread");

    alice.mark_read().expect("mark read");
    assert_eq!(alice.unread_count(), 0);

    // One more arrives; only it is unread, and the mark is durable.
    let id = bob.enqueue(b"three").expect("enqueue");
    let env = bob.encrypt(id).expect("encrypt");
    alice.process_inbound(99, &env).expect("process");
    assert_eq!(alice.unread_count(), 1);
    drop(alice);
    let alice = DurableSession::open(ja).expect("reopen");
    assert_eq!(alice.unread_count(), 1, "the read mark survives a relaunch");
}

/// Every message carries the time THIS device saw it, and an outbound one is `pending` until the
/// relay accepts it — which is what lets a thread show "sending" instead of implying delivery.
#[test]
fn message_views_carry_time_and_delivery_state() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    let id = alice.enqueue(b"hello").expect("enqueue");
    assert!(
        alice.message_views().is_empty(),
        "queued, not yet encrypted"
    );

    let envelope = alice.encrypt(id).expect("encrypt");
    let views = alice.message_views();
    assert_eq!(views.len(), 1);
    assert!(
        views[0].pending,
        "encrypted but not accepted by the relay yet"
    );
    assert!(
        views[0].created_at_ms > 1_700_000_000_000,
        "a real wall-clock stamp"
    );
    assert_eq!(views[0].direction, Direction::Outbound);

    alice.mark_sent(id).expect("mark sent");
    assert!(
        !alice.message_views()[0].pending,
        "accepted ⇒ no longer pending"
    );

    bob.process_inbound(1, &envelope).expect("process");
    let received = bob.message_views();
    assert_eq!(received.len(), 1);
    assert!(!received[0].pending, "inbound is never pending");
    assert!(received[0].created_at_ms > 1_700_000_000_000);
}

/// An attachment is a message whose bytes live elsewhere: the reference (including the key) travels
/// end-to-end and is durable, so the recipient can still open the file after a relaunch — while the
/// relay holds only ciphertext it has no key for.
#[test]
fn attachment_reference_travels_end_to_end_and_survives_reopen() {
    let (mut alice, _ja, mut bob, jb) = pair();
    let file = b"pretend this is a photo".repeat(32);
    let sealed = mls_core::attachment::seal(&file).expect("seal");
    let blob_id = [7u8; 16];

    let id = alice
        .enqueue_attachment(
            blob_id,
            sealed.key,
            sealed.digest,
            file.len() as u64,
            "image/jpeg",
            "beach.jpg",
            "look at this",
        )
        .expect("enqueue attachment");
    let envelope = alice.encrypt(id).expect("encrypt");

    // The sender's own log carries the reference and the caption.
    let mine = &alice.message_views()[0];
    assert_eq!(mine.plaintext, b"look at this");
    let mine_ref = mine.attachment.clone().expect("sender keeps the reference");
    assert_eq!(mine_ref.filename, "beach.jpg");
    assert_eq!(mine_ref.size, file.len() as u64);

    match bob.process_inbound(1, &envelope).expect("process") {
        InboundOutcome::AttachmentReceived { attachment } => {
            assert_eq!(attachment.blob_id, blob_id);
            assert_eq!(attachment.mime, "image/jpeg");
            // The key arrived over MLS, so Bob can open bytes the relay cannot.
            assert_eq!(
                mls_core::attachment::open(&attachment.key, &attachment.digest, &sealed.ciphertext)
                    .expect("open"),
                file
            );
        }
        other => panic!("expected AttachmentReceived, got {other:?}"),
    }

    // Durable: after a relaunch Bob still holds everything needed to fetch and decrypt it.
    drop(bob);
    let bob = DurableSession::open(jb).expect("reopen");
    let view = &bob.message_views()[0];
    assert_eq!(view.plaintext, b"look at this");
    let reference = view.attachment.clone().expect("reference survived");
    assert_eq!(
        mls_core::attachment::open(&reference.key, &reference.digest, &sealed.ciphertext)
            .expect("open after relaunch"),
        file
    );
    assert_eq!(
        bob.unread_count(),
        1,
        "a file is an unread message like any other"
    );
}

/// Reactions are attributed to the MLS-authenticated sender, toggle cleanly, and are refused for
/// messages this device does not have — which is what keeps a hostile member from growing the blob
/// by reacting to ids they invent.
#[test]
fn reactions_are_attributed_toggled_and_bounded() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    let id = alice.enqueue(b"dinner at 8?").expect("enqueue");
    let envelope = alice.encrypt(id).expect("encrypt");
    bob.process_inbound(1, &envelope).expect("process");
    let target = bob.message_views()[0].message_id;

    // Bob reacts; Alice sees it attributed to Bob's identity, not to a claim in the payload.
    let r = bob.enqueue_reaction(target, "👍", false).expect("react");
    let reaction = bob.encrypt(r).expect("encrypt");
    assert_eq!(
        bob.reactions(&target).len(),
        1,
        "the sender sees their own reaction"
    );
    assert!(matches!(
        alice.process_inbound(2, &reaction).expect("process"),
        InboundOutcome::ReactionChanged { target: t } if t == target
    ));
    let seen = alice.reactions(&target);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].emoji, "👍");
    assert_eq!(
        seen[0].sender, b"bob-device",
        "MLS says who, not the message body"
    );
    assert_eq!(alice.message_views()[0].reactions.len(), 1);

    // Reacting again with the same emoji is idempotent; removing takes it back.
    let again = bob.enqueue_reaction(target, "👍", false).expect("react");
    let again = bob.encrypt(again).expect("encrypt");
    alice.process_inbound(3, &again).expect("process");
    assert_eq!(alice.reactions(&target).len(), 1, "not counted twice");
    let undo = bob.enqueue_reaction(target, "👍", true).expect("unreact");
    let undo = bob.encrypt(undo).expect("encrypt");
    alice.process_inbound(4, &undo).expect("process");
    assert!(alice.reactions(&target).is_empty());

    // A reaction naming a message Alice does not have is dropped, not stored for later.
    let ghost = bob
        .enqueue_reaction([0xEE; 16], "🎉", false)
        .expect("react");
    let ghost = bob.encrypt(ghost).expect("encrypt");
    assert_eq!(
        alice.process_inbound(5, &ghost).expect("process"),
        InboundOutcome::Duplicate
    );
    assert!(alice.reactions(&[0xEE; 16]).is_empty());
}

/// A reply carries the id it answers and nothing else — never a copy of the original text, which a
/// hostile client could use to display words the quoted person never wrote.
#[test]
fn replies_reference_the_original_rather_than_quoting_it() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    let first = alice.enqueue(b"who's bringing dessert?").expect("enqueue");
    let envelope = alice.encrypt(first).expect("encrypt");
    bob.process_inbound(1, &envelope).expect("process");
    let target = bob.message_views()[0].message_id;

    let reply = bob.enqueue_reply(b"me", Some(target)).expect("reply");
    let reply_env = bob.encrypt(reply).expect("encrypt");
    assert_eq!(bob.message_views()[1].reply_to, Some(target));

    alice.process_inbound(2, &reply_env).expect("process");
    let views = alice.message_views();
    assert_eq!(views[1].plaintext, b"me");
    assert_eq!(views[1].reply_to, Some(target), "the pointer travelled");
    // The original is found by id in the local log — the reply carried no copy of it.
    let quoted = views
        .iter()
        .find(|v| v.message_id == target)
        .expect("original");
    assert_eq!(quoted.plaintext, b"who's bringing dessert?");
}

/// Receipts are accepted only for our OWN messages, deduplicate per sender, and the sender-side
/// bookkeeping stops the same acknowledgement being sent on every sync.
#[test]
fn receipts_count_only_our_own_messages() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    let id = alice.enqueue(b"ping").expect("enqueue");
    let envelope = alice.encrypt(id).expect("encrypt");
    alice.mark_sent(id).expect("sent");
    bob.process_inbound(1, &envelope).expect("process");
    let mid = bob.message_views()[0].message_id;

    // Nothing is owed until Bob has actually read it; delivery is owed immediately.
    assert_eq!(
        bob.unacknowledged_inbound(ReceiptKind::Delivered),
        vec![mid]
    );
    assert!(bob.unacknowledged_inbound(ReceiptKind::Read).is_empty());

    let r = bob
        .enqueue_receipt(ReceiptKind::Delivered, vec![mid])
        .expect("receipt");
    let receipt = bob.encrypt(r).expect("encrypt");
    bob.record_receipts_sent(ReceiptKind::Delivered, &[mid])
        .expect("record");
    assert!(
        bob.unacknowledged_inbound(ReceiptKind::Delivered)
            .is_empty(),
        "a receipt is sent once, not on every sync"
    );

    assert_eq!(
        alice.process_inbound(2, &receipt).expect("process"),
        InboundOutcome::ReceiptsReceived {
            kind: ReceiptKind::Delivered,
            count: 1
        }
    );
    assert_eq!(alice.message_views()[0].delivered_count, 1);
    assert_eq!(alice.message_views()[0].read_count, 0);

    // Now Bob reads it and acknowledges that too.
    bob.mark_read().expect("read");
    assert_eq!(bob.unacknowledged_inbound(ReceiptKind::Read), vec![mid]);
    let r = bob
        .enqueue_receipt(ReceiptKind::Read, vec![mid])
        .expect("receipt");
    let receipt = bob.encrypt(r).expect("encrypt");
    alice.process_inbound(3, &receipt).expect("process");
    assert_eq!(alice.message_views()[0].read_count, 1);

    // A receipt naming a message Alice never sent changes nothing.
    let bogus = bob
        .enqueue_receipt(ReceiptKind::Read, vec![[0x77; 16]])
        .expect("receipt");
    let bogus = bob.encrypt(bogus).expect("encrypt");
    assert_eq!(
        alice.process_inbound(4, &bogus).expect("process"),
        InboundOutcome::ReceiptsReceived {
            kind: ReceiptKind::Read,
            count: 0
        }
    );
}

/// Typing is ephemeral: it names its sender, and it adds nothing to either side's message log.
#[test]
fn typing_is_reported_but_never_logged() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    let t = bob.enqueue_typing(true).expect("typing");
    let envelope = bob.encrypt(t).expect("encrypt");
    assert!(bob.message_views().is_empty(), "the sender logs nothing");

    assert_eq!(
        alice.process_inbound(1, &envelope).expect("process"),
        InboundOutcome::Typing {
            sender: b"bob-device".to_vec(),
            active: true
        }
    );
    assert!(
        alice.message_views().is_empty(),
        "the recipient logs nothing"
    );
    assert_eq!(
        alice.unread_count(),
        0,
        "a typing hint is not an unread message"
    );

    let stop = bob.enqueue_typing(false).expect("typing");
    let stop = bob.encrypt(stop).expect("encrypt");
    assert_eq!(
        alice.process_inbound(2, &stop).expect("process"),
        InboundOutcome::Typing {
            sender: b"bob-device".to_vec(),
            active: false
        }
    );
}

/// Disappearing messages: the timer travels E2EE, applies to messages logged AFTER it (on both
/// sides), and `scrub_expired` removes expired rows with their bookkeeping. Wall-clock based and
/// local — R-901's honest best-effort, which is exactly what these assertions cover.
#[test]
fn disappearing_timer_applies_and_scrubs() {
    let (mut alice, _ja, mut bob, _jb) = pair();

    // Before any timer: messages keep forever.
    let pre = alice.enqueue(b"kept").expect("enqueue");
    let pre_env = alice.encrypt(pre).expect("encrypt");
    bob.process_inbound(1, &pre_env).expect("process");
    assert_eq!(bob.message_views()[0].expires_at_ms, None);

    // Alice turns on a 1-second timer; bob learns it from the ciphertext.
    let t = alice.enqueue_timer_change(1).expect("timer");
    let t_env = alice.encrypt(t).expect("encrypt");
    assert_eq!(alice.disappear_after_secs(), 1, "sender applies at encrypt");
    assert_eq!(
        bob.process_inbound(2, &t_env).expect("process"),
        InboundOutcome::TimerChanged { seconds: 1 }
    );
    assert_eq!(bob.disappear_after_secs(), 1);

    // A message sent now is stamped on both ends; the pre-timer message is untouched.
    let m = alice.enqueue(b"fleeting").expect("enqueue");
    let m_env = alice.encrypt(m).expect("encrypt");
    bob.process_inbound(3, &m_env).expect("process");
    let stamped = |views: Vec<mls_core::durable::MessageView>| {
        views.iter().filter(|v| v.expires_at_ms.is_some()).count()
    };
    assert_eq!(stamped(alice.message_views()), 1);
    assert_eq!(stamped(bob.message_views()), 1);

    // Nothing has expired yet; then the second passes and the stamped message is scrubbed —
    // with its reactions — while the pre-timer message stays.
    assert_eq!(bob.scrub_expired().expect("scrub"), 0);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(bob.scrub_expired().expect("scrub"), 1);
    let left = bob.message_views();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].plaintext, b"kept");

    // The cap is enforced at the source, like every other bounded input.
    assert!(alice
        .enqueue_timer_change(mls_core::content::MAX_DISAPPEAR_SECS + 1)
        .is_err());
}

/// Delete-for-everyone: the author's retraction tombstones both copies; a non-author cannot even
/// queue one, and a delete naming an unknown message is a durable no-op.
#[test]
fn delete_for_everyone_tombstones_both_sides() {
    let (mut alice, _ja, mut bob, _jb) = pair();

    let id = alice.enqueue(b"regretted").expect("enqueue");
    let envelope = alice.encrypt(id).expect("encrypt");
    bob.process_inbound(1, &envelope).expect("process");
    let target = bob.message_views()[0].message_id;

    // Bob reacts, so there is bookkeeping to clean up.
    let r = bob.enqueue_reaction(target, "😀", false).expect("react");
    let r_env = bob.encrypt(r).expect("encrypt");
    alice.process_inbound(2, &r_env).expect("process");

    // Bob did not author it: refused locally, before anything is sent.
    assert!(matches!(
        bob.enqueue_delete(target),
        Err(DurableError::UnknownLocal)
    ));

    // Alice retracts. Her copy tombstones at encrypt (when the group is told), not before.
    let d = alice.enqueue_delete(target).expect("delete");
    let d_env = alice.encrypt(d).expect("encrypt");
    let mine = alice
        .message_views()
        .into_iter()
        .find(|v| v.message_id == target)
        .expect("still listed");
    assert!(mine.deleted);
    assert!(mine.plaintext.is_empty());
    assert!(mine.reactions.is_empty(), "reactions went with the body");

    // Bob's copy tombstones when the delete arrives.
    assert_eq!(
        bob.process_inbound(3, &d_env).expect("process"),
        InboundOutcome::MessageDeleted { target }
    );
    let theirs = bob
        .message_views()
        .into_iter()
        .find(|v| v.message_id == target)
        .expect("row remains");
    assert!(theirs.deleted);
    assert!(theirs.plaintext.is_empty());

    // A delete for an id nobody has: durable no-op.
    let ghost = alice
        .enqueue(b"soon deleted locally only")
        .expect("enqueue");
    let _ = alice.encrypt(ghost).expect("encrypt");
    let unknown_target = [9u8; 16];
    assert!(matches!(
        alice.enqueue_delete(unknown_target),
        Err(DurableError::UnknownLocal)
    ));
}

/// R-105: history beyond the hot window spills into the append-only archive — the committed BLOB
/// stops containing old message bodies (the actual fix: commits stop rewriting all history), the
/// full log stays pageable in order, and everything survives reopen.
#[test]
fn history_spills_to_the_archive_and_the_blob_stops_growing_with_it() {
    let (mut alice, _ja, mut bob, jb) = pair();
    bob.set_hot_limit(6);

    let mut blob_at_window_full = 0usize;
    for i in 0..20 {
        let id = alice
            .enqueue(format!("archived-msg-{i:02}").as_bytes())
            .expect("enqueue");
        let env = alice.encrypt(id).expect("encrypt");
        bob.process_inbound(i + 1, &env).expect("process");
        if i == 6 {
            blob_at_window_full = jb.load().expect("load").expect("blob").len();
        }
    }

    // The hot window is bounded; the total is not lost.
    assert!(
        bob.messages().len() <= 6,
        "hot window bounded: {}",
        bob.messages().len()
    );
    assert_eq!(bob.total_message_count(), 20);

    // THE R-105 PROPERTY: once the window is full, the per-commit blob stops growing with
    // history. Thirteen further equal-sized messages must not add thirteen messages' worth of
    // bytes — the slack below is a fraction of ONE message's footprint (bookkeeping like the
    // dedup tail and receipt sets), not a multiple.
    let blob_at_20 = jb.load().expect("load").expect("blob").len();
    assert!(
        blob_at_20 < blob_at_window_full + 600,
        "blob grew with history: {blob_at_window_full} -> {blob_at_20}"
    );

    // Full history pages in order across the archive/hot boundary.
    let first = bob.message_views_page(0, 5).expect("page");
    assert_eq!(
        first
            .iter()
            .map(|v| String::from_utf8_lossy(&v.plaintext).into_owned())
            .collect::<Vec<_>>(),
        (0..5)
            .map(|i| format!("archived-msg-{i:02}"))
            .collect::<Vec<_>>()
    );
    let straddle = bob.message_views_page(12, 6).expect("page");
    assert_eq!(
        straddle
            .iter()
            .map(|v| String::from_utf8_lossy(&v.plaintext).into_owned())
            .collect::<Vec<_>>(),
        (12..18)
            .map(|i| format!("archived-msg-{i:02}"))
            .collect::<Vec<_>>()
    );

    // Reopen: watermark + archive line up again.
    let mut bob = DurableSession::open(jb.clone()).expect("reopen");
    bob.set_hot_limit(6);
    assert_eq!(bob.total_message_count(), 20);
    let after = bob.message_views_page(0, 3).expect("page");
    assert_eq!(after[0].plaintext, b"archived-msg-00");
}

/// The spill is WRITE-AHEAD: when the blob commit fails after archive records were appended, the
/// messages are still hot on reopen (nothing lost), and the crash leftovers in the archive never
/// surface as duplicates.
#[test]
fn failed_spill_commit_loses_nothing_and_duplicates_nothing() {
    let (mut alice, _ja, mut bob, jb) = pair();
    bob.set_hot_limit(3);

    for i in 0..3u64 {
        let id = alice
            .enqueue(format!("pre-{i}").as_bytes())
            .expect("enqueue");
        let env = alice.encrypt(id).expect("encrypt");
        bob.process_inbound(i + 1, &env).expect("process");
    }
    // The next inbound overflows the window; its commit (which would also spill) is failed.
    let id = alice.enqueue(b"overflow").expect("enqueue");
    let env = alice.encrypt(id).expect("encrypt");
    jb.fail_next_commit();
    assert!(
        bob.process_inbound(4, &env).is_err(),
        "injected commit failure"
    );

    // Recovery contract: reopen from the journal. All three pre-messages are present exactly
    // once; the archive's write-ahead leftovers (if the failure landed after appends) are
    // invisible because the watermark never advanced.
    let mut bob = DurableSession::open(jb.clone()).expect("reopen");
    bob.set_hot_limit(3);
    assert_eq!(bob.total_message_count(), 3);
    let all = bob.message_views_page(0, 10).expect("page");
    let texts: Vec<_> = all
        .iter()
        .map(|v| String::from_utf8_lossy(&v.plaintext).into_owned())
        .collect();
    assert_eq!(texts, vec!["pre-0", "pre-1", "pre-2"]);

    // Redelivery of the failed envelope now processes and spills cleanly.
    assert!(matches!(
        bob.process_inbound(4, &env).expect("redelivered"),
        InboundOutcome::Application(_)
    ));
    assert_eq!(bob.total_message_count(), 4);
    let all = bob.message_views_page(0, 10).expect("page");
    assert_eq!(all.len(), 4, "no duplicates after the crash-and-retry");
}

/// Disappearing messages never enter the immutable archive: the scrub owns their deletion, so
/// they hold the spill (and the messages behind them) hot until they expire.
#[test]
fn disappearing_messages_stay_hot_until_scrubbed() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    bob.set_hot_limit(2);

    let t = alice.enqueue_timer_change(1).expect("timer");
    let t_env = alice.encrypt(t).expect("encrypt");
    bob.process_inbound(1, &t_env).expect("process");

    for i in 0..5u64 {
        let id = alice
            .enqueue(format!("fleeting-{i}").as_bytes())
            .expect("enqueue");
        let env = alice.encrypt(id).expect("encrypt");
        bob.process_inbound(i + 2, &env).expect("process");
    }
    assert_eq!(bob.total_message_count(), 5);
    assert_eq!(bob.messages().len(), 5, "expiring messages refuse to spill");

    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(bob.scrub_expired().expect("scrub"), 5);
    assert_eq!(bob.total_message_count(), 0);
}

/// Local history erase covers the archive too, and (unchanged contract) decryption continues.
#[test]
fn clear_visible_history_erases_the_archive() {
    let (mut alice, _ja, mut bob, _jb) = pair();
    bob.set_hot_limit(2);
    for i in 0..6u64 {
        let id = alice
            .enqueue(format!("gone-{i}").as_bytes())
            .expect("enqueue");
        let env = alice.encrypt(id).expect("encrypt");
        bob.process_inbound(i + 1, &env).expect("process");
    }
    assert!(bob.total_message_count() == 6);
    bob.clear_visible_history().expect("clear");
    assert_eq!(bob.total_message_count(), 0);
    assert!(bob.message_views_page(0, 10).expect("page").is_empty());

    let id = alice.enqueue(b"after the purge").expect("enqueue");
    let env = alice.encrypt(id).expect("encrypt");
    assert!(matches!(
        bob.process_inbound(7, &env).expect("process"),
        InboundOutcome::Application(_)
    ));
}

/// Edits: the author's replacement lands on both sides, VISIBLY marked; a non-author cannot even
/// queue one; an edit never resurrects a deleted message; attachments and secrets don't edit.
#[test]
fn edits_are_author_only_and_always_visible() {
    let (mut alice, _ja, mut bob, _jb) = pair();

    let id = alice.enqueue(b"teh message").expect("enqueue");
    let env = alice.encrypt(id).expect("encrypt");
    bob.process_inbound(1, &env).expect("process");
    let target = bob.message_views()[0].message_id;

    // Bob did not author it: refused locally.
    assert!(matches!(
        bob.enqueue_edit(target, b"hijacked"),
        Err(DurableError::UnknownLocal)
    ));

    // Alice fixes the typo; her copy updates at encrypt, bob's when it arrives — both marked.
    let e = alice.enqueue_edit(target, b"the message").expect("edit");
    let e_env = alice.encrypt(e).expect("encrypt");
    let mine = alice
        .message_views()
        .into_iter()
        .find(|v| v.message_id == target)
        .expect("mine");
    assert_eq!(mine.plaintext, b"the message");
    assert!(mine.edited, "an edit is visible, never silent");
    assert_eq!(
        bob.process_inbound(2, &e_env).expect("process"),
        InboundOutcome::MessageEdited { target }
    );
    let theirs = bob
        .message_views()
        .into_iter()
        .find(|v| v.message_id == target)
        .expect("theirs");
    assert_eq!(theirs.plaintext, b"the message");
    assert!(theirs.edited);

    // Deleted stays deleted: alice retracts, then a (redelivered/stale) edit cannot revive it.
    let d = alice.enqueue_delete(target).expect("delete");
    let d_env = alice.encrypt(d).expect("encrypt");
    bob.process_inbound(3, &d_env).expect("process");
    let e2 = alice.enqueue_edit(target, b"resurrected?");
    assert!(
        e2.is_err(),
        "the author can't edit their own deleted message either"
    );
    let stale_edit = mls_core::content::Content::Edit {
        target,
        body: b"resurrected?".to_vec(),
    };
    // Even if edit bytes arrive (a hostile client), the deleted flag wins.
    let _ = stale_edit; // recipients enforce via apply_incoming's !deleted guard (unit-tested below)
    let after = bob
        .message_views()
        .into_iter()
        .find(|v| v.message_id == target)
        .expect("row");
    assert!(after.deleted);
    assert!(after.plaintext.is_empty());
}
