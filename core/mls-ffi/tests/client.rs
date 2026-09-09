//! Drives the exact Rust surface UniFFI exports, proving the object semantics independently of the
//! generated Swift; the Swift host test then proves the binding marshals to this same surface.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use mls_ffi::{capabilities, InboundResult, MlsClient, MlsClientError, ReceiptKindFfi};

const KEY: [u8; 32] = [7u8; 32];

fn key() -> Vec<u8> {
    KEY.to_vec()
}

/// A unique temp path per call (no external tempfile dep).
fn tmp(tag: &str) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut p = std::env::temp_dir();
    p.push(format!(
        "mls-ffi-{}-{}-{}-{}",
        std::process::id(),
        tag,
        nanos,
        n
    ));
    p.to_string_lossy().into_owned()
}

/// Build a two-party group: Alice creates, Bob joins via key-package → welcome. Returns both.
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

#[test]
fn two_clients_exchange_a_real_mls_message() {
    let (alice, bob) = two_party(&tmp("alice"), &tmp("bob"));

    // Alice queues, encrypts, and (notionally) sends.
    let id = alice.enqueue(b"hello bob".to_vec()).unwrap();
    let envelope = alice.encrypt(id).unwrap();
    alice.mark_sent(id).unwrap();

    // Bob decrypts the opaque envelope back to plaintext.
    match bob.process_inbound(1, envelope).unwrap() {
        InboundResult::Application { plaintext } => assert_eq!(plaintext, b"hello bob"),
        other => panic!("expected application message, got {other:?}"),
    }

    // Both are in the same epoch after the add.
    assert_eq!(alice.epoch().unwrap(), bob.epoch().unwrap());
    // And the stored message log reflects one outbound (Alice) / one inbound (Bob).
    assert_eq!(alice.messages().unwrap().len(), 1);
    assert_eq!(bob.messages().unwrap().len(), 1);
}

#[test]
fn retry_encrypt_returns_same_ciphertext_and_does_not_advance() {
    let (alice, _bob) = two_party(&tmp("alice"), &tmp("bob"));
    let id = alice.enqueue(b"once".to_vec()).unwrap();
    let epoch_before = alice.epoch().unwrap();
    let first = alice.encrypt(id).unwrap();
    let second = alice.encrypt(id).unwrap();
    assert_eq!(first, second, "retry must return the cached ciphertext");
    assert_eq!(
        alice.epoch().unwrap(),
        epoch_before,
        "encrypt must not advance the epoch"
    );
}

#[test]
fn duplicate_inbound_is_a_durable_noop() {
    let (alice, bob) = two_party(&tmp("alice"), &tmp("bob"));
    let id = alice.enqueue(b"dup".to_vec()).unwrap();
    let envelope = alice.encrypt(id).unwrap();
    assert!(matches!(
        bob.process_inbound(42, envelope.clone()).unwrap(),
        InboundResult::Application { .. }
    ));
    // Same envelope id again ⇒ Duplicate, no second stored message.
    assert!(matches!(
        bob.process_inbound(42, envelope).unwrap(),
        InboundResult::Duplicate
    ));
    assert_eq!(bob.messages().unwrap().len(), 1);
}

#[test]
fn relaunch_reopens_durable_state_and_continues() {
    let alice_db = tmp("alice");
    let bob_db = tmp("bob");
    let (alice, bob) = two_party(&alice_db, &bob_db);

    let id = alice.enqueue(b"before crash".to_vec()).unwrap();
    let _ = alice.encrypt(id).unwrap();
    let epoch = alice.epoch().unwrap();
    let msg_count = alice.messages().unwrap().len();

    // Simulate relaunch: drop the handle, reopen from the encrypted journal.
    alice.close();
    drop(alice);
    let alice2 = MlsClient::open(alice_db, key()).unwrap();
    assert_eq!(alice2.epoch().unwrap(), epoch);
    assert_eq!(alice2.messages().unwrap().len(), msg_count);

    // It keeps working after relaunch: send a fresh message Bob can read.
    let id2 = alice2.enqueue(b"after crash".to_vec()).unwrap();
    let env2 = alice2.encrypt(id2).unwrap();
    match bob.process_inbound(2, env2).unwrap() {
        InboundResult::Application { plaintext } => assert_eq!(plaintext, b"after crash"),
        other => panic!("expected application message, got {other:?}"),
    }
}

#[test]
fn closed_client_rejects_all_ops() {
    let alice = MlsClient::create_group(b"alice".to_vec(), tmp("a"), key()).unwrap();
    alice.close();
    alice.close(); // idempotent, no panic
    assert_eq!(alice.epoch().unwrap_err(), MlsClientError::Closed);
    assert_eq!(
        alice.enqueue(b"x".to_vec()).unwrap_err(),
        MlsClientError::Closed
    );
    assert!(matches!(alice.messages(), Err(MlsClientError::Closed)));
}

#[test]
fn pending_joiner_rejects_group_ops_until_joined() {
    let bob = MlsClient::new_joiner(b"bob".to_vec(), tmp("b"), key()).unwrap();
    // Key package is fine while pending; group operations are not.
    assert!(bob.key_package().is_ok());
    assert_eq!(bob.epoch().unwrap_err(), MlsClientError::WrongState);
    assert_eq!(
        bob.enqueue(b"x".to_vec()).unwrap_err(),
        MlsClientError::WrongState
    );
}

#[test]
fn bad_at_rest_key_length_is_rejected() {
    assert!(matches!(
        MlsClient::create_group(b"a".to_vec(), tmp("a"), vec![0u8; 16]),
        Err(MlsClientError::BadKeyLength)
    ));
}

#[test]
fn oversized_input_is_rejected_before_processing() {
    let alice = MlsClient::create_group(b"a".to_vec(), tmp("a"), key()).unwrap();
    let too_big = vec![0u8; 64 * 1024 + 1]; // MAX_PLAINTEXT_LEN + 1
    assert_eq!(
        alice.enqueue(too_big).unwrap_err(),
        MlsClientError::InputTooLarge
    );
}

#[test]
fn message_pagination_windows_the_log() {
    let (alice, _bob) = two_party(&tmp("alice"), &tmp("bob"));
    for i in 0..5u8 {
        let id = alice.enqueue(vec![i]).unwrap();
        let _ = alice.encrypt(id).unwrap();
    }
    assert_eq!(alice.message_count().unwrap(), 5);

    // Window in the middle, oldest first.
    let page = alice.messages_page(1, 2).unwrap();
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].plaintext, vec![1]);
    assert_eq!(page[1].plaintext, vec![2]);

    // Window clipped at the end; offset past the end is an empty page, not an error.
    assert_eq!(alice.messages_page(4, 10).unwrap().len(), 1);
    assert_eq!(alice.messages_page(99, 10).unwrap().len(), 0);

    // A huge limit is clamped, never unbounded.
    assert!(alice.messages_page(0, u32::MAX).unwrap().len() <= 256);

    // Consistent with the full accessor.
    assert_eq!(alice.messages().unwrap().len(), 5);
}

#[test]
fn capabilities_report_the_pinned_contract() {
    let c = capabilities();
    assert_eq!(c.protocol, "MLS 1.0 (RFC 9420)");
    assert_eq!(
        c.ciphersuite,
        "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"
    );
    assert_eq!(c.storage_format_version, 1);
    assert_eq!(c.max_plaintext, 64 * 1024);
}

#[test]
fn staged_commit_proposer_and_recipient_paths() {
    // Two-party group; alice stages adding carol, the "server accepts", alice merges, and bob (the
    // recipient) verifies the commit against the manifest's delta before merging.
    let (alice, bob) = two_party(&tmp("alice"), &tmp("bob"));
    let epoch = alice.epoch().unwrap();

    // A third identity (carol) to be added, with its own key package.
    let carol = MlsClient::new_joiner(b"carol".to_vec(), tmp("carol"), key()).unwrap();
    let carol_kp = carol.key_package().unwrap();

    // Stage: no epoch advance yet. (This first staged commit is discarded below.)
    let _ = alice.stage_add(carol_kp).unwrap();
    assert_eq!(alice.epoch().unwrap(), epoch, "staging must not advance");

    // Simulate the server REJECTING first (stale epoch): discard, state unchanged, still usable.
    alice.clear_staged().unwrap();
    assert_eq!(alice.epoch().unwrap(), epoch);

    // Rebuild and this time the server ACCEPTS: merge.
    let carol_kp2 = carol.key_package().unwrap();
    let staged = alice.stage_add(carol_kp2).unwrap();
    alice.merge_staged().unwrap();
    assert_eq!(alice.epoch().unwrap(), epoch + 1);

    // Recipient bob: the honest manifest claims carol was added → merges and advances.
    bob.process_commit(
        staged.commit.clone(),
        epoch + 1,
        vec![b"carol".to_vec()],
        vec![],
    )
    .unwrap();
    assert_eq!(bob.epoch().unwrap(), alice.epoch().unwrap());

    // Carol joins from the welcome and can read subsequent traffic.
    carol.join_group(staged.welcome).unwrap();
}

#[test]
fn recipient_refuses_a_commit_that_does_not_match_the_manifest() {
    let (alice, bob) = two_party(&tmp("alice"), &tmp("bob"));
    let epoch = alice.epoch().unwrap();
    let mallory = MlsClient::new_joiner(b"mallory".to_vec(), tmp("mallory"), key()).unwrap();

    let staged = alice.stage_add(mallory.key_package().unwrap()).unwrap();
    alice.merge_staged().unwrap();

    // The manifest LIES (claims "carol"); bob refuses and does not advance.
    let err = bob
        .process_commit(staged.commit, epoch + 1, vec![b"carol".to_vec()], vec![])
        .unwrap_err();
    assert_eq!(err, MlsClientError::InvalidMessage);
    assert_eq!(bob.epoch().unwrap(), epoch, "state must not follow a lie");
}

#[test]
fn process_inbound_rejects_an_unknown_envelope_version() {
    let (alice, bob) = two_party(&tmp("alice"), &tmp("bob"));
    let id = alice.enqueue(b"hi".to_vec()).unwrap();
    let mut env = alice.encrypt(id).unwrap();
    // Rewrite the 2-byte version prefix to a future, unsupported version.
    env[0] = 0x00;
    env[1] = 0x02;
    assert_eq!(
        bob.process_inbound(1, env).unwrap_err(),
        MlsClientError::InvalidMessage
    );
    // A correctly-versioned message from alice still works (sanity).
    let id2 = alice.enqueue(b"real".to_vec()).unwrap();
    let good = alice.encrypt(id2).unwrap();
    matches!(
        bob.process_inbound(2, good).unwrap(),
        InboundResult::Application { .. }
    );
}

/// `unsent_local_ids` is the relaunch retry set: queued/encrypted until `mark_sent`, and a retry
/// `encrypt` replays the cached ciphertext rather than advancing the ratchet again.
#[test]
fn unsent_local_ids_follow_the_upload_lifecycle() {
    let path = tmp("unsent");
    let alice = MlsClient::create_group(b"alice".to_vec(), path.clone(), key()).expect("create");
    assert!(alice.unsent_local_ids().expect("unsent").is_empty());
    let a = alice.enqueue(b"a".to_vec()).expect("enqueue");
    let b = alice.enqueue(b"b".to_vec()).expect("enqueue");
    let bytes = alice.encrypt(b).expect("encrypt");
    assert_eq!(alice.unsent_local_ids().expect("unsent"), vec![a, b]);
    alice.close();

    let reopened = MlsClient::open(path, key()).expect("reopen");
    assert_eq!(reopened.unsent_local_ids().expect("unsent"), vec![a, b]);
    assert_eq!(reopened.encrypt(b).expect("retry"), bytes);
    reopened.mark_sent(b).expect("mark sent");
    assert_eq!(reopened.unsent_local_ids().expect("unsent"), vec![a]);
}

/// Across the FFI: a joiner created, its prekey published, the process "dies", the identity is
/// reopened from disk still Pending, and the Welcome made for that prekey joins it.
#[test]
fn pending_joiner_survives_relaunch_and_joins() {
    let bob_path = tmp("pending-bob");
    let bob = MlsClient::new_joiner(b"bob".to_vec(), bob_path.clone(), key()).expect("joiner");
    assert!(bob.is_pending().expect("pending"));
    let kp = bob.key_package().expect("kp");
    bob.close();

    let alice =
        MlsClient::create_group(b"alice".to_vec(), tmp("pending-alice"), key()).expect("alice");
    let add = alice.add_member(kp).expect("add");

    let bob = MlsClient::open(bob_path, key()).expect("reopen pending");
    assert!(bob.is_pending().expect("still pending after relaunch"));
    bob.join_group(add.welcome).expect("join");
    assert!(!bob.is_pending().expect("active"));

    let id = alice.enqueue(b"hello bob".to_vec()).expect("enqueue");
    let env = alice.encrypt(id).expect("encrypt");
    assert!(matches!(
        bob.process_inbound(1, env).expect("process"),
        InboundResult::Application { plaintext } if plaintext == b"hello bob"
    ));
}

/// A group grows past two: the member who joined first applies the later add's commit through the
/// ordinary inbound path and every pair can then decrypt each other — the shape the app's
/// bootstrap relies on (Welcome to the newcomer, commit to everyone already in).
#[test]
fn group_growth_commit_reaches_earlier_members_through_process_inbound() {
    let alice = MlsClient::create_group(b"alice".to_vec(), tmp("g-alice"), key()).expect("alice");
    let bob = MlsClient::new_joiner(b"bob".to_vec(), tmp("g-bob"), key()).expect("bob");
    let carol = MlsClient::new_joiner(b"carol".to_vec(), tmp("g-carol"), key()).expect("carol");
    let add_bob = alice
        .add_member(bob.key_package().expect("kp"))
        .expect("add bob");
    bob.join_group(add_bob.welcome).expect("bob joins");
    let add_carol = alice
        .add_member(carol.key_package().expect("kp"))
        .expect("add carol");
    assert!(matches!(
        bob.process_inbound(1, add_carol.commit)
            .expect("bob applies the commit"),
        InboundResult::StateAdvanced
    ));
    carol.join_group(add_carol.welcome).expect("carol joins");

    let say = |from: &MlsClient, text: &[u8]| {
        let id = from.enqueue(text.to_vec()).expect("enqueue");
        let env = from.encrypt(id).expect("encrypt");
        from.mark_sent(id).expect("sent");
        env
    };
    let hear = |to: &MlsClient, id: u64, env: Vec<u8>| match to.process_inbound(id, env) {
        Ok(InboundResult::Application { plaintext }) => plaintext,
        other => panic!("expected application, got {other:?}"),
    };
    let from_carol = say(&carol, b"hello all");
    assert_eq!(hear(&alice, 2, from_carol.clone()), b"hello all");
    assert_eq!(hear(&bob, 3, from_carol), b"hello all");
    let from_bob = say(&bob, b"hey");
    assert_eq!(hear(&alice, 4, from_bob.clone()), b"hey");
    assert_eq!(hear(&carol, 5, from_bob), b"hey");
    let from_alice = say(&alice, b"welcome both");
    assert_eq!(hear(&bob, 6, from_alice.clone()), b"welcome both");
    assert_eq!(hear(&carol, 7, from_alice), b"welcome both");
}

/// Across the FFI: a rename reaches the other member as `GroupRenamed` and nothing about it exists
/// outside the ciphertext; unread counts follow inbound messages and the read mark; and a message
/// reports `pending` until it is marked sent.
#[test]
fn group_name_unread_and_pending_state_cross_the_boundary() {
    let alice = MlsClient::create_group(b"alice".to_vec(), tmp("meta-a"), key()).expect("alice");
    let bob = MlsClient::new_joiner(b"bob".to_vec(), tmp("meta-b"), key()).expect("bob");
    let add = alice
        .add_member(bob.key_package().expect("kp"))
        .expect("add");
    bob.join_group(add.welcome).expect("join");

    // Rename.
    assert_eq!(alice.group_name().expect("name"), None);
    let rename = alice.set_group_name("Weekend Trip".into()).expect("rename");
    let envelope = alice.encrypt(rename).expect("encrypt");
    alice.mark_sent(rename).expect("sent");
    assert_eq!(
        alice.group_name().expect("name"),
        Some("Weekend Trip".into())
    );
    assert!(matches!(
        bob.process_inbound(1, envelope).expect("process"),
        InboundResult::GroupRenamed { ref name } if name == "Weekend Trip"
    ));
    assert_eq!(bob.group_name().expect("name"), Some("Weekend Trip".into()));
    assert!(
        bob.messages().expect("messages").is_empty(),
        "a rename is not a chat message"
    );
    // A name no client could render safely is refused here, not at every recipient.
    assert!(alice.set_group_name("bad\u{202E}name".into()).is_err());

    // Pending state: encrypted but unsent, then accepted.
    let id = alice.enqueue(b"hi".to_vec()).expect("enqueue");
    let msg = alice.encrypt(id).expect("encrypt");
    let mine = alice.messages().expect("messages");
    assert_eq!(mine.len(), 1);
    assert!(mine[0].pending);
    assert!(mine[0].created_at_ms > 1_700_000_000_000);
    alice.mark_sent(id).expect("sent");
    assert!(!alice.messages().expect("messages")[0].pending);

    // Unread: Bob has one, until he reads.
    assert_eq!(bob.unread_count().expect("unread"), 0);
    bob.process_inbound(2, msg).expect("process");
    assert_eq!(bob.unread_count().expect("unread"), 1);
    let received = bob.messages().expect("messages");
    assert!(!received[0].pending, "inbound is never pending");
    bob.mark_read().expect("mark read");
    assert_eq!(bob.unread_count().expect("unread"), 0);
}

/// Attachments across the FFI: seal → (upload happens outside) → reference the blob in a message →
/// the recipient gets the key over MLS and opens bytes the relay could not.
#[test]
fn attachment_seals_travels_and_opens_across_the_boundary() {
    let alice = MlsClient::create_group(b"alice".to_vec(), tmp("att-a"), key()).expect("alice");
    let bob = MlsClient::new_joiner(b"bob".to_vec(), tmp("att-b"), key()).expect("bob");
    let add = alice
        .add_member(bob.key_package().expect("kp"))
        .expect("add");
    bob.join_group(add.welcome).expect("join");

    let file = b"a photo's bytes".repeat(40);
    let sealed = mls_ffi::seal_attachment(file.clone()).expect("seal");
    assert_ne!(
        sealed.ciphertext, file,
        "what the relay would store is not the file"
    );
    let blob_id = vec![3u8; 16];

    let id = alice
        .send_attachment(
            blob_id.clone(),
            sealed.key.clone(),
            sealed.digest.clone(),
            file.len() as u64,
            "image/png".into(),
            "shot.png".into(),
            "here".into(),
        )
        .expect("send attachment");
    let envelope = alice.encrypt(id).expect("encrypt");

    let info = match bob.process_inbound(1, envelope).expect("process") {
        InboundResult::AttachmentReceived { attachment } => attachment,
        other => panic!("expected AttachmentReceived, got {other:?}"),
    };
    assert_eq!(info.blob_id, blob_id);
    assert_eq!(info.mime, "image/png");
    assert_eq!(info.filename, "shot.png");
    assert_eq!(info.size, file.len() as u64);
    assert_eq!(
        mls_ffi::open_attachment(
            info.key.clone(),
            info.digest.clone(),
            sealed.ciphertext.clone()
        )
        .expect("open"),
        file
    );

    // The message log carries the caption and the reference on both sides.
    let received = &bob.messages().expect("messages")[0];
    assert_eq!(received.plaintext, b"here");
    assert!(received.attachment.is_some());
    assert!(alice.messages().expect("messages")[0].attachment.is_some());

    // A substituted blob is refused, and so is a wrong key.
    let other = mls_ffi::seal_attachment(b"different".to_vec()).expect("seal");
    assert!(
        mls_ffi::open_attachment(info.key.clone(), info.digest.clone(), other.ciphertext).is_err()
    );
    assert!(mls_ffi::open_attachment(vec![0u8; 32], info.digest, sealed.ciphertext).is_err());
}

/// Replies, reactions, receipts and typing across the FFI, in the order a conversation actually
/// uses them.
#[test]
fn interaction_layer_crosses_the_boundary() {
    let alice = MlsClient::create_group(b"alice".to_vec(), tmp("int-a"), key()).expect("alice");
    let bob = MlsClient::new_joiner(b"bob".to_vec(), tmp("int-b"), key()).expect("bob");
    let add = alice
        .add_member(bob.key_package().expect("kp"))
        .expect("add");
    bob.join_group(add.welcome).expect("join");

    // Alice sends; Bob receives and learns its id.
    let id = alice.enqueue(b"dinner at 8?".to_vec()).expect("enqueue");
    let envelope = alice.encrypt(id).expect("encrypt");
    alice.mark_sent(id).expect("sent");
    bob.process_inbound(1, envelope).expect("process");
    let target = bob.messages().expect("messages")[0].message_id.clone();
    assert_eq!(target.len(), 16);

    // Reply: the pointer travels, and Alice resolves it against her own log.
    let reply = bob
        .send_reply(b"works for me".to_vec(), target.clone())
        .expect("reply");
    let reply_env = bob.encrypt(reply).expect("encrypt");
    alice.process_inbound(2, reply_env).expect("process");
    let alice_msgs = alice.messages().expect("messages");
    assert_eq!(alice_msgs[1].reply_to, Some(target.clone()));
    assert_eq!(
        alice_msgs[0].message_id, target,
        "the answered message is ours"
    );

    // Reaction: attributed to Bob's MLS identity, and it toggles.
    let react = bob
        .react(target.clone(), "👍".into(), false)
        .expect("react");
    let react_env = bob.encrypt(react).expect("encrypt");
    assert!(matches!(
        alice.process_inbound(3, react_env).expect("process"),
        InboundResult::ReactionChanged { .. }
    ));
    let reactions = alice.messages().expect("messages")[0].reactions.clone();
    assert_eq!(reactions.len(), 1);
    assert_eq!(reactions[0].emoji, "👍");
    assert_eq!(reactions[0].sender, b"bob");
    let unreact = bob
        .react(target.clone(), "👍".into(), true)
        .expect("unreact");
    let unreact_env = bob.encrypt(unreact).expect("encrypt");
    alice.process_inbound(4, unreact_env).expect("process");
    assert!(alice.messages().expect("messages")[0].reactions.is_empty());

    // Receipts: delivered is owed immediately, read only after the user has seen it.
    assert_eq!(
        bob.unacknowledged(ReceiptKindFfi::Delivered).expect("owed"),
        vec![target.clone()]
    );
    assert!(bob
        .unacknowledged(ReceiptKindFfi::Read)
        .expect("owed")
        .is_empty());
    let r = bob
        .send_receipt(ReceiptKindFfi::Delivered, vec![target.clone()])
        .expect("receipt");
    let r_env = bob.encrypt(r).expect("encrypt");
    assert!(
        bob.unacknowledged(ReceiptKindFfi::Delivered)
            .expect("owed")
            .is_empty(),
        "sending a receipt records it, so it is not sent again"
    );
    assert!(matches!(
        alice.process_inbound(5, r_env).expect("process"),
        InboundResult::ReceiptsReceived {
            kind: ReceiptKindFfi::Delivered,
            count: 1
        }
    ));
    assert_eq!(alice.messages().expect("messages")[0].delivered_count, 1);
    assert_eq!(alice.messages().expect("messages")[0].read_count, 0);

    bob.mark_read().expect("read");
    let r = bob
        .send_receipt(ReceiptKindFfi::Read, vec![target])
        .expect("receipt");
    let r_env = bob.encrypt(r).expect("encrypt");
    alice.process_inbound(6, r_env).expect("process");
    assert_eq!(alice.messages().expect("messages")[0].read_count, 1);

    // Typing: reported, attributed, and logged by nobody.
    let logged_before = alice.messages().expect("messages").len();
    let t = bob.send_typing(true).expect("typing");
    let t_env = bob.encrypt(t).expect("encrypt");
    assert!(matches!(
        alice.process_inbound(7, t_env).expect("process"),
        InboundResult::Typing { ref sender, active: true } if sender == b"bob"
    ));
    assert_eq!(
        alice.messages().expect("messages").len(),
        logged_before,
        "typing is not a message"
    );
}
