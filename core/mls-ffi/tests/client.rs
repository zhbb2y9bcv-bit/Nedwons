//! Integration tests for the FFI-facing `MlsClient` object (ADR-0007). These drive the exact Rust
//! surface UniFFI exports, so they prove the object semantics (two-party MLS, durable persistence,
//! retry-idempotence, state machine, bounds) independently of the generated Swift — the Swift host
//! test then proves the binding marshals to this same surface.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use mls_ffi::{capabilities, InboundResult, MlsClient, MlsClientError};

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
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
    );
    assert_eq!(c.storage_format_version, 1);
    assert_eq!(c.max_plaintext, 64 * 1024);
}
