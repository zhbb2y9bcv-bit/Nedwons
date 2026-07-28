//! The wasm binding driven as ordinary Rust, on the host.
//!
//! These run under a plain `cargo test` with **no browser and no wasm toolchain**, because the
//! binding's logic — state machine, bounds, error mapping, envelope wrapping — is
//! platform-independent; only the JS glue is not. That keeps the expensive part of the surface under
//! regression test in normal CI. What they deliberately do NOT cover is the `JournalHost` seam,
//! which needs a real JS host (see `journal.rs`).
//!
//! The point of the round trip is that it is REAL MLS: two clients, actual X-Wing key packages,
//! Welcome, and ciphertext through the same `mls-core` the iOS app uses.

use mls_wasm::{InboundKind, MlsClient, SecretPhase, WasmError};

/// `unwrap_err()` would require `Debug` on the success type, and neither `MlsClient` nor
/// `InboundResult` derives it **on purpose** — a `Debug` impl over ratchet state or decrypted
/// plaintext is exactly how secrets end up in a log. So assert on errors through this instead.
fn err<T>(r: Result<T, WasmError>) -> WasmError {
    match r {
        Ok(_) => panic!("expected an error, got Ok"),
        Err(e) => e,
    }
}

/// Two clients on the volatile journal, already in one group.
fn paired() -> (MlsClient, MlsClient) {
    let alice = MlsClient::create_group_in_memory(b"alice".to_vec()).expect("create group");
    let bob = MlsClient::new_joiner_in_memory(b"bob".to_vec()).expect("new joiner");
    let key_package = bob.key_package().expect("key package");
    let added = alice.add_member(key_package).expect("add member");
    bob.join_group(added.welcome()).expect("join");
    (alice, bob)
}

/// Send `body` from `from` to `to`, returning what the recipient made of it.
fn deliver(
    from: &MlsClient,
    to: &MlsClient,
    envelope_id: u64,
    body: &[u8],
) -> mls_wasm::InboundResult {
    let local_id = from.enqueue(body.to_vec()).expect("enqueue");
    let envelope = from.encrypt(local_id).expect("encrypt");
    from.mark_sent(local_id).expect("mark sent");
    to.process_inbound(envelope_id, envelope).expect("inbound")
}

#[test]
fn two_clients_exchange_a_real_mls_message() {
    let (alice, bob) = paired();
    let result = deliver(&alice, &bob, 1, b"hello from the browser");
    assert_eq!(result.kind(), InboundKind::Application);
    assert_eq!(
        result.plaintext().as_deref(),
        Some(&b"hello from the browser"[..])
    );

    // Both sides have it in their log: the sender records a display copy on encrypt.
    assert_eq!(bob.message_count().unwrap(), 1);
    assert_eq!(alice.message_count().unwrap(), 1);
    let page = bob.messages_page(0, 10).unwrap();
    assert_eq!(page.len(), 1);
    assert!(!page[0].outbound(), "bob received it");
    assert_eq!(page[0].plaintext(), b"hello from the browser".to_vec());
}

#[test]
fn ciphertext_never_contains_the_plaintext() {
    // The binding wraps the MLS message in the versioned app envelope; neither layer may leak the
    // body. Cheap, but it is the invariant the whole product rests on (INV-1).
    let (alice, _bob) = paired();
    let secret_body = b"the-quick-brown-fox-9f3a2b";
    let local_id = alice.enqueue(secret_body.to_vec()).unwrap();
    let envelope = alice.encrypt(local_id).unwrap();
    assert!(
        !envelope
            .windows(secret_body.len())
            .any(|w| w == secret_body),
        "plaintext must not appear anywhere in the envelope"
    );
}

#[test]
fn redelivery_is_an_idempotent_no_op() {
    let (alice, bob) = paired();
    let local_id = alice.enqueue(b"once".to_vec()).unwrap();
    let envelope = alice.encrypt(local_id).unwrap();

    let first = bob.process_inbound(7, envelope.clone()).unwrap();
    assert_eq!(first.kind(), InboundKind::Application);
    // At-least-once delivery replays the SAME envelope id — a durable no-op, not a second message.
    let second = bob.process_inbound(7, envelope).unwrap();
    assert_eq!(second.kind(), InboundKind::Duplicate);
    assert_eq!(bob.message_count().unwrap(), 1);
}

#[test]
fn encrypt_is_idempotent_and_never_double_advances_the_ratchet() {
    let (alice, bob) = paired();
    let local_id = alice.enqueue(b"retry me".to_vec()).unwrap();
    let first = alice.encrypt(local_id).unwrap();
    let second = alice.encrypt(local_id).unwrap();
    assert_eq!(first, second, "a retry must return the cached ciphertext");
    // And the once-encrypted message still decrypts, proving the ratchet advanced exactly once.
    let out = bob.process_inbound(1, second).unwrap();
    assert_eq!(out.plaintext().as_deref(), Some(&b"retry me"[..]));
}

#[test]
fn an_unknown_envelope_version_is_rejected_before_reaching_mls() {
    let (_alice, bob) = paired();
    // Valid-looking length, unknown app-envelope version prefix.
    let mut hostile = vec![0xFF, 0xFF];
    hostile.extend_from_slice(&[0u8; 64]);
    assert_eq!(
        err(bob.process_inbound(1, hostile)),
        WasmError::InvalidMessage
    );
}

#[test]
fn oversized_and_malformed_inputs_are_refused_with_typed_errors() {
    let alice = MlsClient::create_group_in_memory(b"alice".to_vec()).unwrap();

    let caps = mls_wasm::capabilities();
    assert_eq!(
        err(alice.enqueue(vec![0u8; caps.max_plaintext() as usize + 1])),
        WasmError::InputTooLarge
    );
    assert_eq!(
        err(MlsClient::create_group_in_memory(vec![
            0u8;
            caps.max_identity()
                as usize
                + 1
        ])),
        WasmError::InputTooLarge
    );
    // A secret id is fixed-width; any other length fails closed rather than being padded.
    assert_eq!(
        err(alice.secret_phase(vec![0u8; 15], 0)),
        WasmError::InvalidMessage
    );
    // A delivery key is exactly 32 bytes.
    assert_eq!(
        err(alice.enqueue_delivery_key_grant(vec![0u8; 31])),
        WasmError::InvalidMessage
    );
    // An unknown local id is not found, not a panic.
    assert_eq!(err(alice.encrypt(9_999)), WasmError::NotFound);
}

#[test]
fn state_machine_rejects_out_of_order_use() {
    let joiner = MlsClient::new_joiner_in_memory(b"carol".to_vec()).unwrap();
    // Pending: no conversation yet, so conversation operations are refused...
    assert_eq!(
        err(joiner.enqueue(b"too early".to_vec())),
        WasmError::WrongState
    );
    assert_eq!(err(joiner.epoch()), WasmError::WrongState);
    // ...but publishing a prekey is exactly what a pending joiner is for.
    assert!(joiner.key_package().is_ok());

    // Closed invalidates everything, idempotently.
    let alice = MlsClient::create_group_in_memory(b"alice".to_vec()).unwrap();
    alice.close();
    alice.close();
    assert_eq!(
        err(alice.enqueue(b"after close".to_vec())),
        WasmError::Closed
    );
    assert_eq!(err(alice.key_package()), WasmError::Closed);
}

#[test]
fn a_secret_travels_sealed_and_reveals_exactly_once() {
    let (alice, bob) = paired();
    let handle = alice
        .enqueue_secret(b"burn after reading".to_vec())
        .unwrap();
    let envelope = alice.encrypt(handle.local_id()).unwrap();
    alice.mark_sent(handle.local_id()).unwrap();

    // The recipient gets a SEALED placeholder — the body is not delivered by process_inbound.
    let inbound = bob.process_inbound(1, envelope).unwrap();
    assert_eq!(inbound.kind(), InboundKind::SecretSealed);
    let secret_id = inbound.secret_id().expect("secret id");
    assert!(
        inbound.plaintext().is_none(),
        "the body must not ride along"
    );
    assert_eq!(
        bob.secret_phase(secret_id.clone(), 0).unwrap(),
        SecretPhase::Sealed
    );
    assert!(bob
        .secret_visible_body(secret_id.clone(), 0)
        .unwrap()
        .is_none());

    // Reveal starts a countdown, then the body becomes visible...
    bob.begin_secret_reveal(secret_id.clone(), 1_000).unwrap();
    assert_eq!(
        bob.secret_phase(secret_id.clone(), 1_000).unwrap(),
        SecretPhase::Countdown
    );
    let visible_at = 1_000 + 5_000;
    assert_eq!(
        bob.secret_phase(secret_id.clone(), visible_at).unwrap(),
        SecretPhase::Visible
    );
    assert_eq!(
        bob.secret_visible_body(secret_id.clone(), visible_at)
            .unwrap()
            .as_deref(),
        Some(&b"burn after reading"[..])
    );

    // ...and after expiry it is gone forever, not merely hidden.
    let expired = visible_at + 60_000;
    assert_eq!(
        bob.secret_phase(secret_id.clone(), expired).unwrap(),
        SecretPhase::Consumed
    );
    assert!(bob
        .secret_visible_body(secret_id.clone(), expired)
        .unwrap()
        .is_none());
    // Even rewinding the clock cannot reopen it.
    assert!(bob
        .secret_visible_body(secret_id, visible_at)
        .unwrap()
        .is_none());
}

#[test]
fn clearing_visible_history_keeps_the_ratchet_working() {
    // Deleting a conversation is a LOCAL, display-only erase: protocol state must survive or later
    // messages would stop decrypting.
    let (alice, bob) = paired();
    deliver(&alice, &bob, 1, b"first");
    assert_eq!(bob.message_count().unwrap(), 1);

    bob.clear_visible_history().unwrap();
    assert_eq!(bob.message_count().unwrap(), 0);

    let out = deliver(&alice, &bob, 2, b"second");
    assert_eq!(out.plaintext().as_deref(), Some(&b"second"[..]));
    assert_eq!(bob.message_count().unwrap(), 1);
}

#[test]
fn message_pages_are_bounded_and_offsets_are_safe() {
    let (alice, bob) = paired();
    for i in 0..5u64 {
        deliver(&alice, &bob, i + 1, format!("msg{i}").as_bytes());
    }
    assert_eq!(bob.messages_page(0, 2).unwrap().len(), 2);
    assert_eq!(
        bob.messages_page(3, 100).unwrap().len(),
        2,
        "clamped to the tail"
    );
    assert!(
        bob.messages_page(999, 10).unwrap().is_empty(),
        "past the end is empty, not an error"
    );
    // limit is capped regardless of what the caller asks for.
    assert!(bob.messages_page(0, u32::MAX).unwrap().len() <= mls_wasm::MAX_PAGE_MESSAGES as usize);
}

#[test]
fn capabilities_report_the_pq_ciphersuite_and_match_the_core() {
    let caps = mls_wasm::capabilities();
    assert_eq!(
        caps.ciphersuite(),
        "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"
    );
    assert_eq!(caps.protocol(), "MLS 1.0 (RFC 9420)");
    // The storage format must match the core's, or a blob written by one is misread by the other.
    assert_eq!(caps.storage_format_version(), 1);
    assert!(mls_wasm::binding_version().contains("mls-wasm"));
    assert_eq!(
        mls_wasm::secret_tombstone_text(),
        "a secret message has been sent"
    );
}
