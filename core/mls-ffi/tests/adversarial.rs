//! Adversarial, crash, and concurrency tests for the FFI boundary (ADR-0007 Phase 4).
//!
//! The point of these is negative-space coverage: hostile inputs, boundary sizes, invalid handle
//! states, concurrency, and injected faults must yield **typed errors, never a panic across the
//! boundary or a corrupt state**.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use mls_core::client::{MAX_ENVELOPE_LEN, MAX_PLAINTEXT_LEN};
use mls_core::durable::InMemoryJournal;
use mls_ffi::{InboundResult, MlsClient, MlsClientError};

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
        "mls-adv-{}-{}-{}-{}",
        std::process::id(),
        tag,
        nanos,
        n
    ));
    p.to_string_lossy().into_owned()
}

fn two_party() -> (Arc<MlsClient>, Arc<MlsClient>) {
    let alice = MlsClient::create_group(b"alice".to_vec(), tmp("a"), key()).unwrap();
    let bob = MlsClient::new_joiner(b"bob".to_vec(), tmp("b"), key()).unwrap();
    let add = alice.add_member(bob.key_package().unwrap()).unwrap();
    bob.join_group(add.welcome).unwrap();
    (alice, bob)
}

/// A tiny deterministic PRNG so the malformed-input corpus is reproducible.
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next() & 0xff) as u8).collect()
    }
}

#[test]
fn input_bounds_max_minus_one_max_and_max_plus_one() {
    let alice = MlsClient::create_group(b"a".to_vec(), tmp("a"), key()).unwrap();
    assert!(alice.enqueue(vec![0u8; MAX_PLAINTEXT_LEN - 1]).is_ok());
    assert!(alice.enqueue(vec![0u8; MAX_PLAINTEXT_LEN]).is_ok());
    assert_eq!(
        alice.enqueue(vec![0u8; MAX_PLAINTEXT_LEN + 1]).unwrap_err(),
        MlsClientError::InputTooLarge
    );
}

#[test]
fn binary_non_utf8_plaintext_round_trips() {
    let (alice, bob) = two_party();
    // Deliberately invalid UTF-8 — the surface is byte-oriented and must not assume text.
    let payload = vec![0xff, 0xfe, 0x00, 0x80, 0xc0, 0x01, 0xff];
    let id = alice.enqueue(payload.clone()).unwrap();
    let env = alice.encrypt(id).unwrap();
    match bob.process_inbound(1, env).unwrap() {
        InboundResult::Application { plaintext } => assert_eq!(plaintext, payload),
        other => panic!("expected application, got {other:?}"),
    }
}

#[test]
fn malformed_envelopes_yield_typed_errors_never_panic() {
    let (_alice, bob) = two_party();

    // Fixed nasty cases.
    let fixed: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0xff; 32],
        vec![0x01, 0x02, 0x03, 0x04],
        b"not an mls message".to_vec(),
    ];
    for (i, corpus) in fixed.iter().enumerate() {
        // Must return a typed Result (reaching this line at all means no panic escaped).
        let r = bob.process_inbound(1000 + i as u64, corpus.clone());
        assert!(
            matches!(r, Ok(_) | Err(MlsClientError::InvalidMessage)),
            "unexpected result for fixed case {i}: {r:?}"
        );
    }

    // Random corpus.
    let mut rng = XorShift(0x5eed_1234_dead_beef);
    for i in 0..4000u64 {
        let len = (rng.next() % 512) as usize;
        let r = bob.process_inbound(2000 + i, rng.bytes(len));
        assert!(matches!(r, Ok(_) | Err(MlsClientError::InvalidMessage)));
    }

    // Truncations of a *real* envelope from a separate group.
    let (alice2, _bob2) = two_party();
    let id = alice2.enqueue(b"real".to_vec()).unwrap();
    let real = alice2.encrypt(id).unwrap();
    for cut in 1..real.len() {
        let r = bob.process_inbound(9_000_000 + cut as u64, real[..cut].to_vec());
        assert!(matches!(r, Ok(_) | Err(MlsClientError::InvalidMessage)));
    }

    // Oversized ⇒ rejected before parsing.
    assert_eq!(
        bob.process_inbound(1, vec![0u8; MAX_ENVELOPE_LEN + 1])
            .unwrap_err(),
        MlsClientError::InputTooLarge
    );
}

#[test]
fn cross_client_isolation_no_shared_handle_space() {
    // Two fully independent clients. A local id minted by one is meaningless to the other — there is
    // no shared registry to confuse (the object model's core safety property).
    let a = MlsClient::create_group(b"a".to_vec(), tmp("a"), key()).unwrap();
    let b = MlsClient::create_group(b"b".to_vec(), tmp("b"), key()).unwrap();
    let id = a.enqueue(b"x".to_vec()).unwrap();
    assert_eq!(b.encrypt(id).unwrap_err(), MlsClientError::NotFound);
}

#[test]
fn repeated_open_close_cycles_do_not_panic() {
    for _ in 0..200 {
        let c = MlsClient::create_group(b"c".to_vec(), tmp("c"), key()).unwrap();
        let _ = c.enqueue(b"x".to_vec()).unwrap();
        c.close();
        assert_eq!(c.epoch().unwrap_err(), MlsClientError::Closed);
        drop(c);
    }
}

#[test]
fn concurrent_ops_on_one_handle_are_serialized() {
    let client = MlsClient::create_group(b"a".to_vec(), tmp("a"), key()).unwrap();
    let ids: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let threads = 8;
    let per = 50;
    let mut handles = Vec::new();
    for _ in 0..threads {
        let c = Arc::clone(&client);
        let ids = Arc::clone(&ids);
        handles.push(std::thread::spawn(move || {
            for _ in 0..per {
                let id = c.enqueue(b"m".to_vec()).unwrap();
                let _ = c.epoch().unwrap();
                ids.lock().unwrap().push(id);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let ids = ids.lock().unwrap();
    // All local ids distinct ⇒ the id counter was not raced (single-writer serialization holds).
    let unique: HashSet<u64> = ids.iter().copied().collect();
    assert_eq!(unique.len(), threads * per);
    assert!(
        client.epoch().is_ok(),
        "client still healthy after contention"
    );
}

#[test]
fn independent_clients_run_concurrently() {
    let a = MlsClient::create_group(b"a".to_vec(), tmp("a"), key()).unwrap();
    let b = MlsClient::create_group(b"b".to_vec(), tmp("b"), key()).unwrap();
    let ha = {
        let a = Arc::clone(&a);
        std::thread::spawn(move || {
            for _ in 0..100 {
                a.enqueue(b"x".to_vec()).unwrap();
            }
        })
    };
    let hb = {
        let b = Arc::clone(&b);
        std::thread::spawn(move || {
            for _ in 0..100 {
                b.enqueue(b"y".to_vec()).unwrap();
            }
        })
    };
    ha.join().unwrap();
    hb.join().unwrap();
    assert!(a.epoch().is_ok());
    assert!(b.epoch().is_ok());
}

#[test]
fn injected_panic_is_contained_as_internal_error() {
    let j = InMemoryJournal::new();
    let client = MlsClient::__test_active_in_memory(b"a", j.clone()).unwrap();
    j.panic_next_commit();
    // The panic in `commit` must be caught and mapped, not unwound across the (would-be) ABI.
    assert_eq!(
        client.enqueue(b"x".to_vec()).unwrap_err(),
        MlsClientError::Internal
    );
    // After a poisoning panic the client fails safe (still no panic).
    assert_eq!(client.epoch().unwrap_err(), MlsClientError::Internal);
}

#[test]
fn clean_journal_failure_surfaces_as_typed_error_without_corruption() {
    let j = InMemoryJournal::new();
    let client = MlsClient::__test_active_in_memory(b"a", j.clone()).unwrap();
    j.fail_next_commit();
    assert_eq!(
        client.enqueue(b"x".to_vec()).unwrap_err(),
        MlsClientError::Journal
    );
    // A clean commit failure (not a panic) does not poison the client: it stays usable, and the
    // failed enqueue left no partial state.
    assert!(client.epoch().is_ok());
    assert!(client.enqueue(b"y".to_vec()).is_ok());
}

#[test]
fn error_messages_are_redacted() {
    // Every variant's Display must be a coarse, fixed phrase — no key bytes, plaintext, or paths.
    let variants = [
        (MlsClientError::InputTooLarge, "input too large"),
        (MlsClientError::BadKeyLength, "at-rest key must be 32 bytes"),
        (
            MlsClientError::WrongState,
            "operation not valid in the client's current state",
        ),
        (MlsClientError::NotFound, "not found"),
        (MlsClientError::InvalidMessage, "invalid message"),
        (MlsClientError::NoSession, "no persisted session"),
        (MlsClientError::Journal, "storage error"),
        (MlsClientError::Closed, "client is closed"),
        (MlsClientError::Internal, "internal error"),
    ];
    for (e, expected) in variants {
        let s = format!("{e}");
        assert_eq!(s, expected);
        assert!(!s.contains('/'), "error leaked a path: {s}");
    }
}
