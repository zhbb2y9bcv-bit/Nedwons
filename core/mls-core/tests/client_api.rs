//! Gate 2 first slice: the narrow, FFI-ready `ClientApi` must (1) carry a real two-party message
//! end to end through opaque handles, (2) reject oversized input before parsing, and (3) never
//! panic on malformed/hostile input — it returns a typed error instead. These run headlessly
//! (`cargo test`); the actual UniFFI packaging + on-device run is ADR-0007 / R-101.

use mls_core::client::{
    ClientApi, ClientError, Received, MAX_ENVELOPE_LEN, MAX_IDENTITY_LEN, MAX_PLAINTEXT_LEN,
};

/// Deterministic round trip: Alice creates a group, adds Bob via his key package, sends an
/// application message, and Bob decrypts exactly it — all through handles, no MLS objects crossing.
#[test]
fn two_party_round_trip_through_handles() {
    let api = ClientApi::new();

    let alice = api.create_identity(b"alice-device").expect("alice");
    let bob = api.create_identity(b"bob-device").expect("bob");

    let bob_kp = api.key_package(bob).expect("bob key package");
    let group = api.create_group(alice).expect("group");

    let added = api.add_member(group, alice, &bob_kp).expect("add bob");
    let bob_group = api
        .join_from_welcome(bob, &added.welcome)
        .expect("bob joins from welcome");

    // Deterministic: whatever the (random) ciphertext bytes, the decrypted plaintext is exact.
    let plaintext = b"deterministic-hello";
    let envelope = api.encrypt(group, alice, plaintext).expect("encrypt");

    // The envelope is opaque: it does not contain the plaintext (INV-1, at the client layer too).
    assert!(
        !contains(&envelope, plaintext),
        "ciphertext must not contain the plaintext"
    );

    match api
        .process(bob_group, bob, &envelope)
        .expect("bob processes")
    {
        Received::Application(bytes) => assert_eq!(bytes, plaintext),
        Received::StateAdvanced => panic!("expected application message, got a control message"),
    }

    // Adding a member advanced the epoch past genesis.
    assert!(api.epoch(group).expect("epoch") >= 1);
}

/// Oversized inputs are rejected up front, before any parsing/allocation.
#[test]
fn oversized_inputs_are_rejected() {
    let api = ClientApi::new();
    let alice = api.create_identity(b"alice").expect("alice");
    let group = api.create_group(alice).expect("group");

    assert_eq!(
        api.create_identity(&vec![0u8; MAX_IDENTITY_LEN + 1]),
        Err(ClientError::InputTooLarge)
    );
    assert_eq!(
        api.encrypt(group, alice, &vec![0u8; MAX_PLAINTEXT_LEN + 1]),
        Err(ClientError::InputTooLarge)
    );
    assert_eq!(
        api.process(group, alice, &vec![0u8; MAX_ENVELOPE_LEN + 1]),
        Err(ClientError::InputTooLarge)
    );
}

/// Unknown handles fail closed with a typed error, never a panic.
#[test]
fn unknown_handles_are_not_found() {
    let api = ClientApi::new();
    assert_eq!(api.key_package(999), Err(ClientError::NotFound));
    assert_eq!(api.create_group(999), Err(ClientError::NotFound));
    assert_eq!(api.epoch(999), Err(ClientError::NotFound));
    assert_eq!(api.encrypt(999, 999, b"x"), Err(ClientError::NotFound));
}

/// Malformed/hostile bytes must yield `InvalidMessage`, never crash the client. This is the
/// property a fuzzer will harden further (ADR-0007); here we assert it over a deterministic
/// corpus of garbage and near-miss buffers.
#[test]
fn malformed_input_never_panics() {
    let api = ClientApi::new();
    let alice = api.create_identity(b"alice").expect("alice");
    let bob = api.create_identity(b"bob").expect("bob");
    let group = api.create_group(alice).expect("group");

    // A pseudo-random but reproducible corpus (no rng dependency): byte patterns + a truncated,
    // otherwise-valid welcome/envelope.
    let mut corpus: Vec<Vec<u8>> = Vec::new();
    corpus.push(Vec::new()); // empty
    corpus.push(vec![0x00]); // single byte
    corpus.push(vec![0xff; 32]);
    for seed in 0u16..64 {
        let n = (seed as usize % 300) + 1;
        let buf: Vec<u8> = (0..n).map(|i| (i as u32 ^ seed as u32) as u8).collect();
        corpus.push(buf);
    }
    // Near-miss: a real key package with its last bytes chopped off.
    let mut truncated_kp = api.key_package(bob).expect("kp");
    truncated_kp.truncate(truncated_kp.len().saturating_sub(3));
    corpus.push(truncated_kp);

    for (i, buf) in corpus.iter().enumerate() {
        // process on garbage
        match api.process(group, alice, buf) {
            Err(ClientError::InvalidMessage) | Err(ClientError::InputTooLarge) => {}
            other => panic!("process corpus[{i}] returned {other:?}, expected a typed error"),
        }
        // join on garbage
        match api.join_from_welcome(bob, buf) {
            Ok(_) => panic!("garbage should never produce a valid group (corpus[{i}])"),
            Err(ClientError::InvalidMessage) | Err(ClientError::InputTooLarge) => {}
            Err(other) => panic!("join corpus[{i}] returned {other:?}"),
        }
        // add_member on garbage key package
        match api.add_member(group, alice, buf) {
            Ok(_) => panic!("garbage key package should not add a member (corpus[{i}])"),
            Err(ClientError::InvalidMessage) | Err(ClientError::InputTooLarge) => {}
            Err(other) => panic!("add_member corpus[{i}] returned {other:?}"),
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
