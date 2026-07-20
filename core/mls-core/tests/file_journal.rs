//! The production journal: an encrypted, atomically-written local store. Proves the blob is
//! ciphertext at rest, that tampering or a wrong key fails closed, and that a real DurableSession
//! survives a relaunch through the encrypted file.

use std::sync::atomic::{AtomicU64, Ordering};

use mls_core::durable::{
    Direction, DurableSession, FileJournal, InMemoryJournal, InboundOutcome, Journal,
};
use mls_core::Member;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_path(tag: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("nedwons-fj-{pid}-{nanos}-{n}-{tag}.bin"))
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let mut tmp = path.to_path_buf();
    let mut name = tmp.file_name().unwrap().to_os_string();
    name.push(".tmp");
    tmp.set_file_name(name);
    let _ = std::fs::remove_file(tmp);
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn round_trips_and_is_ciphertext_at_rest() {
    let path = temp_path("rt");
    let key = [3u8; 32];

    let mut journal = FileJournal::new(&path, &key);
    journal.commit(b"top-secret-plaintext").expect("commit");

    let raw = std::fs::read(&path).expect("read file");
    assert!(
        !contains(&raw, b"top-secret-plaintext"),
        "the blob must be encrypted at rest"
    );

    // A fresh journal (a relaunch) with the same path + key reads it back.
    let loaded = FileJournal::new(&path, &key).load().expect("load");
    assert_eq!(loaded, Some(b"top-secret-plaintext".to_vec()));

    cleanup(&path);
}

#[test]
fn wrong_key_fails_closed() {
    let path = temp_path("wk");
    FileJournal::new(&path, &[1u8; 32])
        .commit(b"authentic")
        .expect("commit");

    let result = FileJournal::new(&path, &[2u8; 32]).load();
    assert!(result.is_err(), "a wrong key must not decrypt");
    cleanup(&path);
}

#[test]
fn tamper_fails_closed() {
    let path = temp_path("tp");
    let key = [9u8; 32];
    FileJournal::new(&path, &key)
        .commit(b"authentic")
        .expect("commit");

    // Flip a ciphertext byte.
    let mut raw = std::fs::read(&path).expect("read");
    let last = raw.len() - 1;
    raw[last] ^= 0xff;
    std::fs::write(&path, &raw).expect("write");

    assert!(
        FileJournal::new(&path, &key).load().is_err(),
        "GCM must reject tampered ciphertext"
    );
    cleanup(&path);
}

#[test]
fn missing_file_is_none() {
    let path = temp_path("missing"); // never created
    let loaded = FileJournal::new(&path, &[0u8; 32]).load().expect("load");
    assert_eq!(loaded, None);
}

#[test]
fn commit_is_atomic_no_temp_left_behind() {
    let path = temp_path("atomic");
    let key = [4u8; 32];
    let mut journal = FileJournal::new(&path, &key);
    journal.commit(b"v1").expect("commit v1");
    journal.commit(b"v2").expect("commit v2");

    // The temp file must not linger after a successful rename.
    let mut tmp = path.clone();
    let mut name = tmp.file_name().unwrap().to_os_string();
    name.push(".tmp");
    tmp.set_file_name(name);
    assert!(
        !tmp.exists(),
        "temp file must be renamed away, not left behind"
    );

    // The target holds the latest committed value.
    assert_eq!(
        FileJournal::new(&path, &key).load().expect("load"),
        Some(b"v2".to_vec())
    );
    cleanup(&path);
}

#[test]
fn durable_session_survives_relaunch_over_encrypted_file() {
    let path = temp_path("sess");
    let key = [5u8; 32];

    // Low-level async add, then adopt Alice over the encrypted file journal.
    let alice = Member::new(b"alice-device").expect("alice");
    let bob = Member::new(b"bob-device").expect("bob");
    let bob_kp = bob.key_package_bytes().expect("kp");
    let mut alice_group = alice.create_group().expect("group");
    let add = alice_group.add_member(&alice, &bob_kp).expect("add");
    let bob_group = bob.join_from_welcome(&add.welcome).expect("join");

    let mut da =
        DurableSession::adopt(alice, alice_group, FileJournal::new(&path, &key)).expect("adopt");
    let mut db = DurableSession::adopt(bob, bob_group, InMemoryJournal::new()).expect("adopt bob");

    let id = da.enqueue(b"file-backed-secret").expect("enqueue");
    let ct = da.encrypt(id).expect("encrypt");
    assert!(matches!(
        db.process_inbound(1, &ct).expect("process"),
        InboundOutcome::Application(p) if p == b"file-backed-secret"
    ));

    // The on-disk session must not contain the plaintext.
    let raw = std::fs::read(&path).expect("read");
    assert!(
        !contains(&raw, b"file-backed-secret"),
        "session blob is encrypted"
    );

    // Relaunch Alice from the encrypted file: her outbound message is still there.
    drop(da);
    let da2 = DurableSession::open(FileJournal::new(&path, &key)).expect("reopen");
    let outbound = da2
        .messages()
        .iter()
        .filter(|m| m.direction == Direction::Outbound)
        .count();
    assert_eq!(outbound, 1);

    // A wrong key cannot reopen the session.
    assert!(
        DurableSession::open(FileJournal::new(&path, &[0u8; 32])).is_err(),
        "wrong key must fail to open the session"
    );

    cleanup(&path);
}
