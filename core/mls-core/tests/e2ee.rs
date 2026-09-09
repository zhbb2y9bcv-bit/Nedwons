//! Evidence behind THREAT_MODEL.md INV-1 ("the service never receives plaintext") and the
//! group-epoch guarantee (a removed member cannot read future messages).

use mls_core::{Incoming, Member};

/// The property the server relies on: it routes these bytes blind.
#[test]
fn two_members_exchange_encrypted_message() {
    let alice = Member::new(b"alice-device").expect("alice");
    let bob = Member::new(b"bob-device").expect("bob");

    let bob_kp = bob.key_package_bytes().expect("bob kp");
    let mut alice_group = alice.create_group().expect("group");
    let add = alice_group.add_member(&alice, &bob_kp).expect("add bob");

    let mut bob_group = bob.join_from_welcome(&add.welcome).expect("bob joins");
    assert_eq!(
        alice_group.epoch(),
        bob_group.epoch(),
        "same epoch after join"
    );

    let plaintext = b"meet me at the safehouse at 0300";
    let envelope = alice_group.encrypt(&alice, plaintext).expect("encrypt");

    // INV-1 evidence.
    assert!(
        !contains(&envelope, plaintext),
        "ciphertext envelope must not contain plaintext"
    );

    match bob_group.process(&bob, &envelope).expect("bob process") {
        Incoming::Application { payload: bytes, .. } => assert_eq!(bytes, plaintext),
        Incoming::StateAdvanced => panic!("expected application message"),
    }
}

#[test]
fn outsider_cannot_decrypt() {
    let alice = Member::new(b"alice").expect("alice");
    let bob = Member::new(b"bob").expect("bob");
    let mallory = Member::new(b"mallory").expect("mallory");

    let mut alice_group = alice.create_group().expect("group");
    let add = alice_group
        .add_member(&alice, &bob.key_package_bytes().unwrap())
        .expect("add bob");
    let _bob_group = bob.join_from_welcome(&add.welcome).expect("bob joins");

    let envelope = alice_group.encrypt(&alice, b"secret").expect("encrypt");

    let mut mallory_group = mallory.create_group().expect("mallory group");
    assert!(
        mallory_group.process(&mallory, &envelope).is_err(),
        "an outsider must not be able to decrypt"
    );
}

/// Epoch guarantee: a removed member cannot decrypt messages sent in the new epoch.
#[test]
fn removed_member_cannot_read_future_messages() {
    let alice = Member::new(b"alice").expect("alice");
    let bob = Member::new(b"bob").expect("bob");
    let carol = Member::new(b"carol").expect("carol");

    let mut alice_group = alice.create_group().expect("group");
    let add_bob = alice_group
        .add_member(&alice, &bob.key_package_bytes().unwrap())
        .expect("add bob");
    let mut bob_group = bob.join_from_welcome(&add_bob.welcome).expect("bob joins");

    let add_carol = alice_group
        .add_member(&alice, &carol.key_package_bytes().unwrap())
        .expect("add carol");
    // Bob must process the commit that adds Carol so his state stays in sync.
    bob_group
        .process(&bob, &add_carol.commit)
        .expect("bob processes add-carol commit");
    let mut carol_group = carol
        .join_from_welcome(&add_carol.welcome)
        .expect("carol joins");

    let epoch_before = alice_group.epoch();

    let remove_commit = alice_group
        .remove_member(&alice, b"bob")
        .expect("remove bob");
    assert!(
        alice_group.epoch() > epoch_before,
        "epoch advances on removal"
    );

    carol_group
        .process(&carol, &remove_commit)
        .expect("carol processes removal");
    let _ = bob_group.process(&bob, &remove_commit); // Bob learns he was removed.

    // A message in the NEW epoch: Carol (still a member) reads it, Bob (removed) cannot.
    let envelope = alice_group
        .encrypt(&alice, b"post-removal secret")
        .expect("encrypt");

    match carol_group.process(&carol, &envelope).expect("carol reads") {
        Incoming::Application { payload: bytes, .. } => assert_eq!(bytes, b"post-removal secret"),
        Incoming::StateAdvanced => panic!("expected application message"),
    }

    assert!(
        bob_group.process(&bob, &envelope).is_err(),
        "a removed member must not decrypt future-epoch messages"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The cross-epoch race real multi-device traffic hits constantly: bob sends BEFORE processing
/// the commit that added carol, so his message is encrypted at the old epoch. Members who already
/// merged must still decrypt it (`MAX_PAST_EPOCHS`) — with the default of zero past epochs the
/// message would be silently lost, which is exactly what the reconcile loop must never cause.
#[test]
fn message_from_a_member_one_epoch_behind_still_decrypts() {
    let alice = Member::new(b"alice").expect("alice");
    let bob = Member::new(b"bob").expect("bob");
    let carol = Member::new(b"carol").expect("carol");

    let mut alice_group = alice.create_group().expect("group");
    let add_bob = alice_group
        .add_member(&alice, &bob.key_package_bytes().unwrap())
        .expect("add bob");
    let mut bob_group = bob.join_from_welcome(&add_bob.welcome).expect("bob joins");

    // Alice adds carol and merges (epoch N+1). Bob has NOT seen that commit yet.
    let add_carol = alice_group
        .add_member(&alice, &carol.key_package_bytes().unwrap())
        .expect("add carol");
    let mut carol_group = carol
        .join_from_welcome(&add_carol.welcome)
        .expect("carol joins");
    let stale_envelope = bob_group
        .encrypt(&bob, b"sent while one epoch behind")
        .expect("encrypt at old epoch");

    // Alice (merged) decrypts bob's old-epoch message thanks to the retained window.
    match alice_group
        .process(&alice, &stale_envelope)
        .expect("alice reads")
    {
        Incoming::Application { payload, .. } => {
            assert_eq!(payload, b"sent while one epoch behind")
        }
        Incoming::StateAdvanced => panic!("expected application message"),
    }
    // Carol joined at N+1 and never had epoch-N keys: for her the message is honestly
    // undecryptable — pre-join history is never readable, window or no window.
    assert!(carol_group.process(&carol, &stale_envelope).is_err());

    // Bob catches up and future messages flow normally at the shared epoch.
    bob_group
        .process(&bob, &add_carol.commit)
        .expect("bob merges the add");
    let fresh = alice_group
        .encrypt(&alice, b"all caught up")
        .expect("encrypt");
    match bob_group.process(&bob, &fresh).expect("bob reads") {
        Incoming::Application { payload, .. } => assert_eq!(payload, b"all caught up"),
        Incoming::StateAdvanced => panic!("expected application message"),
    }
}
