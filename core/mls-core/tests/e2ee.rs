//! End-to-end encryption property tests for the OpenMLS integration. These produce the
//! evidence behind THREAT_MODEL.md INV-1 ("the service never receives plaintext") and the
//! group-epoch guarantee (a removed member cannot read future messages).

use mls_core::{Incoming, Member};

/// Two members exchange an encrypted message and the ciphertext envelope contains no
/// plaintext. This is the property the server relies on: it routes these bytes blind.
#[test]
fn two_members_exchange_encrypted_message() {
    let alice = Member::new(b"alice-device").expect("alice");
    let bob = Member::new(b"bob-device").expect("bob");

    // Bob publishes a key package; Alice creates a group and adds Bob.
    let bob_kp = bob.key_package_bytes().expect("bob kp");
    let mut alice_group = alice.create_group().expect("group");
    let add = alice_group.add_member(&alice, &bob_kp).expect("add bob");

    // Bob joins from the welcome.
    let mut bob_group = bob.join_from_welcome(&add.welcome).expect("bob joins");
    assert_eq!(
        alice_group.epoch(),
        bob_group.epoch(),
        "same epoch after join"
    );

    // Alice encrypts a message.
    let plaintext = b"meet me at the safehouse at 0300";
    let envelope = alice_group.encrypt(&alice, plaintext).expect("encrypt");

    // INV-1 evidence: the on-the-wire envelope does not contain the plaintext.
    assert!(
        !contains(&envelope, plaintext),
        "ciphertext envelope must not contain plaintext"
    );

    // Bob decrypts it back.
    match bob_group.process(&bob, &envelope).expect("bob process") {
        Incoming::Application(bytes) => assert_eq!(bytes, plaintext),
        Incoming::StateAdvanced => panic!("expected application message"),
    }
}

/// A third party who never joined cannot decrypt the envelope.
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

    // Mallory has her own unrelated group and cannot process Alice's envelope.
    let mut mallory_group = mallory.create_group().expect("mallory group");
    assert!(
        mallory_group.process(&mallory, &envelope).is_err(),
        "an outsider must not be able to decrypt"
    );
}

/// Group epoch guarantee: after a member is removed, the removed member cannot decrypt
/// messages sent in the new epoch (post-compromise/forward membership security).
#[test]
fn removed_member_cannot_read_future_messages() {
    let alice = Member::new(b"alice").expect("alice");
    let bob = Member::new(b"bob").expect("bob");
    let carol = Member::new(b"carol").expect("carol");

    // Alice creates a group with Bob and Carol.
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

    // Alice removes Bob. Bob processing his own removal advances his state, but he is no
    // longer a member of the new epoch.
    let remove_commit = alice_group
        .remove_member(&alice, b"bob")
        .expect("remove bob");
    assert!(
        alice_group.epoch() > epoch_before,
        "epoch advances on removal"
    );

    // Carol applies the removal commit and stays in the group.
    carol_group
        .process(&carol, &remove_commit)
        .expect("carol processes removal");
    let _ = bob_group.process(&bob, &remove_commit); // Bob learns he was removed.

    // Alice sends a message in the NEW epoch.
    let envelope = alice_group
        .encrypt(&alice, b"post-removal secret")
        .expect("encrypt");

    // Carol (still a member) can read it.
    match carol_group.process(&carol, &envelope).expect("carol reads") {
        Incoming::Application(bytes) => assert_eq!(bytes, b"post-removal secret"),
        Incoming::StateAdvanced => panic!("expected application message"),
    }

    // Bob (removed) cannot.
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
