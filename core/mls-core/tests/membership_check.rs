//! ADR-0010 client-side correspondence check: a recipient merges a commit ONLY if its actual
//! cryptographic effect (adds/removes read from the staged, un-merged commit) equals the sender's
//! signed membership manifest. A lying manifest must leave group state untouched.

use mls_core::{Incoming, Member, MlsError};

#[test]
fn matching_add_commit_is_merged_and_group_advances() {
    let alice = Member::new(b"alice-device").unwrap();
    let bob = Member::new(b"bob-device").unwrap();
    let carol = Member::new(b"carol-device").unwrap();

    let mut group_a = alice.create_group().unwrap();
    let add_bob = group_a
        .add_member(&alice, &bob.key_package_bytes().unwrap())
        .unwrap();
    let mut group_b = bob.join_from_welcome(&add_bob.welcome).unwrap();

    // Alice adds Carol; Bob verifies the commit against the (honest) manifest before merging.
    let add_carol = group_a
        .add_member(&alice, &carol.key_package_bytes().unwrap())
        .unwrap();
    let expected_next = group_b.epoch() + 1;
    group_b
        .process_commit_checked(
            &bob,
            &add_carol.commit,
            expected_next,
            &[b"carol-device".to_vec()],
            &[],
        )
        .unwrap();
    assert_eq!(group_b.epoch(), group_a.epoch());

    // The advanced group really works: Carol joins and reads Alice's next message.
    let mut group_c = carol.join_from_welcome(&add_carol.welcome).unwrap();
    let envelope = group_a.encrypt(&alice, b"hi all").unwrap();
    match group_c.process(&carol, &envelope).unwrap() {
        Incoming::Application(pt) => assert_eq!(pt, b"hi all"),
        _ => panic!("expected application message"),
    }
}

#[test]
fn lying_manifest_is_refused_and_state_does_not_advance() {
    let alice = Member::new(b"alice-device").unwrap();
    let bob = Member::new(b"bob-device").unwrap();
    let mallory = Member::new(b"mallory-device").unwrap();

    let mut group_a = alice.create_group().unwrap();
    let add_bob = group_a
        .add_member(&alice, &bob.key_package_bytes().unwrap())
        .unwrap();
    let mut group_b = bob.join_from_welcome(&add_bob.welcome).unwrap();

    // Alice's commit ACTUALLY adds mallory-device, but the manifest CLAIMS it adds carol-device.
    let add_mallory = group_a
        .add_member(&alice, &mallory.key_package_bytes().unwrap())
        .unwrap();
    let epoch_before = group_b.epoch();
    let err = group_b
        .process_commit_checked(
            &bob,
            &add_mallory.commit,
            epoch_before + 1,
            &[b"carol-device".to_vec()], // the lie
            &[],
        )
        .unwrap_err();
    assert!(matches!(err, MlsError::ManifestMismatch));
    assert_eq!(group_b.epoch(), epoch_before, "state must not follow a lie");

    // One-shot reality (forward secrecy): processing the commit consumed its decryption secret,
    // so the SAME bytes cannot be re-processed even with an honest manifest — after refusing a
    // lie, the member is desynced by design and must resync via re-add (ADR-0010).
    assert!(group_b
        .process_commit_checked(
            &bob,
            &add_mallory.commit,
            epoch_before + 1,
            &[b"mallory-device".to_vec()],
            &[],
        )
        .is_err());

    // The desync is real: Bob cannot read Alice's next-epoch traffic (he refused the advance),
    // which is exactly the signal that triggers the resync path.
    let post_lie = group_a.encrypt(&alice, b"next epoch").unwrap();
    assert!(group_b.process(&bob, &post_lie).is_err());
}

#[test]
fn honest_remove_commit_is_verified_and_merged() {
    let alice = Member::new(b"alice-device").unwrap();
    let bob = Member::new(b"bob-device").unwrap();
    let carol = Member::new(b"carol-device").unwrap();

    let mut group_a = alice.create_group().unwrap();
    let add_bob = group_a
        .add_member(&alice, &bob.key_package_bytes().unwrap())
        .unwrap();
    let mut group_b = bob.join_from_welcome(&add_bob.welcome).unwrap();
    let add_carol = group_a
        .add_member(&alice, &carol.key_package_bytes().unwrap())
        .unwrap();
    group_b
        .process_commit_checked(
            &bob,
            &add_carol.commit,
            group_b.epoch() + 1,
            &[b"carol-device".to_vec()],
            &[],
        )
        .unwrap();

    // Removed leaves resolve against the PRE-merge member list, so the manifest names Carol.
    let remove_carol = group_a.remove_member(&alice, b"carol-device").unwrap();
    group_b
        .process_commit_checked(
            &bob,
            &remove_carol,
            group_b.epoch() + 1,
            &[],
            &[b"carol-device".to_vec()],
        )
        .unwrap();
    assert_eq!(group_b.epoch(), group_a.epoch());
}

#[test]
fn lying_remove_manifest_is_refused() {
    let alice = Member::new(b"alice-device").unwrap();
    let bob = Member::new(b"bob-device").unwrap();
    let carol = Member::new(b"carol-device").unwrap();

    let mut group_a = alice.create_group().unwrap();
    let add_bob = group_a
        .add_member(&alice, &bob.key_package_bytes().unwrap())
        .unwrap();
    let mut group_b = bob.join_from_welcome(&add_bob.welcome).unwrap();
    let add_carol = group_a
        .add_member(&alice, &carol.key_package_bytes().unwrap())
        .unwrap();
    group_b
        .process_commit_checked(
            &bob,
            &add_carol.commit,
            group_b.epoch() + 1,
            &[b"carol-device".to_vec()],
            &[],
        )
        .unwrap();

    // Alice removes Carol but the manifest CLAIMS she removed Bob: refused, state unchanged.
    let remove_carol = group_a.remove_member(&alice, b"carol-device").unwrap();
    let epoch_before = group_b.epoch();
    let err = group_b
        .process_commit_checked(
            &bob,
            &remove_carol,
            epoch_before + 1,
            &[],
            &[b"bob-device".to_vec()], // the lie
        )
        .unwrap_err();
    assert!(matches!(err, MlsError::ManifestMismatch));
    assert_eq!(group_b.epoch(), epoch_before);
}

#[test]
fn wrong_next_epoch_is_refused_without_touching_state() {
    let alice = Member::new(b"alice-device").unwrap();
    let bob = Member::new(b"bob-device").unwrap();
    let carol = Member::new(b"carol-device").unwrap();

    let mut group_a = alice.create_group().unwrap();
    let add_bob = group_a
        .add_member(&alice, &bob.key_package_bytes().unwrap())
        .unwrap();
    let mut group_b = bob.join_from_welcome(&add_bob.welcome).unwrap();
    let add_carol = group_a
        .add_member(&alice, &carol.key_package_bytes().unwrap())
        .unwrap();

    let epoch_before = group_b.epoch();
    let err = group_b
        .process_commit_checked(
            &bob,
            &add_carol.commit,
            epoch_before + 7, // manifest claims a skipped epoch
            &[b"carol-device".to_vec()],
            &[],
        )
        .unwrap_err();
    assert!(matches!(err, MlsError::ManifestMismatch));
    assert_eq!(group_b.epoch(), epoch_before);
}

#[test]
fn application_message_cannot_satisfy_a_manifest() {
    let alice = Member::new(b"alice-device").unwrap();
    let bob = Member::new(b"bob-device").unwrap();

    let mut group_a = alice.create_group().unwrap();
    let add_bob = group_a
        .add_member(&alice, &bob.key_package_bytes().unwrap())
        .unwrap();
    let mut group_b = bob.join_from_welcome(&add_bob.welcome).unwrap();

    let envelope = group_a.encrypt(&alice, b"not a commit").unwrap();
    let err = group_b
        .process_commit_checked(&bob, &envelope, group_b.epoch() + 1, &[], &[])
        .unwrap_err();
    assert!(matches!(err, MlsError::ManifestMismatch));
}

// ----- Staged commits (ADR-0010): the proposer must not advance until the server confirms -----

#[test]
fn staged_add_is_not_applied_until_merged() {
    let alice = Member::new(b"alice-device").unwrap();
    let bob = Member::new(b"bob-device").unwrap();
    let carol = Member::new(b"carol-device").unwrap();

    let mut group_a = alice.create_group().unwrap();
    let add_bob = group_a
        .add_member(&alice, &bob.key_package_bytes().unwrap())
        .unwrap();
    let mut group_b = bob.join_from_welcome(&add_bob.welcome).unwrap();
    let epoch = group_a.epoch();

    // Stage adding carol: commit built, but the epoch has NOT advanced.
    let staged = group_a
        .stage_add_member(&alice, &carol.key_package_bytes().unwrap())
        .unwrap();
    assert_eq!(group_a.epoch(), epoch, "staging must not advance the epoch");

    // The server accepted (epoch CAS won): merge. Now the epoch advances and bob follows via the
    // checked path with the honest manifest.
    group_a.merge_staged(&alice).unwrap();
    assert_eq!(group_a.epoch(), epoch + 1);
    group_b
        .process_commit_checked(
            &bob,
            &staged.commit,
            epoch + 1,
            &[b"carol-device".to_vec()],
            &[],
        )
        .unwrap();
    assert_eq!(group_b.epoch(), group_a.epoch());
}

#[test]
fn discarded_stage_leaves_state_untouched_and_can_be_rebuilt() {
    let alice = Member::new(b"alice-device").unwrap();
    let bob = Member::new(b"bob-device").unwrap();
    let carol = Member::new(b"carol-device").unwrap();

    let mut group_a = alice.create_group().unwrap();
    let add_bob = group_a
        .add_member(&alice, &bob.key_package_bytes().unwrap())
        .unwrap();
    let _ = bob.join_from_welcome(&add_bob.welcome).unwrap();
    let epoch = group_a.epoch();

    // Stage, then the server REJECTED (stale epoch): discard. State is unchanged.
    let _ = group_a
        .stage_add_member(&alice, &carol.key_package_bytes().unwrap())
        .unwrap();
    group_a.clear_staged(&alice).unwrap();
    assert_eq!(
        group_a.epoch(),
        epoch,
        "a discarded stage must not advance the epoch"
    );

    // After discarding, the group is healthy: it can send, and it can stage+merge a fresh commit.
    let _ = group_a.encrypt(&alice, b"still working").unwrap();
    let dave = Member::new(b"dave-device").unwrap();
    let staged = group_a
        .stage_add_member(&alice, &dave.key_package_bytes().unwrap())
        .unwrap();
    group_a.merge_staged(&alice).unwrap();
    assert_eq!(group_a.epoch(), epoch + 1);
    // The rebuilt commit is real: dave joins from its welcome.
    let mut group_d = dave.join_from_welcome(&staged.welcome).unwrap();
    let envelope = group_a.encrypt(&alice, b"hi dave").unwrap();
    match group_d.process(&dave, &envelope).unwrap() {
        Incoming::Application(pt) => assert_eq!(pt, b"hi dave"),
        _ => panic!("expected application message"),
    }
}
