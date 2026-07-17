//! Tests for the RFC 6962 append-only Merkle transparency log (key transparency substrate, R-201).
//! The domain separation is anchored against the raw SHA-256 primitive; inclusion and consistency
//! proofs are property-tested across many tree sizes with negative (tamper) cases.

use auth_core::crypto::sha256;
use auth_core::transparency::{
    consistency_proof, encode_sth, hash_leaf, inclusion_proof, merkle_root, verify_consistency,
    verify_inclusion, Hash,
};

fn leaves(n: usize) -> Vec<Hash> {
    (0..n)
        .map(|i| hash_leaf(format!("binding-entry-{i}").as_bytes()))
        .collect()
}

/// Domain separation is exactly RFC 6962: empty tree = H(""), a leaf = H(0x00 || entry).
#[test]
fn hashing_matches_rfc6962_domain_separation() {
    assert_eq!(
        merkle_root(&[]),
        sha256(&[]),
        "empty tree hashes to H(\"\")"
    );
    assert_eq!(
        hash_leaf(b""),
        sha256(&[0x00]),
        "leaf hash = H(0x00 || entry)"
    );
    // A single-leaf tree's root IS that leaf's hash.
    let single = leaves(1);
    assert_eq!(merkle_root(&single), single[0]);
}

/// Every leaf, in every tree size up to 33, produces an inclusion proof that verifies against the
/// independently computed root — and tampering is rejected.
#[test]
fn inclusion_proofs_verify_and_reject_tampering() {
    for n in 1..=33 {
        let ls = leaves(n);
        let root = merkle_root(&ls);
        for i in 0..n {
            let proof = inclusion_proof(&ls, i);
            assert!(
                verify_inclusion(&ls[i], i, n, &proof, &root),
                "valid inclusion proof (n={n}, i={i})"
            );

            // Wrong leaf hash → reject.
            let wrong_leaf = hash_leaf(b"not-in-the-tree");
            assert!(
                !verify_inclusion(&wrong_leaf, i, n, &proof, &root),
                "wrong leaf must fail (n={n}, i={i})"
            );

            // Wrong root → reject.
            let mut bad_root = root;
            bad_root[0] ^= 0xff;
            assert!(!verify_inclusion(&ls[i], i, n, &proof, &bad_root));

            // Flipped proof node → reject (when there is one).
            if let Some(first) = proof.first() {
                let mut tampered = proof.clone();
                tampered[0] = {
                    let mut h = *first;
                    h[0] ^= 0xff;
                    h
                };
                assert!(!verify_inclusion(&ls[i], i, n, &tampered, &root));
            }

            // Wrong index (claim a neighbour position) → reject.
            if n > 1 {
                let other = (i + 1) % n;
                assert!(!verify_inclusion(&ls[i], other, n, &proof, &root));
            }
        }
    }
}

/// For every prefix size m of every tree size n, the consistency proof verifies — and a rewritten
/// history (any change to the first m leaves) is rejected.
#[test]
fn consistency_proofs_verify_and_detect_history_rewrite() {
    for n in 1..=33 {
        let ls = leaves(n);
        let second_hash = merkle_root(&ls);
        for m in 1..=n {
            let first_hash = merkle_root(&ls[..m]);
            let proof = consistency_proof(&ls, m);
            assert!(
                verify_consistency(m, n, &first_hash, &second_hash, &proof),
                "valid consistency proof (m={m}, n={n})"
            );

            if m < n {
                // Rewrite history: change leaf 0 in the big tree. The old prefix root no longer
                // reconciles with the (mutated) new root → must fail (append-only violated).
                let mut rewritten = ls.clone();
                rewritten[0] = hash_leaf(b"rewritten-history");
                let mutated_second = merkle_root(&rewritten);
                assert!(
                    !verify_consistency(m, n, &first_hash, &mutated_second, &proof),
                    "history rewrite must be detected (m={m}, n={n})"
                );

                // A wrong first_hash → reject.
                let mut bad_first = first_hash;
                bad_first[0] ^= 0xff;
                assert!(!verify_consistency(m, n, &bad_first, &second_hash, &proof));

                // A flipped proof node → reject.
                if let Some(first) = proof.first() {
                    let mut tampered = proof.clone();
                    tampered[0] = {
                        let mut h = *first;
                        h[0] ^= 0xff;
                        h
                    };
                    assert!(!verify_consistency(
                        m,
                        n,
                        &first_hash,
                        &second_hash,
                        &tampered
                    ));
                }
            }
        }
    }
}

/// The append-only picture end to end: growing the log one entry at a time, each new tree stays
/// consistent with every earlier one, and every earlier binding stays included under the new root.
#[test]
fn append_only_growth_preserves_inclusion_and_consistency() {
    let full = leaves(20);
    for n in 2..=full.len() {
        let root_n = merkle_root(&full[..n]);
        // Consistency with the immediately previous size.
        let root_prev = merkle_root(&full[..n - 1]);
        let cproof = consistency_proof(&full[..n], n - 1);
        assert!(verify_consistency(n - 1, n, &root_prev, &root_n, &cproof));
        // Every earlier leaf is still included under the new root.
        for i in 0..n {
            let iproof = inclusion_proof(&full[..n], i);
            assert!(verify_inclusion(&full[i], i, n, &iproof, &root_n));
        }
    }
}

/// STH encoding is deterministic, domain-prefixed, and injective across each field.
#[test]
fn sth_encoding_is_canonical() {
    let root = merkle_root(&leaves(5));
    let a = encode_sth(5, &root, 1_700_000_000);
    let b = encode_sth(5, &root, 1_700_000_000);
    assert_eq!(a, b, "deterministic");
    // Domain-separated: begins with the length-prefixed domain string.
    assert_eq!(&a[0..8], &(28u64).to_be_bytes()); // STH_DOMAIN is 28 bytes
    assert_eq!(&a[8..8 + 28], b"sentinel-transparency-sth-v1");
    // Each field participates: changing any one changes the bytes.
    assert_ne!(a, encode_sth(6, &root, 1_700_000_000), "tree_size matters");
    assert_ne!(
        a,
        encode_sth(5, &leaves(6).pop().unwrap(), 1_700_000_000),
        "root matters"
    );
    assert_ne!(a, encode_sth(5, &root, 1_700_000_001), "timestamp matters");
}
