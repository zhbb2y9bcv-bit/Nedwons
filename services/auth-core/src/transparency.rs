//! Append-only Merkle transparency log — the auditable substrate for key transparency (R-201).
//!
//! This is the **RFC 6962** (Certificate Transparency) Merkle tree, a mature, precisely specified
//! *standard* construction — not a novel protocol. It is deliberately NOT a from-scratch design:
//! the hashing and proof algorithms below follow RFC 6962 §2.1 verbatim.
//!
//! - Leaf hash:     `H(0x00 || entry)`
//! - Interior hash: `H(0x01 || left || right)`
//! - Split point:   the largest power of two strictly less than the subtree size.
//!
//! It provides two proofs a client verifies:
//! - **Inclusion**: a specific binding (account → device key) is present in the log at a given
//!   tree size — so the server cannot serve a key it never logged.
//! - **Consistency**: the tree at size *n* is an append-only extension of the tree at size *m<n*
//!   — so the server cannot rewrite history (retroactively swap a logged key).
//!
//! What this does **not** provide on its own (documented honestly in `docs/KEY_TRANSPARENCY.md`,
//! RISK_REGISTER R-201): protection from a server that shows *different* consistent logs to
//! different clients (split-view / equivocation — needs gossip / third-party witnesses), and
//! efficient verifiable *non-inclusion* / "this is the latest key" proofs (needs a verifiable map,
//! e.g. CONIKS/Parakeet). This module + client self-monitoring detects logged-key substitution and
//! history rewriting; it is **not** a complete anti-equivocation KT system and has not had a
//! specialised third-party audit. Manual safety-number verification remains the belt-and-suspenders.

use crate::crypto::sha256;

/// A 32-byte SHA-256 tree hash.
pub type Hash = [u8; 32];

/// Leaf hash of a log entry: `H(0x00 || entry)` (RFC 6962 §2.1).
pub fn hash_leaf(entry: &[u8]) -> Hash {
    let mut buf = Vec::with_capacity(1 + entry.len());
    buf.push(0x00);
    buf.extend_from_slice(entry);
    sha256(&buf)
}

/// Interior node hash: `H(0x01 || left || right)` (RFC 6962 §2.1).
fn hash_node(left: &Hash, right: &Hash) -> Hash {
    let mut buf = Vec::with_capacity(1 + 64);
    buf.push(0x01);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    sha256(&buf)
}

/// Largest power of two strictly less than `n` (defined for `n >= 2`).
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Merkle Tree Hash (root) over the given **leaf hashes** (each already `hash_leaf(entry)`).
/// The empty tree hashes to `H("")`, per RFC 6962.
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => sha256(&[]),
        1 => leaves[0],
        n => {
            let k = split(n);
            hash_node(&merkle_root(&leaves[..k]), &merkle_root(&leaves[k..]))
        }
    }
}

/// Inclusion (audit) path for the leaf at `index` in a tree of `leaves` (RFC 6962 §2.1.1 PATH).
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Vec<Hash> {
    let n = leaves.len();
    assert!(index < n, "index out of range");
    if n == 1 {
        return Vec::new();
    }
    let k = split(n);
    if index < k {
        let mut path = inclusion_proof(&leaves[..k], index);
        path.push(merkle_root(&leaves[k..]));
        path
    } else {
        let mut path = inclusion_proof(&leaves[k..], index - k);
        path.push(merkle_root(&leaves[..k]));
        path
    }
}

/// Verify an inclusion proof: reconstruct the root from `leaf_hash` at `index` in a tree of
/// `tree_size` and compare to `root` (RFC 6962 §2.1.1 verification algorithm).
pub fn verify_inclusion(
    leaf_hash: &Hash,
    index: usize,
    tree_size: usize,
    proof: &[Hash],
    root: &Hash,
) -> bool {
    if index >= tree_size {
        return false;
    }
    let mut fnn = index;
    let mut sn = tree_size - 1;
    let mut r = *leaf_hash;
    let mut it = proof.iter();
    while sn > 0 {
        let Some(p) = it.next() else { return false };
        if fnn & 1 == 1 || fnn == sn {
            r = hash_node(p, &r);
            if fnn & 1 == 0 {
                // Skip the run of trailing zero bits.
                while fnn & 1 == 0 && fnn != 0 {
                    fnn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = hash_node(&r, p);
        }
        fnn >>= 1;
        sn >>= 1;
    }
    it.next().is_none() && r == *root
}

/// Consistency proof that the tree of the first `first` leaves is a prefix of `leaves`
/// (RFC 6962 §2.1.2 PROOF/SUBPROOF). Requires `0 < first <= leaves.len()`.
pub fn consistency_proof(leaves: &[Hash], first: usize) -> Vec<Hash> {
    let n = leaves.len();
    assert!(first > 0 && first <= n, "first out of range");
    if first == n {
        return Vec::new();
    }
    let mut out = Vec::new();
    subproof(first, leaves, true, &mut out);
    out
}

fn subproof(m: usize, leaves: &[Hash], b: bool, out: &mut Vec<Hash>) {
    let n = leaves.len();
    if m == n {
        if !b {
            out.push(merkle_root(leaves));
        }
        return;
    }
    let k = split(n);
    if m <= k {
        subproof(m, &leaves[..k], b, out);
        out.push(merkle_root(&leaves[k..]));
    } else {
        subproof(m - k, &leaves[k..], false, out);
        out.push(merkle_root(&leaves[..k]));
    }
}

/// Verify a consistency proof between trees of size `first` (root `first_hash`) and `second`
/// (root `second_hash`) — RFC 6962 §2.1.2 verification algorithm.
pub fn verify_consistency(
    first: usize,
    second: usize,
    first_hash: &Hash,
    second_hash: &Hash,
    proof: &[Hash],
) -> bool {
    if first > second {
        return false;
    }
    if first == second {
        return proof.is_empty() && first_hash == second_hash;
    }
    if first == 0 {
        // Every tree is consistent with the empty tree; nothing to prove.
        return proof.is_empty();
    }

    // Step 2: if `first` is a power of two, the old root is not in the proof — seed with it.
    let mut path: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        path.push(*first_hash);
    }
    path.extend_from_slice(proof);
    if path.is_empty() {
        return false;
    }

    let mut fnn = first - 1;
    let mut sn = second - 1;
    while fnn & 1 == 1 {
        fnn >>= 1;
        sn >>= 1;
    }

    let mut it = path.into_iter();
    let seed = it.next().expect("path non-empty");
    let mut fr = seed;
    let mut sr = seed;

    for c in it {
        if sn == 0 {
            return false;
        }
        if fnn & 1 == 1 || fnn == sn {
            fr = hash_node(&c, &fr);
            sr = hash_node(&c, &sr);
            if fnn & 1 == 0 {
                while fnn & 1 == 0 && fnn != 0 {
                    fnn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = hash_node(&sr, &c);
        }
        fnn >>= 1;
        sn >>= 1;
    }

    fr == *first_hash && sr == *second_hash && sn == 0
}

/// Canonical, domain-separated, length-prefixed byte encoding of a Signed Tree Head, agreed
/// between the log server (which signs it) and clients (which verify). Mirrors the auth transcript
/// style so Swift/Kotlin re-encode identically. The server signs THIS with the log's key.
pub const STH_DOMAIN: &[u8] = b"nedwons-transparency-sth-v1";

pub fn encode_sth(tree_size: u64, root: &Hash, timestamp: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(STH_DOMAIN.len() + 8 + 8 + 32 + 8);
    // Domain, length-prefixed, then fixed-width big-endian fields — no ambiguity.
    out.extend_from_slice(&(STH_DOMAIN.len() as u64).to_be_bytes());
    out.extend_from_slice(STH_DOMAIN);
    out.extend_from_slice(&tree_size.to_be_bytes());
    out.extend_from_slice(root);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out
}
