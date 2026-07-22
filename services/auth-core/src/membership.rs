//! The canonical, domain-separated **membership manifest** (ADR-0010, R-506).
//!
//! A membership change reaches the relay as `(manifest, signature, opaque commit[, welcomes])`.
//! Because the relay is MLS-blind it cannot parse the commit, so the manifest is the *routing
//! claim*: the server verifies signature + authorization + epoch ordering + `commit_hash` binding,
//! and recipients verify the commit's actual effect matches it before merging — the correspondence
//! check the server cannot perform.
//!
//! Same injective discipline as [`crate::transcript`] (versioned domain tag, length-prefixed
//! fields, count-prefixed lists), so a v1 manifest signature can never be replayed as another
//! protocol object.

use crate::crypto::{sha256, verify_p256};
use crate::ids::{AccountId, DeviceId};

/// Versioned: a future manifest format re-tags (explicit protocol versioning, R-506).
pub const DOMAIN: &[u8] = b"app.nedwons.membership.v1";

/// One kind per commit in v1 — no mixed add+remove, which keeps every verifier simple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlType {
    /// A Welcome per added device travels with the commit.
    Add = 1,
    /// Admin action.
    Remove = 2,
    /// `removed` lists the actor's OWN devices (consent withdrawal, ADR-0009).
    Leave = 3,
}

impl ControlType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(ControlType::Add),
            2 => Some(ControlType::Remove),
            3 => Some(ControlType::Leave),
            _ => None,
        }
    }
}

/// `added` and `removed` MUST be sorted and duplicate-free, or the canonical encoding is ambiguous
/// between semantically-equal manifests. The server rejects unsorted input;
/// [`encode`](Manifest::encode) encodes exactly what it is given.
pub struct Manifest<'a> {
    pub control: ControlType,
    pub group_id: &'a [u8; 16],
    /// MLS epoch the commit was built against.
    pub prev_epoch: u64,
    /// Resulting epoch; MUST be `prev_epoch + 1`.
    pub next_epoch: u64,
    /// SHA-256 of the exact opaque commit ciphertext uploaded alongside.
    pub commit_hash: &'a [u8; 32],
    /// The committing device (must equal the authenticated device).
    pub actor_device: &'a DeviceId,
    pub added: &'a [(AccountId, DeviceId)],
    pub removed: &'a [DeviceId],
    /// Same precise scope as message sends: names ONE logical commit upload.
    pub idempotency_key: &'a [u8; 16],
    /// Bounds the in-transit replay window; the epoch CAS is the real anti-replay.
    pub expires_at: u64,
}

impl<'a> Manifest<'a> {
    /// The canonical byte string that is signed and hashed.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            4 + DOMAIN.len()
                + 1
                + (4 + 16)
                + 8
                + 8
                + (4 + 32)
                + (4 + 16)
                + 4
                + self.added.len() * (4 + 16 + 4 + 16)
                + 4
                + self.removed.len() * (4 + 16)
                + (4 + 16)
                + 8,
        );
        put_lp(&mut out, DOMAIN);
        out.push(self.control as u8);
        put_lp(&mut out, self.group_id);
        out.extend_from_slice(&self.prev_epoch.to_be_bytes());
        out.extend_from_slice(&self.next_epoch.to_be_bytes());
        put_lp(&mut out, self.commit_hash);
        put_lp(&mut out, self.actor_device.as_bytes());
        out.extend_from_slice(&(self.added.len() as u32).to_be_bytes());
        for (account, device) in self.added {
            put_lp(&mut out, account.as_bytes());
            put_lp(&mut out, device.as_bytes());
        }
        out.extend_from_slice(&(self.removed.len() as u32).to_be_bytes());
        for device in self.removed {
            put_lp(&mut out, device.as_bytes());
        }
        put_lp(&mut out, self.idempotency_key);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out
    }

    /// The manifest's identity in the audit log and the idempotency comparison.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.encode())
    }

    /// ECDSA-P256 against the actor's enrolled device key (SEC1). Fail-closed.
    pub fn verify(&self, actor_public_key_sec1: &[u8], signature: &[u8]) -> bool {
        verify_p256(actor_public_key_sec1, &self.encode(), signature)
    }
}

fn put_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// An owned, decoded manifest — what a recipient needs to run the correspondence check
/// (`added`/`removed` device identities) and, later, verify the signature.
#[derive(Debug, PartialEq, Eq)]
pub struct DecodedManifest {
    pub control: ControlType,
    pub group_id: [u8; 16],
    pub prev_epoch: u64,
    pub next_epoch: u64,
    pub commit_hash: [u8; 32],
    pub actor_device: [u8; 16],
    pub added: Vec<([u8; 16], [u8; 16])>,
    pub removed: Vec<[u8; 16]>,
    pub idempotency_key: [u8; 16],
    pub expires_at: u64,
}

/// Parse canonical manifest bytes. Returns `None` on any malformation (fail-closed) — a robust
/// cursor parser, so even though these bytes are server-stored it never panics on bad input. To
/// bound work, `added`/`removed` counts are capped.
pub fn decode(bytes: &[u8]) -> Option<DecodedManifest> {
    const MAX_LIST: u32 = 4096;
    let mut c = Cursor { b: bytes, i: 0 };
    if c.lp()? != DOMAIN {
        return None;
    }
    let control = ControlType::from_u8(c.u8()?)?;
    let group_id: [u8; 16] = c.lp()?.try_into().ok()?;
    let prev_epoch = c.u64()?;
    let next_epoch = c.u64()?;
    let commit_hash: [u8; 32] = c.lp()?.try_into().ok()?;
    let actor_device: [u8; 16] = c.lp()?.try_into().ok()?;
    let n_added = c.u32()?;
    if n_added > MAX_LIST {
        return None;
    }
    let mut added = Vec::with_capacity(n_added as usize);
    for _ in 0..n_added {
        let account: [u8; 16] = c.lp()?.try_into().ok()?;
        let device: [u8; 16] = c.lp()?.try_into().ok()?;
        added.push((account, device));
    }
    let n_removed = c.u32()?;
    if n_removed > MAX_LIST {
        return None;
    }
    let mut removed = Vec::with_capacity(n_removed as usize);
    for _ in 0..n_removed {
        removed.push(c.lp()?.try_into().ok()?);
    }
    let idempotency_key: [u8; 16] = c.lp()?.try_into().ok()?;
    let expires_at = c.u64()?;
    if c.i != c.b.len() {
        return None; // trailing bytes ⇒ not canonical
    }
    Some(DecodedManifest {
        control,
        group_id,
        prev_epoch,
        next_epoch,
        commit_hash,
        actor_device,
        added,
        removed,
        idempotency_key,
        expires_at,
    })
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.i.checked_add(n)?;
        let s = self.b.get(self.i..end)?;
        self.i = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn lp(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_bytes(added: &[(AccountId, DeviceId)], removed: &[DeviceId]) -> Vec<u8> {
        Manifest {
            control: ControlType::Add,
            group_id: &[7u8; 16],
            prev_epoch: 4,
            next_epoch: 5,
            commit_hash: &[9u8; 32],
            actor_device: &DeviceId([1u8; 16]),
            added,
            removed,
            idempotency_key: &[2u8; 16],
            expires_at: 1_000,
        }
        .encode()
    }

    /// Golden stability vector: changing these bytes is a wire-breaking protocol change and
    /// requires a domain-tag bump (v2).
    #[test]
    fn golden_vector_is_stable() {
        let added = [(AccountId([0xAAu8; 16]), DeviceId([0xBBu8; 16]))];
        let bytes = manifest_bytes(&added, &[]);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "000000196170702e6e6564776f6e732e6d656d626572736869702e7631010000001007070\
             707070707070707070707070707000000000000000400000000000000050000002009090909\
             090909090909090909090909090909090909090909090909090909090000001001010101010\
             1010101010101010101010000000100000010aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000\
             10bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00000000000000100202020202020202020202020\
             202020200000000000003e8"
                .replace(['\n', ' '], "")
        );
    }

    /// Distinct field vectors must never collide (injectivity via length/count prefixes).
    #[test]
    fn encoding_is_injective_across_field_moves() {
        let a1 = (AccountId([0xAAu8; 16]), DeviceId([0xBBu8; 16]));
        let a2 = (AccountId([0xCCu8; 16]), DeviceId([0xDDu8; 16]));
        let one_each = manifest_bytes(&[a1], &[DeviceId([0xCCu8; 16])]);
        let two_added = manifest_bytes(
            &[a1, (AccountId([0xCCu8; 16]), DeviceId([0xCCu8; 16]))],
            &[],
        );
        assert_ne!(
            one_each, two_added,
            "moving bytes between lists must change the encoding"
        );
        assert_ne!(manifest_bytes(&[a1], &[]), manifest_bytes(&[a2], &[]));
    }

    #[test]
    fn decode_round_trips_and_rejects_malformation() {
        let added = [
            (AccountId([0xAAu8; 16]), DeviceId([0xBBu8; 16])),
            (AccountId([0xCCu8; 16]), DeviceId([0xDDu8; 16])),
        ];
        let removed = [DeviceId([0xEEu8; 16])];
        let m = Manifest {
            control: ControlType::Remove,
            group_id: &[7u8; 16],
            prev_epoch: 41,
            next_epoch: 42,
            commit_hash: &[9u8; 32],
            actor_device: &DeviceId([1u8; 16]),
            added: &added,
            removed: &removed,
            idempotency_key: &[2u8; 16],
            expires_at: 1234,
        };
        let bytes = m.encode();
        let d = decode(&bytes).expect("decodes");
        assert_eq!(d.control, ControlType::Remove);
        assert_eq!(d.group_id, [7u8; 16]);
        assert_eq!(d.prev_epoch, 41);
        assert_eq!(d.next_epoch, 42);
        assert_eq!(d.commit_hash, [9u8; 32]);
        assert_eq!(d.actor_device, [1u8; 16]);
        assert_eq!(
            d.added,
            vec![([0xAAu8; 16], [0xBBu8; 16]), ([0xCCu8; 16], [0xDDu8; 16])]
        );
        assert_eq!(d.removed, vec![[0xEEu8; 16]]);
        assert_eq!(d.expires_at, 1234);

        // Malformations fail closed, never panic.
        assert!(decode(&[]).is_none());
        assert!(decode(&bytes[..bytes.len() - 1]).is_none()); // truncated
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_none()); // trailing bytes
        assert!(decode(b"app.nedwons.membership.v1 not really").is_none());
    }

    #[test]
    fn control_type_binds_the_signature() {
        let base = Manifest {
            control: ControlType::Remove,
            group_id: &[7u8; 16],
            prev_epoch: 4,
            next_epoch: 5,
            commit_hash: &[9u8; 32],
            actor_device: &DeviceId([1u8; 16]),
            added: &[],
            removed: &[DeviceId([3u8; 16])],
            idempotency_key: &[2u8; 16],
            expires_at: 1_000,
        };
        let leave = Manifest {
            control: ControlType::Leave,
            ..base
        };
        assert_ne!(base.encode(), leave.encode());
        assert_ne!(base.hash(), leave.hash());
    }

    #[test]
    fn sign_verify_round_trip_and_tamper_rejection() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        let signing = SigningKey::random(&mut rand_core::OsRng);
        let public = signing
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let removed = [DeviceId([3u8; 16])];
        let m = Manifest {
            control: ControlType::Remove,
            group_id: &[7u8; 16],
            prev_epoch: 4,
            next_epoch: 5,
            commit_hash: &[9u8; 32],
            actor_device: &DeviceId([1u8; 16]),
            added: &[],
            removed: &removed,
            idempotency_key: &[2u8; 16],
            expires_at: 1_000,
        };
        let sig: Signature = signing.sign(&m.encode());
        assert!(m.verify(&public, &sig.to_bytes()));

        // Any field change invalidates the signature.
        let tampered = Manifest {
            prev_epoch: 5,
            next_epoch: 6,
            ..m
        };
        assert!(!tampered.verify(&public, &sig.to_bytes()));
        // A different key does not verify.
        let other = SigningKey::random(&mut rand_core::OsRng);
        let other_pub = other
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let m2 = Manifest {
            prev_epoch: 4,
            next_epoch: 5,
            ..tampered
        };
        assert!(!m2.verify(&other_pub, &sig.to_bytes()));
    }
}
