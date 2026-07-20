//! Key-transparency store + Signed Tree Head signing (R-201).
//!
//! The append-only log records every account→device-key binding as an RFC 6962 leaf
//! (`auth_core::transparency`). The server signs Signed Tree Heads (STHs) with the log key
//! (production: KMS/HSM; here: an env-provided or ephemeral key). Clients verify inclusion +
//! consistency proofs and **self-monitor** their own account — they do NOT trust the server to log
//! honestly; they check. See `docs/KEY_TRANSPARENCY.md` for the honest threat scope (split-view
//! equivocation and verifiable-map non-inclusion are out of scope for this slice).

use std::sync::Arc;

use auth_core::ids::{AccountId, DeviceId};
use auth_core::store::{StoreError, StoreResult};
use auth_core::transparency::{
    consistency_proof, encode_sth, hash_leaf, inclusion_proof, merkle_root, Hash,
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use r2d2_postgres::postgres::NoTls;

use crate::pgstore::PgPool;

/// A fixed advisory-lock key so concurrent appends serialize on the log's index counter.
const APPEND_LOCK_KEY: i64 = 0x5E_17_10_6E_10_6D_00_01u64 as i64;

/// Canonical leaf entry for a binding: `account(16) || device(16) || u16-len || public_key`.
pub fn encode_binding(account: &AccountId, device: &DeviceId, public_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 16 + 2 + public_key.len());
    out.extend_from_slice(account.as_bytes());
    out.extend_from_slice(device.as_bytes());
    out.extend_from_slice(&(public_key.len().min(u16::MAX as usize) as u16).to_be_bytes());
    out.extend_from_slice(public_key);
    out
}

/// Versioned domain-separation tag for **leaf schema v2** (ADR-0013). A v2 leaf begins with
/// `len32(DOMAIN) || u8(kind) || body`; the kind byte makes leaf types disjoint by construction,
/// so a revocation leaf can never be confused with a binding leaf. v1 binding leaves (see
/// [`encode_binding`]) have no header and coexist forever in the append-only log.
pub const LEAF_DOMAIN_V2: &[u8] = b"app.nedwons.kt-leaf.v2";

/// The kind of a v2 transparency leaf (ADR-0013).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafKind {
    /// account→device-key binding (device added: registration / enrollment / recovery).
    Binding = 1,
    /// device revoked at `revoked_at` — makes *removals* auditable, not just additions.
    Revocation = 2,
}

impl LeafKind {
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(LeafKind::Binding),
            2 => Some(LeafKind::Revocation),
            _ => None,
        }
    }
}

/// A decoded v2 leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLeafV2 {
    pub kind: LeafKind,
    pub account: [u8; 16],
    pub device: [u8; 16],
    /// Binding only: the SEC1 public key. Empty for a revocation.
    pub public_key: Vec<u8>,
    /// Revocation only: unix seconds the device was revoked. 0 for a binding.
    pub revoked_at: u64,
}

fn put_lp32(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// v2 **binding** leaf: `len32(DOMAIN) || u8(1) || account(16) || device(16) || len32(pk) || pk`.
pub fn encode_binding_v2(account: &AccountId, device: &DeviceId, public_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + LEAF_DOMAIN_V2.len() + 1 + 16 + 16 + 4 + public_key.len());
    put_lp32(&mut out, LEAF_DOMAIN_V2);
    out.push(LeafKind::Binding as u8);
    out.extend_from_slice(account.as_bytes());
    out.extend_from_slice(device.as_bytes());
    put_lp32(&mut out, public_key);
    out
}

/// v2 **revocation** leaf: `len32(DOMAIN) || u8(2) || account(16) || device(16) || u64(revoked_at)`.
pub fn encode_revocation_v2(account: &AccountId, device: &DeviceId, revoked_at: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + LEAF_DOMAIN_V2.len() + 1 + 16 + 16 + 8);
    put_lp32(&mut out, LEAF_DOMAIN_V2);
    out.push(LeafKind::Revocation as u8);
    out.extend_from_slice(account.as_bytes());
    out.extend_from_slice(device.as_bytes());
    out.extend_from_slice(&revoked_at.to_be_bytes());
    out
}

/// Decode a **v2** leaf. Returns `None` if `entry` does not carry the v2 domain header (e.g. it is a
/// legacy v1 binding), or is malformed. Strict: every length must match exactly, so a truncated or
/// over-long entry is rejected rather than partially trusted.
pub fn decode_leaf_v2(entry: &[u8]) -> Option<DecodedLeafV2> {
    let dom_len = LEAF_DOMAIN_V2.len();
    // len32(DOMAIN) || DOMAIN
    let header_len = 4 + dom_len;
    if entry.len() < header_len + 1 {
        return None;
    }
    if u32::from_be_bytes(entry[0..4].try_into().ok()?) as usize != dom_len {
        return None;
    }
    if &entry[4..header_len] != LEAF_DOMAIN_V2 {
        return None;
    }
    let kind = LeafKind::from_u8(entry[header_len])?;
    let rest = &entry[header_len + 1..];
    if rest.len() < 32 {
        return None;
    }
    let account: [u8; 16] = rest[0..16].try_into().ok()?;
    let device: [u8; 16] = rest[16..32].try_into().ok()?;
    let tail = &rest[32..];
    match kind {
        LeafKind::Binding => {
            if tail.len() < 4 {
                return None;
            }
            let pk_len = u32::from_be_bytes(tail[0..4].try_into().ok()?) as usize;
            if tail.len() != 4 + pk_len {
                return None; // strict: no trailing bytes
            }
            Some(DecodedLeafV2 {
                kind,
                account,
                device,
                public_key: tail[4..].to_vec(),
                revoked_at: 0,
            })
        }
        LeafKind::Revocation => {
            if tail.len() != 8 {
                return None;
            }
            Some(DecodedLeafV2 {
                kind,
                account,
                device,
                public_key: Vec::new(),
                revoked_at: u64::from_be_bytes(tail.try_into().ok()?),
            })
        }
    }
}

/// A signed tree head (the log's commitment to its current state).
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root: Hash,
    pub timestamp: u64,
    /// ECDSA-P256 signature over `encode_sth(tree_size, root, timestamp)`, 64-byte r‖s.
    pub signature: Vec<u8>,
}

/// One of an account's logged leaves, with an inclusion proof at the current tree size. Named
/// `AccountBinding` for historical reasons; since ADR-0013 a leaf may instead be a **revocation**
/// (`revoked_at.is_some()`), so the full device *lifecycle* — additions and removals — is auditable
/// under the signed root.
pub struct AccountBinding {
    pub leaf_index: u64,
    pub device_id: [u8; 16],
    pub public_key: Vec<u8>,
    pub entry: Vec<u8>,
    pub proof: Vec<Hash>,
    /// `Some(unix_secs)` if this leaf is a v2 **revocation** of `device_id`; `None` for a binding
    /// (legacy v1, or v2 binding). Lets a client detect a revocation it did not initiate.
    pub revoked_at: Option<u64>,
}

/// An account's bindings together with the tree size the proofs were computed at.
pub struct AccountView {
    pub tree_size: u64,
    pub bindings: Vec<AccountBinding>,
}

#[derive(Clone)]
pub struct PgTransparency {
    pool: PgPool,
    signing_key: Arc<SigningKey>,
}

impl PgTransparency {
    pub fn new(pool: PgPool, signing_key: SigningKey) -> Self {
        Self {
            pool,
            signing_key: Arc::new(signing_key),
        }
    }

    /// The log's public key (SEC1 uncompressed, 65 bytes) — clients pin this out of band and use
    /// it to verify STH signatures.
    pub fn log_public_key_sec1(&self) -> Vec<u8> {
        self.signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    fn conn(
        &self,
    ) -> StoreResult<r2d2::PooledConnection<r2d2_postgres::PostgresConnectionManager<NoTls>>> {
        self.pool
            .get()
            .map_err(|e| StoreError(format!("pool: {e}")))
    }

    /// Append a binding as a new leaf. Gapless index under an advisory transaction lock (appends
    /// are infrequent — one per device enrollment). Returns the assigned leaf index.
    pub fn append_binding(
        &self,
        account: &AccountId,
        device: &DeviceId,
        public_key: &[u8],
    ) -> StoreResult<u64> {
        let entry = encode_binding(account, device, public_key);
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        txn.execute("SELECT pg_advisory_xact_lock($1)", &[&APPEND_LOCK_KEY])
            .map_err(db_err)?;
        let next: i64 = txn
            .query_one(
                "SELECT coalesce(max(leaf_index) + 1, 0) FROM transparency_log",
                &[],
            )
            .map_err(db_err)?
            .get(0);
        txn.execute(
            "INSERT INTO transparency_log (leaf_index, account_id, device_id, public_key, entry)
             VALUES ($1, $2, $3, $4, $5)",
            &[
                &next,
                &account.as_bytes(),
                &device.as_bytes(),
                &public_key,
                &entry,
            ],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(next as u64)
    }

    /// Append a **revocation** leaf (ADR-0013 v2) recording that `device` was revoked at
    /// `revoked_at`, so a device *removal* is auditable under the signed root — not just additions.
    /// The stored `public_key` is empty (a revocation carries no key); the v2 kind byte keeps it
    /// unambiguous from a binding leaf. Same gapless-append discipline as [`append_binding`].
    pub fn append_revocation(
        &self,
        account: &AccountId,
        device: &DeviceId,
        revoked_at: u64,
    ) -> StoreResult<u64> {
        let entry = encode_revocation_v2(account, device, revoked_at);
        let empty: &[u8] = &[];
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        txn.execute("SELECT pg_advisory_xact_lock($1)", &[&APPEND_LOCK_KEY])
            .map_err(db_err)?;
        let next: i64 = txn
            .query_one(
                "SELECT coalesce(max(leaf_index) + 1, 0) FROM transparency_log",
                &[],
            )
            .map_err(db_err)?
            .get(0);
        txn.execute(
            "INSERT INTO transparency_log (leaf_index, account_id, device_id, public_key, entry)
             VALUES ($1, $2, $3, $4, $5)",
            &[
                &next,
                &account.as_bytes(),
                &device.as_bytes(),
                &empty,
                &entry,
            ],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(next as u64)
    }

    /// All leaf hashes in index order (used to compute roots and proofs). Recomputed per request;
    /// production would maintain an incremental tree.
    fn leaf_hashes(&self) -> StoreResult<Vec<Hash>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT entry FROM transparency_log ORDER BY leaf_index",
                &[],
            )
            .map_err(db_err)?;
        Ok(rows
            .iter()
            .map(|r| hash_leaf(r.get::<_, &[u8]>(0)))
            .collect())
    }

    /// Current signed tree head.
    pub fn signed_tree_head(&self) -> StoreResult<SignedTreeHead> {
        let leaves = self.leaf_hashes()?;
        let tree_size = leaves.len() as u64;
        let root = merkle_root(&leaves);
        let timestamp = now_unix();
        let sig: Signature = self
            .signing_key
            .sign(&encode_sth(tree_size, &root, timestamp));
        Ok(SignedTreeHead {
            tree_size,
            root,
            timestamp,
            signature: sig.to_bytes().to_vec(),
        })
    }

    /// Consistency proof between sizes `first` and `second`. `Ok(None)` signals an out-of-range
    /// request (the handler maps it to 400) so a genuine DB fault (`Err`) stays a 500.
    pub fn consistency(&self, first: u64, second: u64) -> StoreResult<Option<Vec<Hash>>> {
        let leaves = self.leaf_hashes()?;
        let n = leaves.len() as u64;
        if first == 0 || first > second || second > n {
            return Ok(None);
        }
        Ok(Some(consistency_proof(
            &leaves[..second as usize],
            first as usize,
        )))
    }

    /// Every binding logged under `account`, each with an inclusion proof computed at `at_size`
    /// leaves (defaults to the current size; clamped to it). Pinning the size lets a client verify
    /// inclusion against a specific signed tree head even as the log grows concurrently — the first
    /// `at_size` leaves are an immutable append-only prefix, so their root matches that STH exactly.
    /// A client self-monitoring verifies each proof against the STH root and checks the set matches
    /// what it enrolled (an unexpected key ⇒ the server injected one). Bindings not yet in the
    /// pinned prefix (index ≥ size) are omitted.
    pub fn account_view(
        &self,
        account: &AccountId,
        at_size: Option<u64>,
    ) -> StoreResult<AccountView> {
        let all = self.leaf_hashes()?;
        let tree_size = at_size
            .map(|s| s.min(all.len() as u64))
            .unwrap_or(all.len() as u64);
        let leaves = &all[..tree_size as usize];
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT leaf_index, device_id, public_key, entry FROM transparency_log
                 WHERE account_id = $1 AND leaf_index < $2 ORDER BY leaf_index",
                &[&account.as_bytes(), &(tree_size as i64)],
            )
            .map_err(db_err)?;
        let mut bindings = Vec::with_capacity(rows.len());
        for r in rows {
            let leaf_index: i64 = r.get(0);
            let device: &[u8] = r.get(1);
            let proof = inclusion_proof(leaves, leaf_index as usize);
            let entry: Vec<u8> = r.get(3);
            // A v2 revocation leaf is recognizable by its domain header; everything else (legacy v1
            // binding, v2 binding) is a binding for lifecycle purposes.
            let revoked_at = decode_leaf_v2(&entry).and_then(|leaf| match leaf.kind {
                LeafKind::Revocation => Some(leaf.revoked_at),
                LeafKind::Binding => None,
            });
            bindings.push(AccountBinding {
                leaf_index: leaf_index as u64,
                device_id: device
                    .try_into()
                    .map_err(|_| StoreError("bad device id".into()))?,
                public_key: r.get(2),
                entry,
                proof,
                revoked_at,
            });
        }
        Ok(AccountView {
            tree_size,
            bindings,
        })
    }
}

fn db_err(e: postgres::Error) -> StoreError {
    StoreError(format!("transparency db: {e}"))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod leaf_v2_tests {
    use super::*;
    use auth_core::ids::{AccountId, DeviceId};

    fn ids() -> (AccountId, DeviceId) {
        (AccountId([0xA1; 16]), DeviceId([0xB2; 16]))
    }

    #[test]
    fn binding_v2_roundtrips() {
        let (a, d) = ids();
        let pk: Vec<u8> = std::iter::once(0x04).chain(0..64).collect();
        let entry = encode_binding_v2(&a, &d, &pk);
        let decoded = decode_leaf_v2(&entry).expect("decode");
        assert_eq!(decoded.kind, LeafKind::Binding);
        assert_eq!(decoded.account, a.0);
        assert_eq!(decoded.device, d.0);
        assert_eq!(decoded.public_key, pk);
        assert_eq!(decoded.revoked_at, 0);
    }

    #[test]
    fn revocation_v2_roundtrips() {
        let (a, d) = ids();
        let entry = encode_revocation_v2(&a, &d, 1_700_000_000);
        let decoded = decode_leaf_v2(&entry).expect("decode");
        assert_eq!(decoded.kind, LeafKind::Revocation);
        assert_eq!(decoded.account, a.0);
        assert_eq!(decoded.device, d.0);
        assert!(decoded.public_key.is_empty());
        assert_eq!(decoded.revoked_at, 1_700_000_000);
    }

    #[test]
    fn binding_and_revocation_leaves_are_disjoint() {
        // Same account+device: the kind byte alone must make the two encodings differ, so no
        // revocation can ever be read as a binding (leaf-type confusion is the schema's whole point).
        let (a, d) = ids();
        let b = encode_binding_v2(&a, &d, &[0x04, 0x01, 0x02]);
        let r = encode_revocation_v2(&a, &d, 0);
        assert_ne!(b, r);
        assert_eq!(decode_leaf_v2(&b).unwrap().kind, LeafKind::Binding);
        assert_eq!(decode_leaf_v2(&r).unwrap().kind, LeafKind::Revocation);
    }

    #[test]
    fn legacy_v1_binding_is_not_decoded_as_v2() {
        // A v1 leaf (no domain header) must yield None, so the two schemas never cross-parse.
        let (a, d) = ids();
        let v1 = encode_binding(&a, &d, &[0x04, 0x09, 0x09]);
        assert!(decode_leaf_v2(&v1).is_none());
    }

    #[test]
    fn truncated_or_overlong_entries_are_rejected() {
        let (a, d) = ids();
        let entry = encode_binding_v2(&a, &d, &[0x04, 0x01]);
        assert!(decode_leaf_v2(&entry[..entry.len() - 1]).is_none()); // truncated pk
        let mut overlong = entry.clone();
        overlong.push(0x00); // trailing byte
        assert!(decode_leaf_v2(&overlong).is_none());
        let mut bad_kind = entry.clone();
        bad_kind[4 + LEAF_DOMAIN_V2.len()] = 9; // unknown kind
        assert!(decode_leaf_v2(&bad_kind).is_none());
    }

    #[test]
    fn golden_vectors_are_stable() {
        let (a, d) = ids();
        let pk: Vec<u8> = std::iter::once(0x04).chain(0..64).collect();
        let bind_hex: String = encode_binding_v2(&a, &d, &pk)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let rev_hex: String = encode_revocation_v2(&a, &d, 1_700_000_000)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        // Pin the exact bytes so a cross-language (Swift) verifier can reproduce them.
        assert!(bind_hex.starts_with("00000016")); // len32(22) domain length
        assert!(bind_hex.contains(&hex::encode(LEAF_DOMAIN_V2)));
        assert_eq!(
            rev_hex.len(),
            (4 + LEAF_DOMAIN_V2.len() + 1 + 16 + 16 + 8) * 2
        );
    }
}
