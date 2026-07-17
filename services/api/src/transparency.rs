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

/// A signed tree head (the log's commitment to its current state).
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root: Hash,
    pub timestamp: u64,
    /// ECDSA-P256 signature over `encode_sth(tree_size, root, timestamp)`, 64-byte r‖s.
    pub signature: Vec<u8>,
}

/// One of an account's logged bindings, with an inclusion proof at the current tree size.
pub struct AccountBinding {
    pub leaf_index: u64,
    pub device_id: [u8; 16],
    pub public_key: Vec<u8>,
    pub entry: Vec<u8>,
    pub proof: Vec<Hash>,
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
            bindings.push(AccountBinding {
                leaf_index: leaf_index as u64,
                device_id: device
                    .try_into()
                    .map_err(|_| StoreError("bad device id".into()))?,
                public_key: r.get(2),
                entry: r.get(3),
                proof,
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
