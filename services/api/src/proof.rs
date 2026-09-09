//! DPoP-style request-proof replay cache + header parsing (ADR-0011, R-308).
//!
//! The signed-transcript verification lives in `auth_core::request_proof`; this module holds the
//! stateful, api-side pieces: parsing the wire header and a process-local single-use nonce cache.

use std::collections::HashMap;
use std::sync::Mutex;

/// A parsed `X-Nedwons-Proof: v1;ts=<u64>;nonce=<32 hex>;sig=<hex>` header.
pub struct ParsedProof {
    pub timestamp: u64,
    pub nonce: [u8; 16],
    pub signature: Vec<u8>,
}

/// Parse the proof header. Returns `None` on any malformation (fail-closed), including an unknown
/// version, missing field, bad hex, or an unexpected key.
pub fn parse_proof_header(value: &str) -> Option<ParsedProof> {
    let mut version_ok = false;
    let mut timestamp = None;
    let mut nonce: Option<[u8; 16]> = None;
    let mut signature = None;
    for part in value.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part == "v1" {
            version_ok = true;
            continue;
        }
        let (k, v) = part.split_once('=')?;
        match k {
            "ts" => timestamp = v.parse::<u64>().ok(),
            "nonce" => nonce = hex::decode(v).ok().and_then(|b| b.try_into().ok()),
            "sig" => signature = hex::decode(v).ok(),
            _ => return None,
        }
    }
    if !version_ok {
        return None;
    }
    Some(ParsedProof {
        timestamp: timestamp?,
        nonce: nonce?,
        signature: signature?,
    })
}

/// Records a proof nonce as used, returning `false` if it was already spent.
///
/// Two implementations, and the difference is not cosmetic. [`ProofReplayCache`] is process-local:
/// correct for exactly one API instance, and silently wrong for more than one, because a captured
/// proof replayed against a DIFFERENT instance inside the freshness window meets a cache that has
/// never seen the nonce. [`PgReplayCache`] shares the record through the database and is what a
/// multi-instance deployment must use.
pub trait ReplayGuard: Send + Sync {
    fn check_and_record(&self, device: &[u8; 16], nonce: &[u8; 16], expiry: u64, now: u64) -> bool;
}

/// Single-use nonces within the freshness window (ADR-0011), keyed by `(device, nonce)` so one
/// device cannot burn another's.
///
/// **Per-instance.** Suitable for tests and single-instance deployments only; a multi-instance
/// deployment must use [`PgReplayCache`], which is what production selects.
#[derive(Default)]
pub struct ProofReplayCache {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    seen: HashMap<[u8; 32], u64>,
    last_prune: u64,
}

impl ProofReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// `false` if already used — a proof is single-use. Prunes at most once per second, so the map
    /// stays bounded by the request rate without an O(n) sweep per call.
    pub fn check_and_record(
        &self,
        device: &[u8; 16],
        nonce: &[u8; 16],
        expiry: u64,
        now: u64,
    ) -> bool {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(device);
        key[16..].copy_from_slice(nonce);
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false, // poisoned ⇒ fail closed
        };
        if now > g.last_prune {
            g.seen.retain(|_, exp| *exp > now);
            g.last_prune = now;
        }
        if g.seen.contains_key(&key) {
            return false;
        }
        g.seen.insert(key, expiry);
        true
    }
}

impl ReplayGuard for ProofReplayCache {
    fn check_and_record(&self, device: &[u8; 16], nonce: &[u8; 16], expiry: u64, now: u64) -> bool {
        ProofReplayCache::check_and_record(self, device, nonce, expiry, now)
    }
}

/// Replay protection shared across API instances, backed by `proof_nonces`.
///
/// The primary key does the work: recording is an `INSERT ... ON CONFLICT DO NOTHING`, so the first
/// writer wins and every concurrent racer — on any instance — sees zero rows affected and is
/// refused. There is no read-then-write to race and no lock to take.
///
/// Fails CLOSED. If the database is unreachable the proof is refused rather than accepted, because
/// the alternative is that a database blip silently disables replay protection on the
/// authentication path.
pub struct PgReplayCache {
    pool: crate::pgstore::PgPool,
}

impl PgReplayCache {
    pub fn new(pool: crate::pgstore::PgPool) -> Self {
        Self { pool }
    }
}

impl ReplayGuard for PgReplayCache {
    fn check_and_record(&self, device: &[u8; 16], nonce: &[u8; 16], expiry: u64, now: u64) -> bool {
        let Ok(mut conn) = self.pool.get() else {
            return false; // unreachable database ⇒ fail closed
        };
        // Sweep opportunistically rather than on a timer: bounded by the index on expires_at, and
        // it keeps the table proportional to the in-flight request rate.
        let _ = conn.execute(
            "DELETE FROM proof_nonces WHERE expires_at < to_timestamp($1)",
            &[&(now as f64)],
        );
        match conn.execute(
            "INSERT INTO proof_nonces (device_id, nonce, expires_at)
             VALUES ($1, $2, to_timestamp($3)) ON CONFLICT DO NOTHING",
            &[&device.as_slice(), &nonce.as_slice(), &(expiry as f64)],
        ) {
            Ok(1) => true,
            Ok(_) => false,  // already spent
            Err(_) => false, // fail closed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_header() {
        let p =
            parse_proof_header("v1;ts=1700000000;nonce=0102030405060708090a0b0c0d0e0f10;sig=abcd")
                .expect("parses");
        assert_eq!(p.timestamp, 1_700_000_000);
        assert_eq!(p.nonce[0], 1);
        assert_eq!(p.signature, vec![0xab, 0xcd]);
    }

    #[test]
    fn rejects_malformed_headers() {
        assert!(parse_proof_header("ts=1;nonce=00;sig=00").is_none()); // no version
        assert!(parse_proof_header("v1;nonce=00;sig=00").is_none()); // no ts
        assert!(parse_proof_header("v1;ts=1;nonce=zz;sig=00").is_none()); // bad hex
        assert!(parse_proof_header("v1;ts=1;nonce=0102;sig=00").is_none()); // short nonce
        assert!(
            parse_proof_header("v1;ts=1;nonce=0102030405060708090a0b0c0d0e0f10;sig=00;x=1")
                .is_none()
        ); // unknown key
    }

    #[test]
    fn replay_cache_is_single_use_and_self_prunes() {
        let cache = ProofReplayCache::new();
        let dev = [1u8; 16];
        let nonce = [2u8; 16];
        assert!(
            cache.check_and_record(&dev, &nonce, 100, 10),
            "first use accepted"
        );
        assert!(
            !cache.check_and_record(&dev, &nonce, 100, 10),
            "replay rejected"
        );
        // A different device with the same nonce is independent.
        assert!(cache.check_and_record(&[9u8; 16], &nonce, 100, 10));
        // After expiry + a prune tick, the nonce can be reused (it is a fresh window).
        assert!(cache.check_and_record(&dev, &nonce, 200, 101));
    }
}
