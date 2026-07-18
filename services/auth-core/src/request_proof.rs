//! DPoP-style per-request proof-of-possession (ADR-0011, R-308).
//!
//! A sender-constrained access token: each authenticated request carries a proof that the caller
//! holds the device's enrolled private key. The proof is a raw ECDSA-P256 signature over this
//! canonical, domain-separated transcript — the same vetted signing path as auth/refresh, so a
//! stolen bearer token is useless without the non-exportable key. RFC 9449 semantics (bind
//! method + URI + token + time + nonce), expressed in Sentinel's transcript idiom rather than JWS.

use crate::crypto::verify_p256;

/// Domain-separation tag. Versioned; a new proof format re-tags.
pub const DOMAIN: &[u8] = b"app.sentinel.dpop.v1";

/// Protocol version carried in the signed bytes (explicit, non-silent evolution).
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum accepted clock skew (seconds) between the proof timestamp and server time. Bounds the
/// replay window; the nonce cache makes each proof single-use within it.
pub const MAX_SKEW_SECS: u64 = 60;

/// The fields bound into one request proof.
pub struct RequestProof<'a> {
    /// HTTP method, uppercase ASCII (e.g. `GET`, `POST`).
    pub method: &'a [u8],
    /// Request path, no query string (e.g. `/v1/inbox`).
    pub path: &'a [u8],
    /// SHA-256 of the presented access token — recomputed server-side, so the client cannot lie
    /// about which token the proof covers.
    pub access_token_hash: &'a [u8; 32],
    /// Client clock, unix seconds.
    pub timestamp: u64,
    /// 16 random bytes, unique per request (single-use within the skew window).
    pub nonce: &'a [u8; 16],
}

impl<'a> RequestProof<'a> {
    /// The canonical byte string that is signed and verified.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            4 + DOMAIN.len()
                + 2
                + (4 + self.method.len())
                + (4 + self.path.len())
                + (4 + 32)
                + 8
                + (4 + 16),
        );
        put_lp(&mut out, DOMAIN);
        out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        put_lp(&mut out, self.method);
        put_lp(&mut out, self.path);
        put_lp(&mut out, self.access_token_hash);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        put_lp(&mut out, self.nonce);
        out
    }

    /// Verify `signature` over this proof against the device's SEC1 public key. Fail-closed.
    pub fn verify(&self, device_public_key_sec1: &[u8], signature: &[u8]) -> bool {
        verify_p256(device_public_key_sec1, &self.encode(), signature)
    }

    /// True iff `timestamp` is within `MAX_SKEW_SECS` of `now` (both directions).
    pub fn is_fresh(&self, now: u64) -> bool {
        now.abs_diff(self.timestamp) <= MAX_SKEW_SECS
    }
}

fn put_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ts: u64) -> Vec<u8> {
        RequestProof {
            method: b"POST",
            path: b"/v1/conversations/aabb/messages",
            access_token_hash: &[7u8; 32],
            timestamp: ts,
            nonce: &[9u8; 16],
        }
        .encode()
    }

    #[test]
    fn golden_vector_is_stable() {
        let hex: String = sample(1_700_000_000)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex,
            "000000146170702e73656e74696e656c2e64706f702e7631000100000004504f53540000001f2f76312f636f6e766572736174696f6e732f616162622f6d65737361676573000000200707070707070707070707070707070707070707070707070707070707070707000000006553f1000000001009090909090909090909090909090909"
        );
    }

    #[test]
    fn encoding_is_injective_across_method_and_path() {
        let get = RequestProof {
            method: b"GET",
            path: b"/v1/inbox",
            access_token_hash: &[0u8; 32],
            timestamp: 1,
            nonce: &[0u8; 16],
        }
        .encode();
        let post = RequestProof {
            method: b"POST",
            path: b"/v1/inbox",
            access_token_hash: &[0u8; 32],
            timestamp: 1,
            nonce: &[0u8; 16],
        }
        .encode();
        assert_ne!(get, post, "method must be bound");
        // Moving a byte from method into path must not collide (length prefixes).
        let a = RequestProof {
            method: b"GE",
            path: b"T/v1/inbox",
            access_token_hash: &[0u8; 32],
            timestamp: 1,
            nonce: &[0u8; 16],
        }
        .encode();
        assert_ne!(get, a);
    }

    #[test]
    fn freshness_window() {
        let p = RequestProof {
            method: b"GET",
            path: b"/v1/inbox",
            access_token_hash: &[0u8; 32],
            timestamp: 1000,
            nonce: &[0u8; 16],
        };
        assert!(p.is_fresh(1000));
        assert!(p.is_fresh(1000 + MAX_SKEW_SECS));
        assert!(p.is_fresh(1000 - MAX_SKEW_SECS));
        assert!(!p.is_fresh(1000 + MAX_SKEW_SECS + 1));
        assert!(!p.is_fresh(1000 - MAX_SKEW_SECS - 1));
    }

    #[test]
    fn sign_verify_round_trip_and_tamper() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        let signing = SigningKey::random(&mut rand_core::OsRng);
        let public = signing
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let proof = RequestProof {
            method: b"POST",
            path: b"/v1/inbox/ack",
            access_token_hash: &[3u8; 32],
            timestamp: 42,
            nonce: &[5u8; 16],
        };
        let sig: Signature = signing.sign(&proof.encode());
        assert!(proof.verify(&public, &sig.to_bytes()));

        // A different path (same signature) must not verify — request binding holds.
        let other = RequestProof {
            path: b"/v1/inbox",
            ..RequestProof {
                method: b"POST",
                path: b"/v1/inbox/ack",
                access_token_hash: &[3u8; 32],
                timestamp: 42,
                nonce: &[5u8; 16],
            }
        };
        assert!(!other.verify(&public, &sig.to_bytes()));
    }
}
