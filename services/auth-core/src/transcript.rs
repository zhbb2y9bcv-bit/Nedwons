//! The canonical, domain-separated authentication transcript (CRYPTOGRAPHY.md §4).
//!
//! Every device-binding operation signs the byte string produced by [`encode`]. The
//! encoding is:
//!
//! ```text
//! len32(DOMAIN) || DOMAIN || u16(PROTOCOL) || u8(ACTION)
//!   || len32(ACCOUNT_ID) || ACCOUNT_ID
//!   || len32(DEVICE_ID)  || DEVICE_ID
//!   || len32(PUBKEY)     || PUBKEY
//!   || len32(CHALLENGE)  || CHALLENGE
//!   || u64(EXPIRES_AT)
//!   || len32(TXN_ID)     || TXN_ID
//! ```
//!
//! Two properties matter and are tested:
//!  * **Unambiguous** — every variable field is length-prefixed, so no two distinct field
//!    vectors serialize to the same bytes (prevents field-splicing/confusion).
//!  * **Purpose-bound** — `DOMAIN` + `ACTION` bind a signature to one operation, so a
//!    signature captured for one action cannot be replayed as another.
//!
//! This module is deliberately platform-neutral (ADR-0005): the iOS client reproduces this
//! exact encoding, and shared test vectors keep the two byte-identical.

use crate::ids::{AccountId, DeviceId, TxnId};

/// ASCII domain-separation tag. Versioned; a new protocol version changes this string.
pub const DOMAIN: &[u8] = b"app.sentinel.auth.v1";

/// Protocol version carried in the transcript. Bumping this is an explicit, non-silent
/// change (INV-9): old and new versions produce different signed bytes.
pub const PROTOCOL_VERSION: u16 = 1;

/// The operation a transcript authorizes. The `u8` tag is part of the signed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    Register = 1,
    Login = 2,
    Refresh = 3,
    PasswordChange = 4,
    DeviceEnroll = 5,
    AccountDelete = 6,
}

/// The fields bound into a single signed transcript.
pub struct Transcript<'a> {
    pub action: Action,
    pub account_id: &'a AccountId,
    pub device_id: &'a DeviceId,
    /// SEC1-encoded P-256 public key of the signing device.
    pub public_key: &'a [u8],
    /// 32-byte server challenge (for refresh, the SHA-256 of the rotating refresh token).
    pub challenge: &'a [u8],
    pub expires_at: u64,
    pub txn_id: &'a TxnId,
}

impl<'a> Transcript<'a> {
    /// Produce the canonical byte string to be signed/verified.
    pub fn encode(&self) -> Vec<u8> {
        // Pre-size to avoid reallocation churn; exact size is not security-relevant.
        let mut out = Vec::with_capacity(
            4 + DOMAIN.len()
                + 2
                + 1
                + (4 + 16) * 3
                + (4 + self.public_key.len())
                + (4 + self.challenge.len())
                + 8,
        );
        put_lp(&mut out, DOMAIN);
        out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        out.push(self.action as u8);
        put_lp(&mut out, self.account_id.as_bytes());
        put_lp(&mut out, self.device_id.as_bytes());
        put_lp(&mut out, self.public_key);
        put_lp(&mut out, self.challenge);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        put_lp(&mut out, self.txn_id.as_bytes());
        out
    }
}

/// Append a big-endian u32 length prefix followed by the field bytes.
fn put_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}
