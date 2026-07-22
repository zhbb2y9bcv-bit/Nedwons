//! The canonical, domain-separated authentication transcript (CRYPTOGRAPHY.md §4). Every
//! device-binding operation signs these bytes:
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
//! Two tested properties:
//!  * **Unambiguous** — every variable field is length-prefixed, so no two distinct field vectors
//!    serialize alike (prevents field splicing).
//!  * **Purpose-bound** — `DOMAIN` + `ACTION` bind a signature to one operation, so a signature
//!    captured for one action cannot be replayed as another.
//!
//! Platform-neutral (ADR-0005): the iOS client reproduces this encoding, kept byte-identical by
//! shared test vectors.

use crate::ids::{AccountId, DeviceId, TxnId};

/// Versioned; a new protocol version changes this string.
pub const DOMAIN: &[u8] = b"app.nedwons.auth.v1";

/// Bumping this is an explicit, non-silent change (INV-9): old and new produce different bytes.
pub const PROTOCOL_VERSION: u16 = 1;

/// The `u8` tag is part of the signed bytes.
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

pub struct Transcript<'a> {
    pub action: Action,
    pub account_id: &'a AccountId,
    pub device_id: &'a DeviceId,
    /// SEC1-encoded P-256 public key of the signing device.
    pub public_key: &'a [u8],
    /// 32-byte server challenge; for refresh, SHA-256 of the rotating refresh token.
    pub challenge: &'a [u8],
    pub expires_at: u64,
    pub txn_id: &'a TxnId,
}

impl<'a> Transcript<'a> {
    /// The canonical byte string to sign or verify.
    pub fn encode(&self) -> Vec<u8> {
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

/// Big-endian u32 length prefix, then the field bytes.
fn put_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{AccountId, DeviceId, TxnId};

    /// The Swift encoder MUST produce exactly these bytes (contracts/test-vectors/
    /// auth-transcript-login.hex). Changing this is wire-breaking and needs a version bump.
    #[test]
    fn login_transcript_golden_vector() {
        let account_id = AccountId([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        let device_id = DeviceId([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        let txn_id = TxnId([
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xfe, 0xff,
        ]);
        let mut public_key = vec![0x04u8];
        public_key.extend(0u8..64);
        let challenge: Vec<u8> = (0u8..32).collect();

        let bytes = Transcript {
            action: Action::Login,
            account_id: &account_id,
            device_id: &device_id,
            public_key: &public_key,
            challenge: &challenge,
            expires_at: 1_000_000_000,
            txn_id: &txn_id,
        }
        .encode();

        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "000000136170702e6e6564776f6e732e617574682e7631000102000000100011223344\
             5566778899aabbccddeeff000000100102030405060708090a0b0c0d0e0f100000004104\
             000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223\
             2425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0000002000010203\
             0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000000003b9aca00\
             00000010f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                .replace(['\n', ' '], "")
        );
    }
}
