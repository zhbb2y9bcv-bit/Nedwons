//! Sealed-sender **sender certificate** (ADR-0012, R-204).
//!
//! The server issues each device a short-lived certificate binding `{account, device, sender
//! public key, expires_at}`, signed with a dedicated **sender-certificate key** (ECDSA-P256). A
//! sender embeds this certificate *inside* the E2EE payload of a sealed-sender message, so the
//! recipient — and only the recipient — learns and verifies who sent it, while the relay that
//! delivered the message never saw the sender. The encoding is the same injective, domain-separated
//! discipline as the auth transcript, so no two distinct certificates collide and a signature over
//! one cannot be replayed as any other protocol object.

use crate::crypto::verify_p256;
use crate::ids::{AccountId, DeviceId};

/// Versioned domain-separation tag.
pub const DOMAIN: &[u8] = b"app.nedwons.sender-cert.v1";

/// The fields bound into one sender certificate.
pub struct SenderCert<'a> {
    pub account_id: &'a AccountId,
    pub device_id: &'a DeviceId,
    /// SEC1-encoded P-256 public key of the sending device (the key the recipient checks the MLS
    /// sender against).
    pub sender_public_key: &'a [u8],
    /// Unix seconds. Certificates are short-lived so a leaked/rotated key stops being trusted.
    pub expires_at: u64,
}

impl<'a> SenderCert<'a> {
    /// The canonical byte string that is signed and verified.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            4 + DOMAIN.len() + (4 + 16) + (4 + 16) + (4 + self.sender_public_key.len()) + 8,
        );
        put_lp(&mut out, DOMAIN);
        put_lp(&mut out, self.account_id.as_bytes());
        put_lp(&mut out, self.device_id.as_bytes());
        put_lp(&mut out, self.sender_public_key);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out
    }

    /// Verify `signature` over this certificate against the **pinned** sender-certificate public
    /// key (SEC1), and that it has not expired at `now`. Fail-closed boolean.
    pub fn verify(&self, cert_public_key_sec1: &[u8], signature: &[u8], now: u64) -> bool {
        if now > self.expires_at {
            return false;
        }
        verify_p256(cert_public_key_sec1, &self.encode(), signature)
    }
}

fn put_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    fn sample() -> ([u8; 16], [u8; 16], Vec<u8>) {
        let mut pk = vec![0x04u8];
        pk.extend(0u8..64);
        ([0xA1u8; 16], [0xB2u8; 16], pk)
    }

    #[test]
    fn golden_vector_is_stable() {
        let (acct, dev, pk) = sample();
        let bytes = SenderCert {
            account_id: &AccountId(acct),
            device_id: &DeviceId(dev),
            sender_public_key: &pk,
            expires_at: 1_700_000_000,
        }
        .encode();
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "0000001a6170702e6e6564776f6e732e73656e6465722d636572742e763100000010a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a100000010b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b20000004104000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f000000006553f100"
        );
    }

    #[test]
    fn issue_verify_round_trip_expiry_and_tamper() {
        let signing = SigningKey::random(&mut rand_core::OsRng);
        let cert_pub = signing
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let (acct, dev, pk) = sample();
        let account = AccountId(acct);
        let device = DeviceId(dev);
        let cert = SenderCert {
            account_id: &account,
            device_id: &device,
            sender_public_key: &pk,
            expires_at: 1_000,
        };
        let sig: Signature = signing.sign(&cert.encode());

        assert!(
            cert.verify(&cert_pub, &sig.to_bytes(), 999),
            "valid before expiry"
        );
        assert!(
            cert.verify(&cert_pub, &sig.to_bytes(), 1_000),
            "valid at expiry boundary"
        );
        assert!(
            !cert.verify(&cert_pub, &sig.to_bytes(), 1_001),
            "rejected after expiry"
        );

        // A different cert key does not verify.
        let other = SigningKey::random(&mut rand_core::OsRng)
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        assert!(!cert.verify(&other, &sig.to_bytes(), 999));

        // Tampering with a field (here, the expiry) invalidates the old signature.
        let tampered = SenderCert {
            account_id: &account,
            device_id: &device,
            sender_public_key: &pk,
            expires_at: 2_000,
        };
        assert!(!tampered.verify(&cert_pub, &sig.to_bytes(), 999));
    }
}
