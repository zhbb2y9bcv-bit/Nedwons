//! Client-to-client framing above the opaque MLS ciphertext, now with **bucketed padding**
//! (sealed-sender slice 2d, R-204): the relay — and anyone watching traffic volumes past TLS —
//! sees envelope lengths drawn from a handful of buckets instead of exact sizes, so "a thumbs-up"
//! and "a paragraph" and "a file reference" stop being distinguishable by length alone.
//!
//! - **v2 (written since 2026-09-09):** `u16-BE(2) || u32-BE(inner_len) || mls_message || zeros`
//!   padded up to the next bucket. Zero padding sits OUTSIDE the MLS ciphertext (the relay already
//!   holds these bytes; padding adds nothing readable) and is stripped before anything reaches MLS.
//! - **v1 (still accepted):** `u16-BE(1) || mls_message` — mail queued before the upgrade must
//!   keep decrypting; nothing writes v1 anymore.
//! - An UNKNOWN version is rejected, never guessed at.
//!
//! HONEST SCOPE: padding narrows the size side-channel; it does not hide message *timing* or
//! *frequency* (cover traffic remains future work), and the top bucket rounds to 64 KB steps, so
//! very large payloads still reveal coarse size.

/// Current written version (padded). v1 remains readable.
pub const VERSION: u16 = 2;
const VERSION_UNPADDED: u16 = 1;

/// Bucket boundaries for the padded inner length (`u32` header included in the rounding input so
/// equal-bucket envelopes are byte-identical in length). Above the last bucket: 64 KB steps.
const BUCKETS: [usize; 9] = [256, 512, 1024, 2048, 4096, 8192, 16_384, 32_768, 65_536];

fn padded_len(inner: usize) -> usize {
    for b in BUCKETS {
        if inner <= b {
            return b;
        }
    }
    inner.div_ceil(65_536) * 65_536
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Too short for its own framing, or a padded length that lies about its contents.
    Malformed,
    /// Forward-compat: reject, never guess.
    UnsupportedVersion(u16),
}

pub fn wrap(payload: &[u8]) -> Vec<u8> {
    let inner = 4 + payload.len(); // length header + payload, then rounded up together
    let target = padded_len(inner);
    let mut out = Vec::with_capacity(2 + target);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.resize(2 + target, 0);
    out
}

/// Returns the inner MLS payload; errors on a short buffer, a lying length, or an unsupported
/// version. Accepts v1 (unpadded, pre-upgrade queued mail) and v2 (padded).
pub fn unwrap(envelope: &[u8]) -> Result<&[u8], EnvelopeError> {
    if envelope.len() < 2 {
        return Err(EnvelopeError::Malformed);
    }
    let version = u16::from_be_bytes([envelope[0], envelope[1]]);
    match version {
        VERSION_UNPADDED => Ok(&envelope[2..]),
        VERSION => {
            if envelope.len() < 6 {
                return Err(EnvelopeError::Malformed);
            }
            let len =
                u32::from_be_bytes([envelope[2], envelope[3], envelope[4], envelope[5]]) as usize;
            let end = 6usize.checked_add(len).ok_or(EnvelopeError::Malformed)?;
            if end > envelope.len() {
                return Err(EnvelopeError::Malformed);
            }
            Ok(&envelope[6..end])
        }
        other => Err(EnvelopeError::UnsupportedVersion(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trips_and_pads_to_buckets() {
        for size in [0usize, 1, 200, 251, 252, 253, 1000, 5000, 70_000] {
            let payload = vec![0xA5u8; size];
            let env = wrap(&payload);
            assert_eq!(&env[..2], &VERSION.to_be_bytes());
            assert_eq!(unwrap(&env).unwrap(), payload.as_slice());
            let body = env.len() - 2;
            assert!(
                BUCKETS.contains(&body) || body % 65_536 == 0,
                "len {} for payload {size} is not on a bucket",
                body
            );
        }
    }

    /// The point of the exercise: nearby sizes produce IDENTICAL envelope lengths.
    #[test]
    fn nearby_sizes_are_indistinguishable_by_length() {
        let short = wrap(&[1u8; 10]);
        let alsoshort = wrap(&[2u8; 200]);
        assert_eq!(short.len(), alsoshort.len());
        assert_ne!(short.len(), wrap(&[3u8; 3000]).len(), "different bucket");
    }

    /// Pre-upgrade queued mail (v1, unpadded) still unwraps.
    #[test]
    fn legacy_v1_envelopes_still_unwrap() {
        let mut v1 = 1u16.to_be_bytes().to_vec();
        v1.extend_from_slice(b"old queued payload");
        assert_eq!(unwrap(&v1).unwrap(), b"old queued payload");
    }

    #[test]
    fn rejects_short_lying_and_unknown() {
        assert_eq!(unwrap(&[]), Err(EnvelopeError::Malformed));
        assert_eq!(unwrap(&[0x00]), Err(EnvelopeError::Malformed));
        // v2 header claiming more payload than exists.
        let mut lying = 2u16.to_be_bytes().to_vec();
        lying.extend_from_slice(&100u32.to_be_bytes());
        lying.extend_from_slice(&[0u8; 10]);
        assert_eq!(unwrap(&lying), Err(EnvelopeError::Malformed));
        let mut future = 3u16.to_be_bytes().to_vec();
        future.extend_from_slice(b"payload");
        assert_eq!(unwrap(&future), Err(EnvelopeError::UnsupportedVersion(3)));
    }

    #[test]
    fn empty_payload_is_valid() {
        assert_eq!(unwrap(&wrap(b"")).unwrap(), b"");
    }
}
