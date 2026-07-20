//! Application-envelope protocol versioning (R-506 residual).
//!
//! A tiny client-to-client framing that sits ABOVE the opaque MLS ciphertext: `u16-BE(version) ||
//! mls_message`. It lets the application-message wire format evolve — an older client that receives
//! a newer envelope version **rejects it** instead of feeding unknown bytes to MLS. The MLS-blind
//! relay forwards these bytes untouched (it never parses them), so this changes nothing about the
//! server's opacity. Control (membership) messages are versioned separately via the manifest
//! domain tag (`app.nedwons.membership.v1`).

/// The current application-envelope version. Bumping this is an explicit, non-silent wire change.
pub const VERSION: u16 = 1;

#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Fewer than the 2 version bytes.
    Malformed,
    /// A version this build does not understand (forward-compat: reject, never guess).
    UnsupportedVersion(u16),
}

/// Wrap an MLS message payload in a versioned envelope.
pub fn wrap(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Unwrap a versioned envelope, returning the inner MLS payload. Errors on a short buffer or an
/// unsupported version.
pub fn unwrap(envelope: &[u8]) -> Result<&[u8], EnvelopeError> {
    if envelope.len() < 2 {
        return Err(EnvelopeError::Malformed);
    }
    let version = u16::from_be_bytes([envelope[0], envelope[1]]);
    if version != VERSION {
        return Err(EnvelopeError::UnsupportedVersion(version));
    }
    Ok(&envelope[2..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trips_and_prefixes_the_version() {
        let payload = b"opaque-mls-ciphertext";
        let env = wrap(payload);
        assert_eq!(
            &env[..2],
            &VERSION.to_be_bytes(),
            "version is the 2-byte BE prefix"
        );
        assert_eq!(unwrap(&env).unwrap(), payload);
    }

    #[test]
    fn rejects_short_and_unknown_versions() {
        assert_eq!(unwrap(&[]), Err(EnvelopeError::Malformed));
        assert_eq!(unwrap(&[0x00]), Err(EnvelopeError::Malformed));
        // Version 2 is not understood by this v1 build.
        let mut future = 2u16.to_be_bytes().to_vec();
        future.extend_from_slice(b"payload");
        assert_eq!(unwrap(&future), Err(EnvelopeError::UnsupportedVersion(2)));
    }

    #[test]
    fn empty_payload_is_valid() {
        assert_eq!(unwrap(&wrap(b"")).unwrap(), b"");
    }
}
