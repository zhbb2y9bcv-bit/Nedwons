//! Versioned, typed **application-content envelope** — the plaintext that MLS encrypts.
//!
//! Every application message a client sends is first encoded as one of these and *then* handed to
//! the MLS ciphersuite. So the classification (normal vs **secret**) and the body live **inside** the
//! MLS ciphertext: the relay — which only ever forwards opaque MLS bytes — cannot see whether a
//! message is secret, nor its contents (INV: relay MLS-blindness is preserved by construction; this
//! adds no plaintext server route). This is distinct from [`crate::envelope`], the *outer*
//! transport wrapper `u16(version) || mls_ciphertext`; that versions the wire framing, this versions
//! the decrypted application content.
//!
//! The encoding is length-prefixed and strictly bounded so a hostile or corrupt payload is rejected
//! with a typed, redacted error rather than mis-parsed or panicking (the bytes may be attacker-chosen
//! ciphertext that happened to decrypt, so decode is treated as untrusted input).

/// Current content-envelope version. A bump is an explicit, non-silent wire change; an older client
/// rejects a newer version rather than guessing.
pub const CONTENT_VERSION: u16 = 1;

/// Upper bound on a decoded body. Kept at/under the FFI `MAX_PLAINTEXT_LEN` so a body that fits the
/// envelope also fits the transport. Secret text is short by nature; this is generous headroom.
pub const MAX_CONTENT_BODY: usize = 16 * 1024;

const KIND_NORMAL: u8 = 0;
const KIND_SECRET: u8 = 1;

/// Length of a secret-message id (a sender-chosen random, used for placeholder tracking + replay
/// rejection on the recipient).
pub const SECRET_ID_LEN: usize = 16;

/// A decoded application-content envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// An ordinary message; `body` is the UTF-8 (or opaque) message bytes.
    Normal { body: Vec<u8> },
    /// A **secret** ("view-once") message, identified by `secret_id`.
    Secret {
        secret_id: [u8; SECRET_ID_LEN],
        body: Vec<u8>,
    },
}

/// Typed, **redacted** decode failure — carries no payload bytes, so logging one leaks nothing.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ContentError {
    /// Truncated / structurally invalid.
    Malformed,
    /// A content version this build does not understand.
    UnsupportedVersion(u16),
    /// An unknown message-kind discriminant.
    UnknownKind(u8),
    /// The declared or actual body exceeds [`MAX_CONTENT_BODY`].
    TooLarge,
}

impl Content {
    /// The body regardless of kind.
    pub fn body(&self) -> &[u8] {
        match self {
            Content::Normal { body } | Content::Secret { body, .. } => body,
        }
    }

    /// Canonical encoding:
    /// `u16(CONTENT_VERSION) || u8(kind) || [secret_id(16) if Secret] || u32(body_len) || body`.
    pub fn encode(&self) -> Vec<u8> {
        let body = self.body();
        let mut out = Vec::with_capacity(2 + 1 + SECRET_ID_LEN + 4 + body.len());
        out.extend_from_slice(&CONTENT_VERSION.to_be_bytes());
        match self {
            Content::Normal { .. } => out.push(KIND_NORMAL),
            Content::Secret { secret_id, .. } => {
                out.push(KIND_SECRET);
                out.extend_from_slice(secret_id);
            }
        }
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// Decode untrusted bytes. Strict: exact lengths, no trailing bytes, bounded body.
    pub fn decode(bytes: &[u8]) -> Result<Content, ContentError> {
        if bytes.len() < 2 {
            return Err(ContentError::Malformed);
        }
        let version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if version != CONTENT_VERSION {
            return Err(ContentError::UnsupportedVersion(version));
        }
        let rest = &bytes[2..];
        let (&kind, rest) = rest.split_first().ok_or(ContentError::Malformed)?;
        let (secret_id, rest) = match kind {
            KIND_NORMAL => (None, rest),
            KIND_SECRET => {
                if rest.len() < SECRET_ID_LEN {
                    return Err(ContentError::Malformed);
                }
                let (id, rest) = rest.split_at(SECRET_ID_LEN);
                let mut arr = [0u8; SECRET_ID_LEN];
                arr.copy_from_slice(id);
                (Some(arr), rest)
            }
            other => return Err(ContentError::UnknownKind(other)),
        };
        if rest.len() < 4 {
            return Err(ContentError::Malformed);
        }
        let (len_bytes, body) = rest.split_at(4);
        let body_len =
            u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        if body_len > MAX_CONTENT_BODY {
            return Err(ContentError::TooLarge);
        }
        if body.len() != body_len {
            // Exact: no trailing bytes, no truncation.
            return Err(ContentError::Malformed);
        }
        Ok(match secret_id {
            None => Content::Normal {
                body: body.to_vec(),
            },
            Some(secret_id) => Content::Secret {
                secret_id,
                body: body.to_vec(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_round_trips() {
        let c = Content::Normal {
            body: b"hello world".to_vec(),
        };
        assert_eq!(Content::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn secret_round_trips_with_id() {
        let c = Content::Secret {
            secret_id: [0xAB; SECRET_ID_LEN],
            body: b"for your eyes only".to_vec(),
        };
        let decoded = Content::decode(&c.encode()).unwrap();
        assert_eq!(decoded, c);
        match decoded {
            Content::Secret { secret_id, .. } => assert_eq!(secret_id, [0xAB; SECRET_ID_LEN]),
            _ => panic!("expected secret"),
        }
    }

    #[test]
    fn empty_body_is_valid_for_both_kinds() {
        assert_eq!(
            Content::decode(&Content::Normal { body: vec![] }.encode()).unwrap(),
            Content::Normal { body: vec![] }
        );
        assert!(matches!(
            Content::decode(
                &Content::Secret {
                    secret_id: [0; SECRET_ID_LEN],
                    body: vec![]
                }
                .encode()
            ),
            Ok(Content::Secret { .. })
        ));
    }

    #[test]
    fn rejects_unknown_version() {
        let mut bytes = 2u16.to_be_bytes().to_vec();
        bytes.push(KIND_NORMAL);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            Content::decode(&bytes),
            Err(ContentError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn rejects_unknown_kind() {
        let mut bytes = CONTENT_VERSION.to_be_bytes().to_vec();
        bytes.push(9); // unknown kind
        assert_eq!(Content::decode(&bytes), Err(ContentError::UnknownKind(9)));
    }

    #[test]
    fn rejects_truncated_secret_id() {
        let mut bytes = CONTENT_VERSION.to_be_bytes().to_vec();
        bytes.push(KIND_SECRET);
        bytes.extend_from_slice(&[0u8; 8]); // only half an id
        assert_eq!(Content::decode(&bytes), Err(ContentError::Malformed));
    }

    #[test]
    fn rejects_trailing_and_truncated_body() {
        let mut c = Content::Normal {
            body: b"abc".to_vec(),
        }
        .encode();
        c.push(0xFF); // trailing byte
        assert_eq!(Content::decode(&c), Err(ContentError::Malformed));

        let mut c2 = Content::Normal {
            body: b"abc".to_vec(),
        }
        .encode();
        c2.pop(); // truncated body
        assert_eq!(Content::decode(&c2), Err(ContentError::Malformed));
    }

    #[test]
    fn rejects_oversized_declared_body_without_allocating_it() {
        // Declares a body far larger than the cap; must reject on the length field alone.
        let mut bytes = CONTENT_VERSION.to_be_bytes().to_vec();
        bytes.push(KIND_NORMAL);
        bytes.extend_from_slice(&(u32::MAX).to_be_bytes());
        assert_eq!(Content::decode(&bytes), Err(ContentError::TooLarge));
    }

    #[test]
    fn decode_never_panics_on_arbitrary_prefixes() {
        // A crude sweep: every 1-4 byte prefix decodes to a typed result, never a panic.
        for a in 0u8..=255 {
            let _ = Content::decode(&[a]);
            let _ = Content::decode(&[a, a]);
            let _ = Content::decode(&[a, a, a]);
            let _ = Content::decode(&[a, a, a, a]);
        }
    }
}
