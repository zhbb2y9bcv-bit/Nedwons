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
const KIND_SECRET_CONSUMED: u8 = 2;
const KIND_DELIVERY_KEY_GRANT: u8 = 3;
const KIND_HISTORY_SYNC: u8 = 4;

/// Length of a secret-message id (a sender-chosen random, used for placeholder tracking + replay
/// rejection on the recipient).
pub const SECRET_ID_LEN: usize = 16;

/// Length of a sealed-sender **delivery access key** `K_r` (ADR-0014). Distributing it to an
/// approved contact lets them send you sealed-sender messages; it is granted over the E2EE channel.
pub const DELIVERY_KEY_LEN: usize = 32;

/// Upper bound on entries in a single history-sync batch (#7). Bounds a hostile/oversized payload;
/// a longer history is synced across several batches.
pub const MAX_HISTORY_ENTRIES: usize = 500;

/// One past message replicated to a newly-linked device (#7): the direction (was it sent by this
/// account) plus the plaintext body. Secrets are NOT included (view-once has no re-showable history).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// True if this account originally SENT the message (outbound); false if received (inbound).
    pub outbound: bool,
    pub body: Vec<u8>,
}

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
    /// A **consumption** control message (ADR-0015): the account's device that revealed `secret_id`
    /// tells its OTHER devices to consume that secret too (account-wide single-view). Carries no
    /// body — only the id. E2EE + relay-blind like any other content.
    SecretConsumed { secret_id: [u8; SECRET_ID_LEN] },
    /// A **delivery-key grant** (ADR-0014 Slice 2c): shares this account's sealed-sender delivery
    /// access key `K_r` with an approved contact over the E2EE channel, so they can send sealed
    /// messages. The relay never sees `K_r` (it travels inside the MLS ciphertext).
    DeliveryKeyGrant { key_r: [u8; DELIVERY_KEY_LEN] },
    /// A **history-sync** batch (#7): an existing device replicates past messages to a newly-linked
    /// device over the account's self-group. E2EE + relay-blind. Bounded to [`MAX_HISTORY_ENTRIES`].
    HistorySync { entries: Vec<HistoryEntry> },
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
    /// The body regardless of kind (empty for a `SecretConsumed` control message).
    pub fn body(&self) -> &[u8] {
        match self {
            Content::Normal { body } | Content::Secret { body, .. } => body,
            Content::SecretConsumed { .. }
            | Content::DeliveryKeyGrant { .. }
            | Content::HistorySync { .. } => &[],
        }
    }

    /// Canonical encoding:
    /// - Normal:         `u16(ver) || u8(0) || u32(len) || body`
    /// - Secret:         `u16(ver) || u8(1) || secret_id(16) || u32(len) || body`
    /// - SecretConsumed: `u16(ver) || u8(2) || secret_id(16)`   (no body)
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 1 + SECRET_ID_LEN + 4 + self.body().len());
        out.extend_from_slice(&CONTENT_VERSION.to_be_bytes());
        match self {
            Content::Normal { body } => {
                out.push(KIND_NORMAL);
                out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                out.extend_from_slice(body);
            }
            Content::Secret { secret_id, body } => {
                out.push(KIND_SECRET);
                out.extend_from_slice(secret_id);
                out.extend_from_slice(&(body.len() as u32).to_be_bytes());
                out.extend_from_slice(body);
            }
            Content::SecretConsumed { secret_id } => {
                out.push(KIND_SECRET_CONSUMED);
                out.extend_from_slice(secret_id);
            }
            Content::DeliveryKeyGrant { key_r } => {
                out.push(KIND_DELIVERY_KEY_GRANT);
                out.extend_from_slice(key_r);
            }
            Content::HistorySync { entries } => {
                out.push(KIND_HISTORY_SYNC);
                out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
                for e in entries {
                    out.push(if e.outbound { 1 } else { 0 });
                    out.extend_from_slice(&(e.body.len() as u32).to_be_bytes());
                    out.extend_from_slice(&e.body);
                }
            }
        }
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
        match kind {
            KIND_NORMAL => Ok(Content::Normal {
                body: decode_lp_body(rest)?,
            }),
            KIND_SECRET => {
                let (secret_id, rest) = split_secret_id(rest)?;
                Ok(Content::Secret {
                    secret_id,
                    body: decode_lp_body(rest)?,
                })
            }
            KIND_SECRET_CONSUMED => {
                let (secret_id, rest) = split_secret_id(rest)?;
                if !rest.is_empty() {
                    return Err(ContentError::Malformed); // control message has no trailer
                }
                Ok(Content::SecretConsumed { secret_id })
            }
            KIND_DELIVERY_KEY_GRANT => {
                if rest.len() != DELIVERY_KEY_LEN {
                    return Err(ContentError::Malformed); // exactly the 32-byte key, no trailer
                }
                let mut key_r = [0u8; DELIVERY_KEY_LEN];
                key_r.copy_from_slice(rest);
                Ok(Content::DeliveryKeyGrant { key_r })
            }
            KIND_HISTORY_SYNC => Ok(Content::HistorySync {
                entries: decode_history(rest)?,
            }),
            other => Err(ContentError::UnknownKind(other)),
        }
    }
}

/// Split a leading 16-byte secret id, returning it and the remaining bytes.
fn split_secret_id(rest: &[u8]) -> Result<([u8; SECRET_ID_LEN], &[u8]), ContentError> {
    if rest.len() < SECRET_ID_LEN {
        return Err(ContentError::Malformed);
    }
    let (id, rest) = rest.split_at(SECRET_ID_LEN);
    let mut arr = [0u8; SECRET_ID_LEN];
    arr.copy_from_slice(id);
    Ok((arr, rest))
}

/// Decode a history-sync batch: `u32(count) || [u8(outbound) || u32(len) || body]*`, strict (exact
/// consumption, no trailer) and bounded (`MAX_HISTORY_ENTRIES`, each body `MAX_CONTENT_BODY`).
fn decode_history(mut rest: &[u8]) -> Result<Vec<HistoryEntry>, ContentError> {
    if rest.len() < 4 {
        return Err(ContentError::Malformed);
    }
    let count = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    if count > MAX_HISTORY_ENTRIES {
        return Err(ContentError::TooLarge);
    }
    rest = &rest[4..];
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        // Each entry: flag(1) + len(4) + body(len).
        if rest.len() < 5 {
            return Err(ContentError::Malformed);
        }
        let outbound = match rest[0] {
            0 => false,
            1 => true,
            _ => return Err(ContentError::Malformed), // only 0/1 are valid flags
        };
        let len = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]) as usize;
        if len > MAX_CONTENT_BODY {
            return Err(ContentError::TooLarge);
        }
        rest = &rest[5..];
        if rest.len() < len {
            return Err(ContentError::Malformed);
        }
        let (body, tail) = rest.split_at(len);
        entries.push(HistoryEntry {
            outbound,
            body: body.to_vec(),
        });
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(ContentError::Malformed); // no trailing bytes after the declared count
    }
    Ok(entries)
}

/// Decode a `u32(len) || body` trailer, exact (no trailing/truncation) and bounded.
fn decode_lp_body(rest: &[u8]) -> Result<Vec<u8>, ContentError> {
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
        return Err(ContentError::Malformed);
    }
    Ok(body.to_vec())
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
    fn secret_consumed_round_trips_and_has_no_body() {
        let c = Content::SecretConsumed {
            secret_id: [0x5C; SECRET_ID_LEN],
        };
        let decoded = Content::decode(&c.encode()).unwrap();
        assert_eq!(decoded, c);
        assert!(decoded.body().is_empty());
        // A trailing byte after the id is rejected (control message has no body).
        let mut over = c.encode();
        over.push(0);
        assert_eq!(Content::decode(&over), Err(ContentError::Malformed));
        // A truncated id is rejected.
        let short = &c.encode()[..c.encode().len() - 1];
        assert_eq!(Content::decode(short), Err(ContentError::Malformed));
    }

    #[test]
    fn delivery_key_grant_round_trips_and_is_exact() {
        let c = Content::DeliveryKeyGrant {
            key_r: [0x9c; DELIVERY_KEY_LEN],
        };
        let decoded = Content::decode(&c.encode()).unwrap();
        assert_eq!(decoded, c);
        assert!(decoded.body().is_empty());
        // A trailing byte after the 32-byte key is rejected.
        let mut over = c.encode();
        over.push(0);
        assert_eq!(Content::decode(&over), Err(ContentError::Malformed));
        // A short key is rejected.
        let short = &c.encode()[..c.encode().len() - 1];
        assert_eq!(Content::decode(short), Err(ContentError::Malformed));
    }

    #[test]
    fn history_sync_round_trips_and_is_bounded() {
        let c = Content::HistorySync {
            entries: vec![
                HistoryEntry {
                    outbound: true,
                    body: b"i sent this".to_vec(),
                },
                HistoryEntry {
                    outbound: false,
                    body: b"i got this".to_vec(),
                },
                HistoryEntry {
                    outbound: true,
                    body: vec![],
                },
            ],
        };
        assert_eq!(Content::decode(&c.encode()).unwrap(), c);
        assert!(c.body().is_empty());

        // An empty batch is valid.
        let empty = Content::HistorySync { entries: vec![] };
        assert_eq!(Content::decode(&empty.encode()).unwrap(), empty);

        // A declared count over the cap is rejected on the length field alone (no huge allocation).
        let mut bytes = CONTENT_VERSION.to_be_bytes().to_vec();
        bytes.push(KIND_HISTORY_SYNC);
        bytes.extend_from_slice(&((MAX_HISTORY_ENTRIES as u32) + 1).to_be_bytes());
        assert_eq!(Content::decode(&bytes), Err(ContentError::TooLarge));

        // A trailing byte after the batch is rejected.
        let mut over = c.encode();
        over.push(0xFF);
        assert_eq!(Content::decode(&over), Err(ContentError::Malformed));

        // A bad direction flag (not 0/1) is rejected.
        let mut bad = CONTENT_VERSION.to_be_bytes().to_vec();
        bad.push(KIND_HISTORY_SYNC);
        bad.extend_from_slice(&1u32.to_be_bytes());
        bad.push(9); // invalid flag
        bad.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(Content::decode(&bad), Err(ContentError::Malformed));
    }

    #[test]
    fn kinds_are_disjoint_encodings() {
        let sid = [0x11; SECRET_ID_LEN];
        let secret = Content::Secret {
            secret_id: sid,
            body: vec![],
        }
        .encode();
        let consumed = Content::SecretConsumed { secret_id: sid }.encode();
        assert_ne!(secret, consumed, "kind byte keeps them disjoint");
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
