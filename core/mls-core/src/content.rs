//! Typed application-content envelope — the plaintext MLS encrypts.
//!
//! Because the kind (normal vs **secret**) and body are encoded here and *then* encrypted, they live
//! INSIDE the MLS ciphertext: the relay cannot see that a message is secret, preserving blindness by
//! construction. Distinct from [`crate::envelope`], which versions the outer wire framing.
//!
//! Decode treats its input as untrusted — the bytes may be attacker-chosen ciphertext that happened
//! to decrypt — so it is length-prefixed, strictly bounded, and fails with a redacted error.

use crate::attachment::{ATTACHMENT_DIGEST_LEN, ATTACHMENT_KEY_LEN, MAX_ATTACHMENT_BYTES};

/// A bump is an explicit, non-silent wire change; older clients reject rather than guess.
pub const CONTENT_VERSION: u16 = 1;

/// At/under the FFI `MAX_PLAINTEXT_LEN`, so a body that fits the envelope also fits the transport.
pub const MAX_CONTENT_BODY: usize = 16 * 1024;

const KIND_NORMAL: u8 = 0;
const KIND_SECRET: u8 = 1;
const KIND_SECRET_CONSUMED: u8 = 2;
const KIND_DELIVERY_KEY_GRANT: u8 = 3;
const KIND_HISTORY_SYNC: u8 = 4;
const KIND_GROUP_NAME: u8 = 5;
const KIND_ATTACHMENT: u8 = 6;

/// Sender-chosen random, used for placeholder tracking + recipient-side replay rejection.
pub const SECRET_ID_LEN: usize = 16;

/// Sealed-sender delivery access key `K_r` (ADR-0014), granted over the E2EE channel.
pub const DELIVERY_KEY_LEN: usize = 32;

/// Bounds a hostile payload; longer histories sync across several batches.
pub const MAX_HISTORY_ENTRIES: usize = 500;

/// A group name is a short label, not a document. Bounded in BYTES (not characters) because that is
/// what the decoder can check before allocating.
pub const MAX_GROUP_NAME_BYTES: usize = 128;

/// Media type (`image/jpeg`) and filename bounds for an attachment reference.
pub const MAX_MIME_BYTES: usize = 64;
pub const MAX_FILENAME_BYTES: usize = 256;
/// The relay's blob id: 16 random bytes.
pub const BLOB_ID_LEN: usize = 16;

/// One past message replicated to a newly-linked device (#7). Secrets are NOT included — view-once
/// has no re-showable history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// True if this account SENT it; false if received.
    pub outbound: bool,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    Normal {
        body: Vec<u8>,
    },
    /// A view-once message.
    Secret {
        secret_id: [u8; SECRET_ID_LEN],
        body: Vec<u8>,
    },
    /// ADR-0015: the device that revealed `secret_id` tells the account's OTHER devices to consume
    /// it too (account-wide single-view). No body.
    SecretConsumed {
        secret_id: [u8; SECRET_ID_LEN],
    },
    /// ADR-0014 Slice 2c: shares `K_r` with an approved contact. The relay never sees it — the grant
    /// travels inside the MLS ciphertext.
    DeliveryKeyGrant {
        key_r: [u8; DELIVERY_KEY_LEN],
    },
    /// #7: replicates past messages to a newly-linked device over the account's self-group.
    HistorySync {
        entries: Vec<HistoryEntry>,
    },
    /// The group's name, set by a member and carried INSIDE the MLS ciphertext — so the relay never
    /// learns what a group is called, exactly as it never learns what is said in it. There is no
    /// server-side name field to leak, subpoena, or index.
    ///
    /// Any member can send one: MLS has no notion of roles, and the relay cannot enforce one on a
    /// message it cannot read. The app offers renaming to admins only; that restriction is UI-level
    /// and a modified client could ignore it. Renaming is not destructive, and every member sees the
    /// change, so this is a deliberate trade rather than an oversight.
    GroupName {
        name: String,
    },
    /// A file. The bytes live on the relay as opaque ciphertext; everything that makes them
    /// meaningful — the key, what kind of file it is, what it was called, how big it is — is in
    /// here, inside the MLS ciphertext. The relay can tell that an account uploaded *something* of
    /// a given size, and nothing else about it.
    Attachment {
        /// Where to fetch the ciphertext from the relay.
        blob_id: [u8; BLOB_ID_LEN],
        /// One-time AES-256-GCM key ([`crate::attachment`]). Never leaves the E2EE channel.
        key: [u8; ATTACHMENT_KEY_LEN],
        /// SHA-256 of the ciphertext, so a substituted blob is caught before decryption.
        digest: [u8; ATTACHMENT_DIGEST_LEN],
        /// Plaintext size in bytes, for a progress bar and a sanity check before downloading.
        size: u64,
        /// IANA media type, e.g. `image/jpeg`. Advisory: a recipient must still validate the bytes
        /// it decodes, because this is a value the sender chose.
        mime: String,
        /// Original filename, or empty. Rendered as text only — never used as a path.
        filename: String,
        /// Optional caption typed with the file.
        caption: String,
    },
}

/// Carries no payload bytes, so logging one leaks nothing.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ContentError {
    Malformed,
    UnsupportedVersion(u16),
    UnknownKind(u8),
    TooLarge,
}

impl Content {
    /// Empty for control kinds.
    pub fn body(&self) -> &[u8] {
        match self {
            Content::Normal { body } | Content::Secret { body, .. } => body,
            Content::SecretConsumed { .. }
            | Content::DeliveryKeyGrant { .. }
            | Content::HistorySync { .. }
            | Content::GroupName { .. }
            | Content::Attachment { .. } => &[],
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
            Content::GroupName { name } => {
                out.push(KIND_GROUP_NAME);
                out.extend_from_slice(&(name.len() as u32).to_be_bytes());
                out.extend_from_slice(name.as_bytes());
            }
            Content::Attachment {
                blob_id,
                key,
                digest,
                size,
                mime,
                filename,
                caption,
            } => {
                out.push(KIND_ATTACHMENT);
                out.extend_from_slice(blob_id);
                out.extend_from_slice(key);
                out.extend_from_slice(digest);
                out.extend_from_slice(&size.to_be_bytes());
                for field in [mime, filename, caption] {
                    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
                    out.extend_from_slice(field.as_bytes());
                }
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
            KIND_GROUP_NAME => Ok(Content::GroupName {
                name: decode_group_name(rest)?,
            }),
            KIND_ATTACHMENT => decode_attachment(rest),
            KIND_HISTORY_SYNC => Ok(Content::HistorySync {
                entries: decode_history(rest)?,
            }),
            other => Err(ContentError::UnknownKind(other)),
        }
    }
}

/// `blob_id(16) || key(32) || digest(32) || u64(size) || lp(mime) || lp(filename) || lp(caption)`,
/// consumed exactly. Every text field is checked the same way a group name is: valid UTF-8, bounded,
/// and free of anything that must not be rendered — a filename is attacker-chosen text that lands in
/// a message bubble.
fn decode_attachment(rest: &[u8]) -> Result<Content, ContentError> {
    const FIXED: usize = BLOB_ID_LEN + ATTACHMENT_KEY_LEN + ATTACHMENT_DIGEST_LEN + 8;
    if rest.len() < FIXED {
        return Err(ContentError::Malformed);
    }
    let (fixed, mut tail) = rest.split_at(FIXED);
    let mut blob_id = [0u8; BLOB_ID_LEN];
    blob_id.copy_from_slice(&fixed[..BLOB_ID_LEN]);
    let mut key = [0u8; ATTACHMENT_KEY_LEN];
    key.copy_from_slice(&fixed[BLOB_ID_LEN..BLOB_ID_LEN + ATTACHMENT_KEY_LEN]);
    let mut digest = [0u8; ATTACHMENT_DIGEST_LEN];
    let digest_at = BLOB_ID_LEN + ATTACHMENT_KEY_LEN;
    digest.copy_from_slice(&fixed[digest_at..digest_at + ATTACHMENT_DIGEST_LEN]);
    let size = u64::from_be_bytes(
        fixed[FIXED - 8..]
            .try_into()
            .map_err(|_| ContentError::Malformed)?,
    );
    if size == 0 || size > MAX_ATTACHMENT_BYTES as u64 {
        return Err(ContentError::TooLarge);
    }
    let mut fields = Vec::with_capacity(3);
    for max in [MAX_MIME_BYTES, MAX_FILENAME_BYTES, MAX_CONTENT_BODY] {
        let (field, next) = decode_lp_text(tail, max)?;
        fields.push(field);
        tail = next;
    }
    if !tail.is_empty() {
        return Err(ContentError::Malformed);
    }
    let caption = fields.pop().expect("three fields");
    let filename = fields.pop().expect("three fields");
    let mime = fields.pop().expect("three fields");
    // A media type is machine-read; anything outside printable ASCII is a sender playing games.
    if mime.is_empty() || !mime.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ContentError::Malformed);
    }
    Ok(Content::Attachment {
        blob_id,
        key,
        digest,
        size,
        mime,
        filename,
        caption,
    })
}

/// `u32(len) || utf8` where the text must be safe to render; may be empty. Returns the remainder.
fn decode_lp_text(rest: &[u8], max: usize) -> Result<(String, &[u8]), ContentError> {
    if rest.len() < 4 {
        return Err(ContentError::Malformed);
    }
    let (len_bytes, body) = rest.split_at(4);
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    if len > max {
        return Err(ContentError::TooLarge);
    }
    if body.len() < len {
        return Err(ContentError::Malformed);
    }
    let (text, tail) = body.split_at(len);
    let text = std::str::from_utf8(text).map_err(|_| ContentError::Malformed)?;
    if text.chars().any(is_unsafe_to_render) {
        return Err(ContentError::Malformed);
    }
    Ok((text.to_string(), tail))
}

/// A group name is chosen by another member and then RENDERED, so the decoder — not the UI — is the
/// place to refuse what must never reach a screen. Rejected here: invalid UTF-8, anything longer
/// than [`MAX_GROUP_NAME_BYTES`], an empty name, C0/C1 control characters, and bidirectional
/// override/isolate codepoints (which can make a name render as something it is not — the same
/// hazard `ContactAlias.validate` refuses on the Swift side for locally-typed aliases).
///
/// Whitespace is deliberately NOT trimmed here: encode∘decode must be the identity, which the fuzz
/// target asserts. Callers normalize before sending.
fn decode_group_name(rest: &[u8]) -> Result<String, ContentError> {
    if rest.len() < 4 {
        return Err(ContentError::Malformed);
    }
    let (len_bytes, body) = rest.split_at(4);
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    if len > MAX_GROUP_NAME_BYTES {
        return Err(ContentError::TooLarge);
    }
    if len == 0 || body.len() != len {
        return Err(ContentError::Malformed); // exact, and never an empty name
    }
    let name = std::str::from_utf8(body).map_err(|_| ContentError::Malformed)?;
    if name.chars().any(is_unsafe_to_render) {
        return Err(ContentError::Malformed);
    }
    Ok(name.to_string())
}

/// C0/C1 controls (except none — a name is one line) and the bidi override/isolate family.
fn is_unsafe_to_render(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

fn split_secret_id(rest: &[u8]) -> Result<([u8; SECRET_ID_LEN], &[u8]), ContentError> {
    if rest.len() < SECRET_ID_LEN {
        return Err(ContentError::Malformed);
    }
    let (id, rest) = rest.split_at(SECRET_ID_LEN);
    let mut arr = [0u8; SECRET_ID_LEN];
    arr.copy_from_slice(id);
    Ok((arr, rest))
}

/// `u32(count) || [u8(outbound) || u32(len) || body]*` — exact consumption, no trailer, bounded.
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

/// `u32(len) || body` — exact (no trailer or truncation) and bounded.
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
        let mut over = c.encode();
        over.push(0);
        assert_eq!(Content::decode(&over), Err(ContentError::Malformed));
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
        let mut over = c.encode();
        over.push(0);
        assert_eq!(Content::decode(&over), Err(ContentError::Malformed));
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

        let empty = Content::HistorySync { entries: vec![] };
        assert_eq!(Content::decode(&empty.encode()).unwrap(), empty);

        // Rejected on the length field alone — no huge allocation.
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

    /// A group name round-trips, and every shape a hostile member could send that must never reach
    /// a screen is refused by the DECODER — not left to the UI to notice.
    #[test]
    fn group_name_round_trips_and_rejects_unrenderable_names() {
        let c = Content::GroupName {
            name: "Weekend Trip 🎒".into(),
        };
        assert_eq!(Content::decode(&c.encode()), Ok(c));

        // Hand-built encodings, because `encode` cannot produce these.
        let framed = |body: &[u8]| {
            let mut v = CONTENT_VERSION.to_be_bytes().to_vec();
            v.push(5); // KIND_GROUP_NAME
            v.extend_from_slice(&(body.len() as u32).to_be_bytes());
            v.extend_from_slice(body);
            v
        };
        assert_eq!(Content::decode(&framed(b"")), Err(ContentError::Malformed));
        assert_eq!(
            Content::decode(&framed("a\u{202E}b".as_bytes())),
            Err(ContentError::Malformed),
            "a right-to-left override can make a name render as another"
        );
        assert_eq!(
            Content::decode(&framed(b"two\nlines")),
            Err(ContentError::Malformed)
        );
        assert_eq!(
            Content::decode(&framed(&[0xff, 0xfe])),
            Err(ContentError::Malformed),
            "invalid UTF-8"
        );
        assert_eq!(
            Content::decode(&framed(&[b'x'; MAX_GROUP_NAME_BYTES + 1])),
            Err(ContentError::TooLarge)
        );
        // A declared length that does not match the body is refused rather than truncated.
        let mut short = framed(b"abcd");
        short.pop();
        assert_eq!(Content::decode(&short), Err(ContentError::Malformed));
    }
}
