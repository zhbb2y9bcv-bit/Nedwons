//! Crash-safe client state machine (Gate 2).
//!
//! Ratchet state and visible message state must advance **together**: advancing the ratchet without
//! capturing the plaintext loses the message key forever, and acking an envelope without durably
//! processing it makes the server drop it. So everything persists as **one atomically committed
//! blob** = `{ MLS-store snapshot, message/queue metadata }`, which a crash cannot tear apart.
//!
//! Recovery contract: an operation returning `Err` may have advanced in-memory MLS state without
//! committing. The caller MUST discard the [`DurableSession`] and [`DurableSession::open`] again.
//!
//! Covers inbound dedup (at-least-once redelivery is idempotent), no-ack-until-durable, no partial
//! advance on a failed commit, and retry-without-re-encrypt outbound. Out-of-order/epoch-fork
//! resolution and the encrypted on-device DB remain outstanding.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::content::{Content, ContentError, HistoryEntry, DELIVERY_KEY_LEN, SECRET_ID_LEN};
use crate::secret::{SecretRecord, SecretSide, SecretState};
use crate::{Conversation, Incoming, Member};

/// Bumped when the serialized `{store, meta}` layout changes, so an older blob is detected rather
/// than silently misread. Surfaced via the FFI `capabilities()` call.
pub const BLOB_FORMAT_VERSION: u32 = 1;

/// Caps the out-of-order dedup tail above [`Meta::dedup_watermark`] (R-105): the whole blob is
/// rewritten each commit, so an unbounded seen-set would grow every write. Only bites under a
/// pathological permanent gap, where the watermark is force-advanced (see [`compact_dedup`]).
/// Bounding is safe — blob dedup is a fast path; OpenMLS's ratchet rejects real replays regardless.
const MAX_SEEN_ABOVE_WATERMARK: usize = 4096;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DurableError {
    #[error("mls error")]
    Mls,
    #[error("serialization error")]
    Codec,
    #[error("journal error")]
    Journal,
    #[error("no session persisted")]
    NoSession,
    #[error("unknown local message")]
    UnknownLocal,
    /// An operation needed the self-group (ADR-0015) with none established, or `create_self_group`
    /// found one already existing. Redacted; carries no state.
    #[error("self-group precondition violated")]
    SelfGroup,
}

impl From<crate::MlsError> for DurableError {
    fn from(_: crate::MlsError) -> Self {
        DurableError::Mls
    }
}

/// Both sides stay redacted — no payload bytes leak.
fn map_content(_: ContentError) -> DurableError {
    DurableError::Codec
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Decrypted content lives here; the containing blob is encrypted at rest on device.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Message {
    pub local_id: u64,
    pub direction: Direction,
    pub plaintext: Vec<u8>,
    /// Inbound only: the server envelope id this was decrypted from.
    pub envelope_id: Option<u64>,
    /// `Some` for a view-once secret, whose `plaintext` is then EMPTY — the body lives transiently
    /// in [`Meta::secrets`] and never enters the message log; the UI renders from the secret's
    /// state. `#[serde(default)]` ⇒ older blobs load as `None`.
    #[serde(default)]
    pub secret_id: Option<[u8; SECRET_ID_LEN]>,
}

/// Which MLS group encrypts an outbound message. Normal messages and secrets use the conversation;
/// `SecretConsumed` uses the account's self-group (ADR-0015 option 3), so the conversation's other
/// party never receives the read signal. `#[serde(default)]` ⇒ older blobs load as `Conversation`.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Channel {
    #[default]
    Conversation,
    SelfGroup,
}

/// Lifecycle of an outbound message.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum OutboundStatus {
    /// Drafted + durable, not yet encrypted (ratchet not advanced).
    Queued,
    /// Encrypted once; ciphertext cached so a retry never re-encrypts (no double ratchet advance).
    Encrypted,
    /// The server accepted it.
    Sent,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
struct Outbound {
    local_id: u64,
    /// The encoded [`Content`] envelope, not the raw body, so the classification travels inside the
    /// MLS ciphertext. Scrubbed to empty once a secret is sent.
    plaintext: Vec<u8>,
    status: OutboundStatus,
    ciphertext: Option<Vec<u8>>,
    /// `Some` for a secret message; the sender tombstones it immediately on encrypt.
    #[serde(default)]
    secret_id: Option<[u8; SECRET_ID_LEN]>,
    /// Which MLS group encrypts this message (ADR-0015 option 3). Defaults to `Conversation`.
    #[serde(default)]
    channel: Channel,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InboundOutcome {
    Application(Vec<u8>),
    StateAdvanced,
    /// At-least-once redelivery OR a replayed secret id. A durable no-op.
    Duplicate,
    /// Stored as a sealed placeholder; the body is NOT returned here — it is revealed later, once,
    /// via the reveal state machine.
    SecretSealed {
        secret_id: [u8; SECRET_ID_LEN],
    },
    /// ADR-0015: another of this account's devices revealed `secret_id`, so this device consumed its
    /// copy too. A harmless no-op if this device never held it.
    SecretConsumedRemotely {
        secret_id: [u8; SECRET_ID_LEN],
    },
    /// ADR-0014 Slice 2c: an approved contact shared their `K_r`. The client stores it keyed by
    /// sender. Not user-visible.
    DeliveryKeyGranted {
        key_r: [u8; DELIVERY_KEY_LEN],
    },
    /// #7: `count` past messages were replicated here and appended to the local log.
    HistorySynced {
        count: u64,
    },
}

/// Travels in the committed blob alongside the MLS store snapshot.
#[derive(Serialize, Deserialize, Clone, Default)]
struct Meta {
    /// `#[serde(default)]` ⇒ blobs written before this field load as 0.
    #[serde(default)]
    format_version: u32,
    identity: Vec<u8>,
    public_key: Vec<u8>,
    group_id: Vec<u8>,
    /// Every envelope id `<= dedup_watermark` counts as processed: the contiguous low prefix of seen
    /// ids is collapsed here rather than stored id-by-id (R-105). `#[serde(default)]` ⇒ pre-watermark
    /// blobs load as 0 and self-heal on the next commit.
    #[serde(default)]
    dedup_watermark: u64,
    /// The out-of-order tail above `dedup_watermark`, bounded by [`MAX_SEEN_ABOVE_WATERMARK`].
    /// With the watermark, this is the full dedup set.
    seen_inbound: BTreeSet<u64>,
    /// Durably processed, so safe to acknowledge to the server.
    ack_eligible: BTreeSet<u64>,
    next_local_id: u64,
    messages: Vec<Message>,
    outbox: BTreeMap<u64, Outbound>,
    /// Keyed by hex id (JSON maps need string keys). Every transition is committed here before it
    /// becomes observable. `#[serde(default)]` ⇒ older blobs load empty.
    #[serde(default)]
    secrets: BTreeMap<String, SecretRecord>,
    /// This account's self-group (ADR-0015 option 3), if established. Its ratchet state lives in the
    /// same provider store as the conversation, so one `export_store` snapshot persists both.
    /// `#[serde(default)]` ⇒ older blobs load with no self-group.
    #[serde(default)]
    self_group_id: Option<Vec<u8>>,
}

/// JSON object keys must be strings, so the raw `[u8; 16]` can't be one.
fn sid_key(id: &[u8; SECRET_ID_LEN]) -> String {
    let mut s = String::with_capacity(SECRET_ID_LEN * 2);
    for b in id {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

impl Meta {
    fn take_local_id(&mut self) -> u64 {
        let id = self.next_local_id;
        self.next_local_id += 1;
        id
    }

    /// True if `envelope_id` was already processed (below the watermark or in the tracked tail).
    fn is_seen(&self, envelope_id: u64) -> bool {
        envelope_id <= self.dedup_watermark || self.seen_inbound.contains(&envelope_id)
    }

    /// Mark `envelope_id` processed, then compact so the stored tail stays bounded (R-105).
    fn record_seen(&mut self, envelope_id: u64) {
        if envelope_id > self.dedup_watermark {
            self.seen_inbound.insert(envelope_id);
        }
        self.compact_dedup();
    }

    /// Collapse the contiguous low prefix into `dedup_watermark`; if the tail still exceeds the cap,
    /// force the watermark up to absorb the lowest ids. Forcing only marks *older* ids seen, never
    /// un-sees a newer one, so at worst an unseen low id is later treated as a duplicate — bounded,
    /// and the ratchet is the real replay guard (see [`MAX_SEEN_ABOVE_WATERMARK`]).
    fn compact_dedup(&mut self) {
        // Drop anything already covered by the watermark, and advance over the contiguous prefix.
        while let Some(&lowest) = self.seen_inbound.iter().next() {
            if lowest <= self.dedup_watermark {
                self.seen_inbound.remove(&lowest);
            } else if lowest == self.dedup_watermark + 1 {
                self.dedup_watermark = lowest;
                self.seen_inbound.remove(&lowest);
            } else {
                break;
            }
        }
        // Hard cap on the out-of-order tail.
        while self.seen_inbound.len() > MAX_SEEN_ABOVE_WATERMARK {
            let Some(&lowest) = self.seen_inbound.iter().next() else {
                break;
            };
            self.dedup_watermark = self.dedup_watermark.max(lowest);
            self.seen_inbound.remove(&lowest);
        }
    }
}

/// The blob that is atomically committed. One write ⇒ the MLS state and metadata never tear apart.
#[derive(Serialize, Deserialize)]
struct Blob {
    store: Vec<u8>,
    meta: Meta,
}

/// The in-memory MLS session (its secrets live in `member`'s provider store).
struct Session {
    member: Member,
    conversation: Conversation,
    /// ADR-0015 option 3. Shares `member`'s provider with `conversation`, so one `export_store`
    /// snapshot captures both groups.
    self_group: Option<Conversation>,
    public_key: Vec<u8>,
    group_id: Vec<u8>,
}

impl Session {
    fn wrap(member: Member, conversation: Conversation) -> Self {
        let public_key = member.public_key();
        let group_id = conversation.group_id();
        Self {
            member,
            conversation,
            self_group: None,
            public_key,
            group_id,
        }
    }

    fn restore(meta: &Meta, store: &[u8]) -> Result<Self, DurableError> {
        let member = Member::restore(&meta.identity, store, &meta.public_key)?;
        let conversation = Conversation::reload(&member, &meta.group_id)?;
        let mut session = Self::wrap(member, conversation);
        // Reload the self-group from the SAME provider store (both groups were exported together).
        if let Some(self_group_id) = &meta.self_group_id {
            session.self_group = Some(Conversation::reload(&session.member, self_group_id)?);
        }
        Ok(session)
    }
}

/// Store for the single session blob. `commit` MUST be atomic (all-or-nothing) — on device, a
/// temp-file+rename or a DB transaction.
pub trait Journal {
    fn commit(&mut self, blob: &[u8]) -> Result<(), DurableError>;
    fn load(&self) -> Result<Option<Vec<u8>>, DurableError>;
}

/// A conversation with crash-safe local persistence.
pub struct DurableSession<J: Journal> {
    session: Session,
    meta: Meta,
    journal: J,
}

impl<J: Journal> DurableSession<J> {
    /// Persists before returning.
    pub fn create(identity: &[u8], mut journal: J) -> Result<Self, DurableError> {
        let member = Member::new(identity)?;
        let conversation = member.create_group()?;
        let session = Session::wrap(member, conversation);
        let meta = Meta {
            format_version: BLOB_FORMAT_VERSION,
            identity: identity.to_vec(),
            public_key: session.public_key.clone(),
            group_id: session.group_id.clone(),
            ..Default::default()
        };
        commit_blob(&mut journal, &session, &meta)?;
        Ok(Self {
            session,
            meta,
            journal,
        })
    }

    /// Adopt an existing member + conversation, persisting before returning. The async key-package↔
    /// welcome exchange happens on the lower-level `Member`/`Conversation` — which must share ONE
    /// provider across key-package generation and `join_from_welcome` — then lands here.
    pub fn adopt(
        member: Member,
        conversation: Conversation,
        mut journal: J,
    ) -> Result<Self, DurableError> {
        let identity = member.identity().to_vec();
        let session = Session::wrap(member, conversation);
        let meta = Meta {
            format_version: BLOB_FORMAT_VERSION,
            identity,
            public_key: session.public_key.clone(),
            group_id: session.group_id.clone(),
            ..Default::default()
        };
        commit_blob(&mut journal, &session, &meta)?;
        Ok(Self {
            session,
            meta,
            journal,
        })
    }

    /// Reopen the last durably committed session (crash recovery).
    ///
    /// **Fail closed for secrets:** a reveal that began but never cleanly consumed is forced to
    /// `Consumed` here, so a crash after reveal can never grant another viewing opportunity on
    /// relaunch. Committed before the session is returned.
    pub fn open(journal: J) -> Result<Self, DurableError> {
        let bytes = journal.load()?.ok_or(DurableError::NoSession)?;
        let blob: Blob = serde_json::from_slice(&bytes).map_err(|_| DurableError::Codec)?;
        let session = Session::restore(&blob.meta, &blob.store)?;
        let mut this = Self {
            session,
            meta: blob.meta,
            journal,
        };
        let mut changed = false;
        for rec in this.meta.secrets.values_mut() {
            if matches!(rec.state, SecretState::Countdown | SecretState::Visible) {
                rec.consume();
                changed = true;
            }
        }
        if changed {
            let meta = this.meta.clone();
            this.commit(meta)?;
        }
        Ok(this)
    }

    pub fn key_package(&self) -> Result<Vec<u8>, DurableError> {
        Ok(self.session.member.key_package_bytes()?)
    }

    /// Returns (commit, welcome); the grown group is persisted before returning.
    pub fn add_member(&mut self, key_package: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DurableError> {
        let added = {
            let Session {
                member,
                conversation,
                ..
            } = &mut self.session;
            conversation.add_member(member, key_package)?
        };
        let meta = self.meta.clone();
        self.commit(meta)?;
        Ok((added.commit, added.welcome))
    }

    // ----- Device self-group (ADR-0015 option 3) ----------------------------------------------
    //
    // The self-group is a second MLS group whose members are ONLY this account's own devices. It
    // lives in the SAME `Member` provider as the conversation, so one `export_store` snapshot (and
    // one atomic commit) persists both. `SecretConsumed` control messages are synced over it so the
    // conversation's other party never receives the read signal (unlike option 2, which used the
    // conversation group). The add/join key-package↔welcome handshake mirrors conversation membership.

    /// True if this device has an established self-group.
    pub fn has_self_group(&self) -> bool {
        self.session.self_group.is_some()
    }

    /// Errors if one already exists — never silently orphan a group.
    pub fn create_self_group(&mut self) -> Result<(), DurableError> {
        if self.session.self_group.is_some() {
            return Err(DurableError::SelfGroup);
        }
        let self_group = self.session.member.create_group()?;
        let self_group_id = self_group.group_id();
        self.session.self_group = Some(self_group);
        let mut meta = self.meta.clone();
        meta.self_group_id = Some(self_group_id);
        self.commit(meta)
    }

    /// Returns (commit, welcome) for the existing devices / the new one. Persists before returning.
    pub fn add_self_device(
        &mut self,
        key_package: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), DurableError> {
        let added = {
            let Session {
                member, self_group, ..
            } = &mut self.session;
            let group = self_group.as_mut().ok_or(DurableError::SelfGroup)?;
            group.add_member(member, key_package)?
        };
        let meta = self.meta.clone();
        self.commit(meta)?;
        Ok((added.commit, added.welcome))
    }

    /// From a Welcome produced by another device's [`add_self_device`](Self::add_self_device).
    /// Errors if a self-group is already established here.
    pub fn join_self_group(&mut self, welcome: &[u8]) -> Result<(), DurableError> {
        if self.session.self_group.is_some() {
            return Err(DurableError::SelfGroup);
        }
        let self_group = self.session.member.join_from_welcome(welcome)?;
        let self_group_id = self_group.group_id();
        self.session.self_group = Some(self_group);
        let mut meta = self.meta.clone();
        meta.self_group_id = Some(self_group_id);
        self.commit(meta)
    }

    /// Used when a device is revoked. Returns the remove-commit to fan out; applying it advances the
    /// epoch, so the removed device cannot decrypt later self-group traffic even if it kept old
    /// ratchet state — cryptographic forward secrecy, not merely relay-side exclusion.
    pub fn remove_self_device(&mut self, identity: &[u8]) -> Result<Vec<u8>, DurableError> {
        let commit = {
            let Session {
                member, self_group, ..
            } = &mut self.session;
            let group = self_group.as_mut().ok_or(DurableError::SelfGroup)?;
            group.remove_member(member, identity)?
        };
        let meta = self.meta.clone();
        self.commit(meta)?;
        Ok(commit)
    }

    // ----- Staged commits for MLS-commit-authoritative membership (ADR-0010) ------------------
    //
    // Staging is deliberately NOT persisted: a commit awaiting the server's epoch CAS is
    // discardable, and a crash reopens the last committed (pre-stage) state. Only `merge_staged` /
    // `process_commit_checked` — state the server accepted — persist.

    /// Builds commit + welcome without advancing the epoch or persisting.
    pub fn stage_add_member(
        &mut self,
        key_package: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), DurableError> {
        let Session {
            member,
            conversation,
            ..
        } = &mut self.session;
        let added = conversation.stage_add_member(member, key_package)?;
        Ok((added.commit, added.welcome))
    }

    pub fn stage_remove_member(&mut self, identity: &[u8]) -> Result<Vec<u8>, DurableError> {
        let Session {
            member,
            conversation,
            ..
        } = &mut self.session;
        Ok(conversation.stage_remove_member(member, identity)?)
    }

    /// Merge the pending staged commit (server accepted) and persist the advanced state.
    pub fn merge_staged(&mut self) -> Result<(), DurableError> {
        {
            let Session {
                member,
                conversation,
                ..
            } = &mut self.session;
            conversation.merge_staged(member)?;
        }
        let meta = self.meta.clone();
        self.commit(meta)
    }

    /// Server rejected, or we're rebasing. Nothing durable changes.
    pub fn clear_staged(&mut self) -> Result<(), DurableError> {
        let Session {
            member,
            conversation,
            ..
        } = &mut self.session;
        Ok(conversation.clear_staged(member)?)
    }

    /// Recipient path with the ADR-0010 correspondence check. On mismatch nothing advances and
    /// nothing is persisted.
    pub fn process_commit_checked(
        &mut self,
        envelope: &[u8],
        next_epoch: u64,
        added: &[Vec<u8>],
        removed: &[Vec<u8>],
    ) -> Result<(), DurableError> {
        {
            let Session {
                member,
                conversation,
                ..
            } = &mut self.session;
            conversation.process_commit_checked(member, envelope, next_epoch, added, removed)?;
        }
        let meta = self.meta.clone();
        self.commit(meta)
    }

    /// Idempotent per `envelope_id`, so at-least-once redelivery is a no-op. On success the advanced
    /// MLS state, decrypted message, dedup marker and ack-eligibility are durable **together**.
    pub fn process_inbound(
        &mut self,
        envelope_id: u64,
        ciphertext: &[u8],
    ) -> Result<InboundOutcome, DurableError> {
        if self.meta.is_seen(envelope_id) {
            return Ok(InboundOutcome::Duplicate);
        }
        let incoming = {
            let Session {
                member,
                conversation,
                ..
            } = &mut self.session;
            conversation.process(member, ciphertext)?
        };
        let mut meta = self.meta.clone();
        let outcome = apply_incoming(&mut meta, incoming, envelope_id)?;
        meta.record_seen(envelope_id);
        meta.ack_eligible.insert(envelope_id);
        self.commit(meta)?;
        Ok(outcome)
    }

    /// Self-group channel (ADR-0015 option 3): a `SecretConsumed` from another of this account's
    /// devices, or a self-group membership commit. Decrypting with the self-group — which the
    /// conversation's other party does not belong to — keeps the read signal away from them. Same
    /// dedup + ack machinery as [`process_inbound`]; the caller routes here iff the relay tagged it.
    pub fn process_self_inbound(
        &mut self,
        envelope_id: u64,
        ciphertext: &[u8],
    ) -> Result<InboundOutcome, DurableError> {
        if self.meta.is_seen(envelope_id) {
            return Ok(InboundOutcome::Duplicate);
        }
        let incoming = {
            let Session {
                member, self_group, ..
            } = &mut self.session;
            let group = self_group.as_mut().ok_or(DurableError::SelfGroup)?;
            group.process(member, ciphertext)?
        };
        let mut meta = self.meta.clone();
        let outcome = apply_incoming(&mut meta, incoming, envelope_id)?;
        meta.record_seen(envelope_id);
        meta.ack_eligible.insert(envelope_id);
        self.commit(meta)?;
        Ok(outcome)
    }

    pub fn ack_eligible(&self) -> Vec<u64> {
        self.meta.ack_eligible.iter().copied().collect()
    }

    /// Stop tracking these as ack-eligible; `seen_inbound` dedup history is retained.
    pub fn confirm_acked(&mut self, ids: &[u64]) -> Result<(), DurableError> {
        let mut meta = self.meta.clone();
        for id in ids {
            meta.ack_eligible.remove(id);
        }
        self.commit(meta)
    }

    /// Durable draft; does NOT advance the ratchet.
    pub fn enqueue(&mut self, body: &[u8]) -> Result<u64, DurableError> {
        self.enqueue_content(
            Content::Normal {
                body: body.to_vec(),
            },
            None,
        )
    }

    /// Wrapping the body in a [`Content::Secret`] envelope encrypts the classification end-to-end,
    /// so the relay never learns a message is secret.
    pub fn enqueue_secret(
        &mut self,
        body: &[u8],
    ) -> Result<(u64, [u8; SECRET_ID_LEN]), DurableError> {
        let mut secret_id = [0u8; SECRET_ID_LEN];
        OsRng.fill_bytes(&mut secret_id);
        let local_id = self.enqueue_content(
            Content::Secret {
                secret_id,
                body: body.to_vec(),
            },
            Some(secret_id),
        )?;
        Ok((local_id, secret_id))
    }

    /// ADR-0014 Slice 2c. Rides the same authenticated MLS pipeline as any message, so the relay
    /// never sees `K_r`.
    pub fn enqueue_delivery_key_grant(
        &mut self,
        key_r: &[u8; DELIVERY_KEY_LEN],
    ) -> Result<u64, DurableError> {
        self.enqueue_content(Content::DeliveryKeyGrant { key_r: *key_r }, None)
    }

    // ----- New-device history sync (#7) -------------------------------------------------------

    /// Up to `max` recent messages for a newly-linked device, oldest-first so replay preserves
    /// order. Secrets are excluded — view-once has no re-showable history.
    pub fn history_entries(&self, max: usize) -> Vec<HistoryEntry> {
        let mut recent: Vec<HistoryEntry> = self
            .meta
            .messages
            .iter()
            .rev()
            .filter(|m| m.secret_id.is_none())
            .take(max)
            .map(|m| HistoryEntry {
                outbound: m.direction == Direction::Outbound,
                body: m.plaintext.clone(),
            })
            .collect();
        recent.reverse(); // oldest-first
        recent
    }

    /// Replicates `entries` over the self-group, so it requires one to be established.
    pub fn enqueue_history_sync(
        &mut self,
        entries: Vec<HistoryEntry>,
    ) -> Result<u64, DurableError> {
        if self.session.self_group.is_none() {
            return Err(DurableError::SelfGroup);
        }
        let mut meta = self.meta.clone();
        let local_id = meta.take_local_id();
        meta.outbox.insert(
            local_id,
            Outbound {
                local_id,
                plaintext: Content::HistorySync { entries }.encode(),
                status: OutboundStatus::Queued,
                ciphertext: None,
                secret_id: None,
                channel: Channel::SelfGroup,
            },
        );
        self.commit(meta)?;
        Ok(local_id)
    }

    fn enqueue_content(
        &mut self,
        content: Content,
        secret_id: Option<[u8; SECRET_ID_LEN]>,
    ) -> Result<u64, DurableError> {
        let mut meta = self.meta.clone();
        let local_id = meta.take_local_id();
        meta.outbox.insert(
            local_id,
            Outbound {
                local_id,
                plaintext: content.encode(),
                status: OutboundStatus::Queued,
                ciphertext: None,
                secret_id,
                channel: Channel::Conversation,
            },
        );
        self.commit(meta)?;
        Ok(local_id)
    }

    /// **Idempotent:** an already-encrypted message returns its cached ciphertext without advancing
    /// the ratchet again, so a retry can never double-spend a message key.
    pub fn encrypt(&mut self, local_id: u64) -> Result<Vec<u8>, DurableError> {
        let existing = self
            .meta
            .outbox
            .get(&local_id)
            .ok_or(DurableError::UnknownLocal)?;
        if let Some(ciphertext) = &existing.ciphertext {
            return Ok(ciphertext.clone());
        }
        let plaintext = existing.plaintext.clone();
        let channel = existing.channel;
        let ciphertext = {
            let Session {
                member,
                conversation,
                self_group,
                ..
            } = &mut self.session;
            match channel {
                Channel::Conversation => conversation.encrypt(member, &plaintext)?,
                // Tagged for the self-group but none exists: fail closed rather than silently
                // leaking the message into the conversation.
                Channel::SelfGroup => self_group
                    .as_mut()
                    .ok_or(DurableError::SelfGroup)?
                    .encrypt(member, &plaintext)?,
            }
        };
        // Decode so the DISPLAY message holds the body, never the encoded bytes. A secret becomes an
        // empty placeholder + sender-side tombstone, so the sender keeps no reopenable copy.
        let content = Content::decode(&plaintext).map_err(map_content)?;
        let mut meta = self.meta.clone();
        let local_id_for_msg = meta.take_local_id();
        if let Some(entry) = meta.outbox.get_mut(&local_id) {
            entry.ciphertext = Some(ciphertext.clone());
            entry.status = OutboundStatus::Encrypted;
        }
        let display = match &content {
            Content::Normal { body } => Some(Message {
                local_id: local_id_for_msg,
                direction: Direction::Outbound,
                plaintext: body.clone(),
                envelope_id: None,
                secret_id: None,
            }),
            Content::Secret { secret_id, .. } => {
                meta.secrets.insert(
                    sid_key(secret_id),
                    SecretRecord::tombstone_sender(*secret_id),
                );
                Some(Message {
                    local_id: local_id_for_msg,
                    direction: Direction::Outbound,
                    plaintext: Vec::new(),
                    envelope_id: None,
                    secret_id: Some(*secret_id),
                })
            }
            // Control messages are not user-visible on the sender — no message-log entry.
            Content::SecretConsumed { .. }
            | Content::DeliveryKeyGrant { .. }
            | Content::HistorySync { .. } => None,
        };
        if let Some(display) = display {
            meta.messages.push(display);
        }
        self.commit(meta)?;
        Ok(ciphertext)
    }

    /// A secret's body is scrubbed from the outbox here, now that the server has it; the cached
    /// ciphertext stays for a late retry, but the sender keeps no reopenable plaintext.
    pub fn mark_sent(&mut self, local_id: u64) -> Result<(), DurableError> {
        let mut meta = self.meta.clone();
        if let Some(entry) = meta.outbox.get_mut(&local_id) {
            entry.status = OutboundStatus::Sent;
            if entry.secret_id.is_some() {
                for b in entry.plaintext.iter_mut() {
                    *b = 0;
                }
                entry.plaintext = Vec::new();
            }
        } else {
            return Err(DurableError::UnknownLocal);
        }
        self.commit(meta)
    }

    // --- Secret-message reveal API (view-once ephemeral messages) ---------------------------------

    /// **Atomic + fail closed:** the transition to `Countdown` is durably committed BEFORE this
    /// returns `Ok`. On `Err` — failed write, or an invalid transition such as a double tap or
    /// replay — the caller MUST NOT show anything. `now_ms` is the caller's monotonic clock.
    pub fn begin_secret_reveal(
        &mut self,
        secret_id: &[u8; SECRET_ID_LEN],
        now_ms: u64,
    ) -> Result<(), DurableError> {
        let mut meta = self.meta.clone();
        let rec = meta
            .secrets
            .get_mut(&sid_key(secret_id))
            .ok_or(DurableError::UnknownLocal)?;
        rec.begin_reveal(now_ms).map_err(|_| DurableError::Mls)?;
        self.commit(meta)
    }

    /// The consumption control message for a secret revealed on THIS device (ADR-0015, account-wide
    /// single-view). Returns the outbound `local_id` to encrypt + broadcast, or `None` if the secret
    /// is unknown, is the sender's own copy, or was not revealed here. **Idempotent:** repeated
    /// calls return the same id, so it is built and ratchet-advanced at most once.
    pub fn emit_secret_consumption(
        &mut self,
        secret_id: &[u8; SECRET_ID_LEN],
    ) -> Result<Option<u64>, DurableError> {
        let rec = match self.meta.secrets.get(&sid_key(secret_id)) {
            Some(r) => r,
            None => return Ok(None),
        };
        if rec.side != SecretSide::Recipient || rec.state == SecretState::Sealed {
            return Ok(None);
        }
        if let Some(existing) = rec.consumption_local_id {
            return Ok(Some(existing));
        }
        // The self-group keeps the conversation's other party from learning the secret was opened.
        // Without one (single device, or not yet linked) fall back to the conversation — option 2
        // semantics, a documented degradation (SECRET_MESSAGES.md).
        let channel = if self.session.self_group.is_some() {
            Channel::SelfGroup
        } else {
            Channel::Conversation
        };
        let mut meta = self.meta.clone();
        let local_id = meta.take_local_id();
        meta.outbox.insert(
            local_id,
            Outbound {
                local_id,
                plaintext: Content::SecretConsumed {
                    secret_id: *secret_id,
                }
                .encode(),
                status: OutboundStatus::Queued,
                ciphertext: None,
                secret_id: None, // a control message, not a user-visible secret placeholder
                channel,
            },
        );
        if let Some(rec) = meta.secrets.get_mut(&sid_key(secret_id)) {
            rec.consumption_local_id = Some(local_id);
        }
        self.commit(meta)?;
        Ok(Some(local_id))
    }

    /// Advances for `now_ms`, persisting on a state change so a consumption survives a crash.
    pub fn secret_state(
        &mut self,
        secret_id: &[u8; SECRET_ID_LEN],
        now_ms: u64,
    ) -> Result<Option<SecretState>, DurableError> {
        let before = match self.meta.secrets.get(&sid_key(secret_id)) {
            Some(r) => r.state,
            None => return Ok(None),
        };
        let mut meta = self.meta.clone();
        let rec = meta
            .secrets
            .get_mut(&sid_key(secret_id))
            .expect("present above");
        let after = rec.poll(now_ms);
        if after != before {
            self.commit(meta)?;
        }
        Ok(Some(after))
    }

    /// The plaintext gate: `None` while sealed or counting down, and forever after expiry. Persists
    /// any state advance, including expiry-driven consumption + scrub.
    pub fn secret_visible_body(
        &mut self,
        secret_id: &[u8; SECRET_ID_LEN],
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, DurableError> {
        let before = match self.meta.secrets.get(&sid_key(secret_id)) {
            Some(r) => r.state,
            None => return Ok(None),
        };
        let mut meta = self.meta.clone();
        let rec = meta
            .secrets
            .get_mut(&sid_key(secret_id))
            .expect("present above");
        let body = rec.visible_body(now_ms).map(|b| b.to_vec());
        if rec.state != before {
            self.commit(meta)?;
        }
        Ok(body)
    }

    /// 0 when not in that phase. Drives the UI timer/fade.
    pub fn secret_remaining_ms(
        &mut self,
        secret_id: &[u8; SECRET_ID_LEN],
        now_ms: u64,
    ) -> Result<(u64, u64), DurableError> {
        let mut meta = self.meta.clone();
        let (countdown, view) = match meta.secrets.get_mut(&sid_key(secret_id)) {
            Some(r) => {
                let before = r.state;
                let c = r.remaining_countdown_ms(now_ms);
                let v = r.remaining_view_ms(now_ms);
                if r.state != before {
                    self.commit(meta)?;
                }
                (c, v)
            }
            None => (0, 0),
        };
        Ok((countdown, view))
    }

    /// Used on a detected screenshot/capture or an explicit close. Idempotent; scrubs the body.
    pub fn consume_secret(&mut self, secret_id: &[u8; SECRET_ID_LEN]) -> Result<(), DurableError> {
        let mut meta = self.meta.clone();
        if let Some(rec) = meta.secrets.get_mut(&sid_key(secret_id)) {
            rec.consume();
            self.commit(meta)?;
        }
        Ok(())
    }

    pub fn secret_tombstone_text() -> &'static str {
        crate::secret::TOMBSTONE_TEXT
    }

    /// Inbound decrypted + outbound, in order.
    pub fn messages(&self) -> &[Message] {
        &self.meta.messages
    }

    pub fn epoch(&self) -> u64 {
        self.session.conversation.epoch()
    }

    /// 0 for blobs written before versioning.
    pub fn format_version(&self) -> u32 {
        self.meta.format_version
    }

    /// Snapshots the MLS store together with `meta` in one atomic commit, adopting `meta` only on
    /// success. Per the recovery contract, a failure means the caller must discard and `open` again.
    fn commit(&mut self, meta: Meta) -> Result<(), DurableError> {
        commit_blob(&mut self.journal, &self.session, &meta)?;
        self.meta = meta;
        Ok(())
    }
}

/// Shared by the conversation and self-group channels so content handling is defined in exactly ONE
/// place regardless of which group decrypted it. A decode failure — an authenticated member sent
/// malformed content — is redacted, and the caller does NOT commit the ratchet advance.
fn apply_incoming(
    meta: &mut Meta,
    incoming: Incoming,
    envelope_id: u64,
) -> Result<InboundOutcome, DurableError> {
    Ok(match incoming {
        Incoming::Application(payload) => match Content::decode(&payload).map_err(map_content)? {
            Content::Normal { body } => {
                let local_id = meta.take_local_id();
                meta.messages.push(Message {
                    local_id,
                    direction: Direction::Inbound,
                    plaintext: body.clone(),
                    envelope_id: Some(envelope_id),
                    secret_id: None,
                });
                InboundOutcome::Application(body)
            }
            Content::Secret { secret_id, body } => {
                if meta.secrets.contains_key(&sid_key(&secret_id)) {
                    // A distinct envelope replaying a seen secret id: never grant a second
                    // placeholder or viewing opportunity.
                    InboundOutcome::Duplicate
                } else {
                    let local_id = meta.take_local_id();
                    meta.secrets.insert(
                        sid_key(&secret_id),
                        SecretRecord::sealed_recipient(secret_id, body),
                    );
                    meta.messages.push(Message {
                        local_id,
                        direction: Direction::Inbound,
                        plaintext: Vec::new(),
                        envelope_id: Some(envelope_id),
                        secret_id: Some(secret_id),
                    });
                    InboundOutcome::SecretSealed { secret_id }
                }
            }
            // ADR-0015: another device revealed this secret; force-consume our copy so it can never
            // be opened here. A device that never held it no-ops.
            Content::SecretConsumed { secret_id } => {
                if let Some(rec) = meta.secrets.get_mut(&sid_key(&secret_id)) {
                    rec.consume();
                }
                InboundOutcome::SecretConsumedRemotely { secret_id }
            }
            // ADR-0014 Slice 2c: surfaced for the client to store keyed by sender; no log entry.
            Content::DeliveryKeyGrant { key_r } => InboundOutcome::DeliveryKeyGranted { key_r },
            // #7: append replicated history to the local log, each with a fresh local id.
            Content::HistorySync { entries } => {
                let count = entries.len() as u64;
                for e in entries {
                    let local_id = meta.take_local_id();
                    meta.messages.push(Message {
                        local_id,
                        direction: if e.outbound {
                            Direction::Outbound
                        } else {
                            Direction::Inbound
                        },
                        plaintext: e.body,
                        envelope_id: None, // synced, not decrypted from a server envelope
                        secret_id: None,
                    });
                }
                InboundOutcome::HistorySynced { count }
            }
        },
        Incoming::StateAdvanced => InboundOutcome::StateAdvanced,
    })
}

fn commit_blob<J: Journal>(
    journal: &mut J,
    session: &Session,
    meta: &Meta,
) -> Result<(), DurableError> {
    let store = session.member.export_store()?;
    let bytes = serde_json::to_vec(&Blob {
        store,
        meta: meta.clone(),
    })
    .map_err(|_| DurableError::Codec)?;
    journal.commit(&bytes)
}

// --------------------------------------------------------------------------------------------
// Test journal: in-memory, shareable, with an injectable commit failure to simulate a crash
// before a commit lands.

#[derive(Default)]
struct JournalInner {
    blob: Option<Vec<u8>>,
    fail_next: bool,
    panic_next: bool,
}

#[derive(Clone, Default)]
pub struct InMemoryJournal {
    inner: Arc<Mutex<JournalInner>>,
}

impl InMemoryJournal {
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulates a crash before the write lands.
    pub fn fail_next_commit(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.fail_next = true;
        }
    }

    /// Proves the FFI boundary contains panics as typed errors — they must never unwind across the
    /// C ABI. Test support only.
    pub fn panic_next_commit(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.panic_next = true;
        }
    }
}

impl Journal for InMemoryJournal {
    fn commit(&mut self, blob: &[u8]) -> Result<(), DurableError> {
        let mut g = self.inner.lock().map_err(|_| DurableError::Journal)?;
        if g.panic_next {
            g.panic_next = false;
            panic!("injected journal panic (test)");
        }
        if g.fail_next {
            g.fail_next = false;
            return Err(DurableError::Journal);
        }
        g.blob = Some(blob.to_vec());
        Ok(())
    }

    fn load(&self) -> Result<Option<Vec<u8>>, DurableError> {
        let g = self.inner.lock().map_err(|_| DurableError::Journal)?;
        Ok(g.blob.clone())
    }
}

// --------------------------------------------------------------------------------------------
// Production journal: an encrypted, atomically-written file.
//
// - At rest: the blob (ratchet secrets + decrypted messages) is sealed with AES-256-GCM (RustCrypto,
//   no custom crypto). The key comes from the caller — on device, the Keychain-wrapped hierarchy
//   (CRYPTOGRAPHY.md §5) — never hard-coded, never in the file.
// - Atomicity: temp file (fsync'd) then `rename`, so a crash mid-write can never leave a torn blob.
// - Tamper-evidence: GCM authentication fails closed on any modification.
//
// Layout: `nonce (12 bytes) || AES-256-GCM ciphertext`. A fresh random nonce per write keeps the
// (key, nonce) pair unique, which AES-GCM requires.

pub struct FileJournal {
    path: PathBuf,
    cipher: Aes256Gcm,
}

impl FileJournal {
    /// The same path + key reopen the persisted session after a relaunch. On device the key comes
    /// from the at-rest key hierarchy.
    pub fn new(path: impl Into<PathBuf>, key: &[u8; 32]) -> Self {
        // 32 bytes is always a valid AES-256 key length.
        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 key is 32 bytes");
        Self {
            path: path.into(),
            cipher,
        }
    }

    fn tmp_path(&self) -> PathBuf {
        let mut p = self.path.clone();
        let mut name = p.file_name().map(|n| n.to_os_string()).unwrap_or_default();
        name.push(".tmp");
        p.set_file_name(name);
        p
    }
}

impl Journal for FileJournal {
    fn commit(&mut self, blob: &[u8]) -> Result<(), DurableError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(&nonce_bytes.into(), blob)
            .map_err(|_| DurableError::Journal)?;

        let mut out = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);

        // Write to a temp file, fsync, then atomically rename over the target.
        let tmp = self.tmp_path();
        {
            let mut f = std::fs::File::create(&tmp).map_err(|_| DurableError::Journal)?;
            f.write_all(&out).map_err(|_| DurableError::Journal)?;
            f.sync_all().map_err(|_| DurableError::Journal)?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|_| DurableError::Journal)?;
        Ok(())
    }

    fn load(&self) -> Result<Option<Vec<u8>>, DurableError> {
        let data = match std::fs::read(&self.path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(DurableError::Journal),
        };
        if data.len() < 12 {
            return Err(DurableError::Journal);
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce: [u8; 12] = nonce_bytes.try_into().map_err(|_| DurableError::Journal)?;
        let plaintext = self
            .cipher
            .decrypt(&nonce.into(), ciphertext)
            .map_err(|_| DurableError::Journal)?; // fails closed on tamper / wrong key
        Ok(Some(plaintext))
    }
}

// A `uniffi::Object` cannot be generic, but `DurableSession<J>` is — so the FFI wraps
// `DurableSession<JournalKind>`, which picks the backend at construction: `File` on device/Swift
// tests, `Memory` for Rust crash-injection tests. One persistence authority, not a second store.
pub enum JournalKind {
    // Boxed: `FileJournal` carries the AES key schedule, far larger than the `Memory` variant
    // (clippy::large_enum_variant).
    File(Box<FileJournal>),
    Memory(InMemoryJournal),
}

impl Journal for JournalKind {
    fn commit(&mut self, blob: &[u8]) -> Result<(), DurableError> {
        match self {
            JournalKind::File(j) => j.commit(blob),
            JournalKind::Memory(j) => j.commit(blob),
        }
    }

    fn load(&self) -> Result<Option<Vec<u8>>, DurableError> {
        match self {
            JournalKind::File(j) => j.load(),
            JournalKind::Memory(j) => j.load(),
        }
    }
}

#[cfg(test)]
mod dedup_tests {
    use super::{Meta, MAX_SEEN_ABOVE_WATERMARK};

    #[test]
    fn contiguous_ids_collapse_into_the_watermark() {
        let mut meta = Meta::default();
        for id in 1..=100 {
            meta.record_seen(id);
        }
        // The whole contiguous run folded into the watermark; nothing stored id-by-id.
        assert_eq!(meta.dedup_watermark, 100);
        assert!(meta.seen_inbound.is_empty());
        // Every id in the run is still recognized as seen; the next one is not.
        assert!(meta.is_seen(1));
        assert!(meta.is_seen(100));
        assert!(!meta.is_seen(101));
    }

    #[test]
    fn out_of_order_ids_are_retained_until_the_gap_fills() {
        let mut meta = Meta::default();
        meta.record_seen(1);
        meta.record_seen(3); // gap at 2
        assert_eq!(meta.dedup_watermark, 1);
        assert_eq!(meta.seen_inbound.iter().copied().collect::<Vec<_>>(), [3]);
        assert!(meta.is_seen(1));
        assert!(!meta.is_seen(2));
        assert!(meta.is_seen(3));
        // Filling the gap collapses everything.
        meta.record_seen(2);
        assert_eq!(meta.dedup_watermark, 3);
        assert!(meta.seen_inbound.is_empty());
        assert!(meta.is_seen(2));
    }

    #[test]
    fn redelivery_below_the_watermark_is_still_a_duplicate() {
        let mut meta = Meta::default();
        for id in 1..=10 {
            meta.record_seen(id);
        }
        assert_eq!(meta.dedup_watermark, 10);
        // Re-recording an already-collapsed id is a no-op and stays seen.
        assert!(meta.is_seen(5));
        meta.record_seen(5);
        assert_eq!(meta.dedup_watermark, 10);
        assert!(meta.seen_inbound.is_empty());
    }

    #[test]
    fn tail_is_hard_bounded_under_a_permanent_gap() {
        let mut meta = Meta::default();
        // A permanent gap at id 1: every later id arrives out of order and can never collapse.
        for id in 2..(MAX_SEEN_ABOVE_WATERMARK as u64 + 3_000) {
            meta.record_seen(id);
        }
        // Memory stays bounded rather than growing without limit.
        assert!(meta.seen_inbound.len() <= MAX_SEEN_ABOVE_WATERMARK);
        // The most recently seen ids are still recognized...
        let highest = MAX_SEEN_ABOVE_WATERMARK as u64 + 2_999;
        assert!(meta.is_seen(highest));
        // ...and forcing the watermark up only ever marks OLDER ids as seen (never un-sees a newer
        // one): the watermark never exceeds the highest processed id.
        assert!(meta.dedup_watermark <= highest);
    }
}
