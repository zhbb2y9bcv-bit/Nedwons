//! Crash-safe client state machine (Gate 2).
//!
//! MLS ratchet state and visible message state must advance **together**. If a crash could advance
//! the ratchet without capturing the decrypted plaintext, the message key is gone and the message
//! is lost forever; if it could mark an envelope acknowledged without durably processing it, the
//! server drops it and it is lost. So this layer persists everything as **one atomically committed
//! blob** = `{ MLS-store snapshot, message/queue metadata }`. Because they are one write, they can
//! never be torn apart by a crash.
//!
//! Recovery contract: any operation that returns `Err` may have advanced the in-memory MLS state
//! without committing. The caller MUST discard the [`DurableSession`] and call [`DurableSession::open`]
//! again, which reloads the last durably committed state. Tests exercise exactly this.
//!
//! What this slice covers: inbound dedup (at-least-once redelivery is idempotent), no-ack-until-
//! durable, no partial advance on a failed commit, and retry-without-re-encrypt on the outbound
//! path. Out-of-order/epoch-fork resolution and the encrypted on-device DB are the remaining Gate 2
//! body (the store blob is where on-device encryption + the OpenMLS fork/discard strategy attach).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::content::{Content, ContentError, SECRET_ID_LEN};
use crate::secret::{SecretRecord, SecretSide, SecretState};
use crate::{Conversation, Incoming, Member};

/// On-disk blob schema version. Bumped when the serialized `{store, meta}` layout changes so an
/// older blob is detectable (and, in future, migratable) rather than silently misread. Surfaced to
/// the client via the FFI `capabilities()` call.
pub const BLOB_FORMAT_VERSION: u32 = 1;

/// Upper bound on the out-of-order dedup tail retained above [`Meta::dedup_watermark`] (R-105).
/// The whole blob is rewritten on every commit, so an unbounded `seen_inbound` set would make each
/// write grow without limit. Near-in-order at-least-once delivery keeps the tail tiny; this cap only
/// bites under a pathological permanent gap, where the watermark is force-advanced (see
/// [`compact_dedup`]). Blob-level dedup is a fast path — OpenMLS's ratchet rejects a genuinely
/// replayed ciphertext regardless — so bounding it never weakens replay protection.
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
    /// A self-group precondition was violated: an operation needing the account's device self-group
    /// (ADR-0015 option 3) was called with none established, or `create_self_group` was called when
    /// one already exists. Redacted; carries no state.
    #[error("self-group precondition violated")]
    SelfGroup,
}

impl From<crate::MlsError> for DurableError {
    fn from(_: crate::MlsError) -> Self {
        DurableError::Mls
    }
}

/// Map a redacted content-decode failure to a redacted durable error (no payload bytes leak).
fn map_content(_: ContentError) -> DurableError {
    DurableError::Codec
}

/// Direction of a stored message.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// A durably stored message (decrypted content lives here; the blob is encrypted at rest on device).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Message {
    pub local_id: u64,
    pub direction: Direction,
    pub plaintext: Vec<u8>,
    /// Inbound only: the server envelope id this was decrypted from.
    pub envelope_id: Option<u64>,
    /// `Some` if this message is a **secret** (view-once) message. The `plaintext` field is then
    /// EMPTY — the body lives (transiently) in [`Meta::secrets`] and is never returned in the message
    /// log. The UI renders a sealed placeholder / tombstone from the secret's state instead.
    /// `#[serde(default)]` ⇒ blobs written before secret messages load as `None`.
    #[serde(default)]
    pub secret_id: Option<[u8; SECRET_ID_LEN]>,
}

/// Which MLS group an outbound message is encrypted with. Normal messages and secrets go through
/// the **conversation** (with the peer/sender). A `SecretConsumed` control message (ADR-0015
/// option 3) goes through the account's **self-group** — only this account's own devices — so the
/// conversation's other party never receives the read signal. `#[serde(default)]` ⇒ blobs written
/// before this field load as `Conversation`.
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
    /// The **encoded [`Content`] envelope** to encrypt (not the raw body) — so the classification
    /// travels inside the MLS ciphertext. Scrubbed to empty once a secret message is sent.
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

/// What processing an inbound envelope yielded.
#[derive(Debug, PartialEq, Eq)]
pub enum InboundOutcome {
    Application(Vec<u8>),
    StateAdvanced,
    /// Already processed (at-least-once redelivery, OR a replayed secret id). A durable no-op.
    Duplicate,
    /// A **secret** message arrived and is stored as a sealed placeholder. Carries its id so the
    /// UI can show a sealed placeholder; the body is NOT returned here (it is revealed once, later,
    /// via the reveal state machine).
    SecretSealed {
        secret_id: [u8; SECRET_ID_LEN],
    },
    /// A **consumption** control message arrived (ADR-0015): another of this account's devices
    /// revealed `secret_id`, so this device consumed its copy too (account-wide single-view). If
    /// this device held that secret it is now `Consumed`; otherwise this is a harmless no-op.
    SecretConsumedRemotely {
        secret_id: [u8; SECRET_ID_LEN],
    },
}

/// Serializable metadata that travels in the committed blob alongside the MLS store snapshot.
#[derive(Serialize, Deserialize, Clone, Default)]
struct Meta {
    /// Blob schema version. `#[serde(default)]` ⇒ blobs written before this field load as 0.
    #[serde(default)]
    format_version: u32,
    identity: Vec<u8>,
    public_key: Vec<u8>,
    group_id: Vec<u8>,
    /// Every envelope id `<= dedup_watermark` is considered already processed. The contiguous
    /// low prefix of seen ids is collapsed into this watermark so it need not be stored id-by-id
    /// (R-105 bounded dedup). `#[serde(default)]` ⇒ pre-watermark blobs load as 0 and self-heal on
    /// the next commit.
    #[serde(default)]
    dedup_watermark: u64,
    /// Processed envelope ids **above** `dedup_watermark` — the out-of-order tail only, bounded by
    /// [`MAX_SEEN_ABOVE_WATERMARK`]. Combined with the watermark this is the full dedup set.
    seen_inbound: BTreeSet<u64>,
    /// Envelope ids durably processed and therefore safe to acknowledge to the server.
    ack_eligible: BTreeSet<u64>,
    next_local_id: u64,
    messages: Vec<Message>,
    outbox: BTreeMap<u64, Outbound>,
    /// Reveal state for each secret message, keyed by its **hex** id (JSON maps need string keys).
    /// Crash-safe: every transition is committed here before it becomes observable.
    /// `#[serde(default)]` ⇒ older blobs load empty.
    #[serde(default)]
    secrets: BTreeMap<String, SecretRecord>,
    /// The MLS group id of this account's **self-group** (ADR-0015 option 3), if one is established —
    /// the group of only this account's own devices, over which `SecretConsumed` control messages are
    /// synced without the conversation's other party learning anything. Its ratchet state lives in the
    /// same provider store as the conversation, so the one `export_store` snapshot persists both.
    /// `#[serde(default)]` ⇒ older blobs load with no self-group.
    #[serde(default)]
    self_group_id: Option<Vec<u8>>,
}

/// Hex key for a secret id (JSON object keys must be strings, so the raw `[u8; 16]` can't be a key).
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

    /// Collapse the contiguous low prefix of `seen_inbound` into `dedup_watermark`, then, if the
    /// non-contiguous tail still exceeds the cap, force the watermark up to absorb the lowest ids.
    /// Forcing only ever marks *older* ids as seen (never un-sees a newer one), so a not-yet-seen
    /// low id could at worst be treated as a duplicate later — bounded, and the ratchet is the real
    /// replay guard (see [`MAX_SEEN_ABOVE_WATERMARK`]).
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
    /// The account's device self-group (ADR-0015 option 3), if established. Shares `member`'s
    /// provider with `conversation`, so both groups are captured by one `export_store` snapshot.
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

/// Durable append-only store for the single session blob. `commit` must be atomic (all-or-nothing).
/// On device this is a small encrypted file/row written via a temp-file+rename or a DB transaction.
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
    /// Create a brand-new conversation owned by `identity`, persisting it before returning.
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

    /// Adopt an existing member + conversation into a durable session, persisting it before
    /// returning. This is the general seam: the async add/join key-package↔welcome exchange is done
    /// with the lower-level `Member`/`Conversation` (or `ClientApi`) — which must share one provider
    /// across key-package generation and `join_from_welcome` — and the result is adopted here for
    /// crash-safe persistence. (`create` is the convenience for the group creator.)
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
    /// **Fail closed for secrets:** any secret whose reveal had begun (recipient side, `Countdown`
    /// or `Visible`) but was not cleanly consumed is forced to `Consumed` here — a crash or
    /// termination after reveal begins must never grant another viewing opportunity on relaunch. The
    /// forced consumption is committed before the session is returned.
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

    /// Publish this member's key package (for others to add them).
    pub fn key_package(&self) -> Result<Vec<u8>, DurableError> {
        Ok(self.session.member.key_package_bytes()?)
    }

    /// Add a member; returns (commit, welcome). The grown group is persisted before returning.
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

    /// Create this account's self-group with this device as its sole initial member, persisting it.
    /// Errors with [`DurableError::SelfGroup`] if one already exists (never silently orphan a group).
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

    /// Add another of this account's devices to the self-group by its key package. Returns
    /// (commit, welcome) to deliver to the existing devices / the new device. The advanced self-group
    /// state is persisted before returning. Errors with [`DurableError::SelfGroup`] if there is no
    /// self-group on this device yet.
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

    /// Join this account's self-group from a Welcome produced by another of its devices'
    /// [`add_self_device`](Self::add_self_device). Adopts it as this device's self-group and persists.
    /// Errors with [`DurableError::SelfGroup`] if a self-group is already established here.
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

    // ----- Staged commits for MLS-commit-authoritative membership (ADR-0010) ------------------
    //
    // Staging is deliberately NOT persisted: an in-flight commit awaiting the server's epoch CAS
    // is discardable, and on a crash the client reopens the last committed (pre-stage) state and
    // rebuilds. Only `merge_staged` / `process_commit_checked` (state the server accepted) persist.

    /// Stage an add: build commit + welcome without advancing the epoch or persisting.
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

    /// Stage a remove: build the commit without advancing the epoch or persisting.
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

    /// Discard the pending staged commit (server rejected / rebase). Nothing durable changes.
    pub fn clear_staged(&mut self) -> Result<(), DurableError> {
        let Session {
            member,
            conversation,
            ..
        } = &mut self.session;
        Ok(conversation.clear_staged(member)?)
    }

    /// Recipient path: process an inbound commit with the ADR-0010 correspondence check, then
    /// persist the advanced state. On mismatch nothing advances and nothing is persisted.
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

    /// Process an inbound envelope. Idempotent per `envelope_id` (at-least-once redelivery is a
    /// no-op). On success the advanced MLS state, the decrypted message, dedup marker, and
    /// ack-eligibility are all durable **together** before this returns.
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

    /// Process an inbound envelope that arrived on the account's **self-group** channel (ADR-0015
    /// option 3): a `SecretConsumed` control message from one of this account's OTHER devices, or a
    /// self-group membership commit (a device was linked/unlinked). Decrypts with the self-group —
    /// which the conversation's other party is not a member of — so the read signal never reaches
    /// them. Shares the same idempotent dedup + ack machinery as [`process_inbound`]; the caller
    /// routes an envelope here iff the relay tagged it for the self-group. Returns
    /// [`DurableError::SelfGroup`] if no self-group is established on this device.
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

    /// Envelope ids that are durably processed and safe to acknowledge to the server.
    pub fn ack_eligible(&self) -> Vec<u64> {
        self.meta.ack_eligible.iter().copied().collect()
    }

    /// After the server confirms an ack, stop tracking those ids as ack-eligible (dedup history in
    /// `seen_inbound` is retained). Persisted before returning.
    pub fn confirm_acked(&mut self, ids: &[u64]) -> Result<(), DurableError> {
        let mut meta = self.meta.clone();
        for id in ids {
            meta.ack_eligible.remove(id);
        }
        self.commit(meta)
    }

    /// Queue an outbound **normal** message (durable draft). Does NOT advance the ratchet. The body
    /// is wrapped in a [`Content::Normal`] envelope so every message shares one typed, versioned
    /// application format. Returns a local id.
    pub fn enqueue(&mut self, body: &[u8]) -> Result<u64, DurableError> {
        self.enqueue_content(
            Content::Normal {
                body: body.to_vec(),
            },
            None,
        )
    }

    /// Queue an outbound **secret** (view-once) message. A random secret id is generated; the body
    /// is wrapped in a [`Content::Secret`] envelope so the classification is encrypted end-to-end
    /// (the relay never learns a message is secret). Returns `(local_id, secret_id)`.
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

    /// Encrypt a queued message and return its envelope. **Idempotent:** if already encrypted, the
    /// cached ciphertext is returned and the ratchet is NOT advanced again (a retry can never
    /// double-encrypt or double-spend a message key).
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
                // A `SecretConsumed` control message (ADR-0015 option 3) is encrypted with the
                // self-group so the conversation's other party never receives it. If the outbound
                // was tagged for the self-group but none exists, that is a self-group precondition
                // violation — fail closed rather than silently leaking it to the conversation.
                Channel::SelfGroup => self_group
                    .as_mut()
                    .ok_or(DurableError::SelfGroup)?
                    .encrypt(member, &plaintext)?,
            }
        };
        // `plaintext` is the encoded Content envelope; decode it to build the DISPLAY message
        // (never the encoded bytes). A secret becomes an empty-plaintext placeholder + a sender-side
        // tombstone, so the sender never retains a reopenable copy.
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
            // A consumption control message (ADR-0015) is not user-visible — no message log entry.
            Content::SecretConsumed { .. } => None,
        };
        if let Some(display) = display {
            meta.messages.push(display);
        }
        self.commit(meta)?;
        Ok(ciphertext)
    }

    /// Mark a message accepted by the server. Persisted before returning. For a **secret** message,
    /// the sender's encoded body is scrubbed from the outbox now that the server has it — the cached
    /// ciphertext remains for any late retry, but the plaintext body is not retained (the sender
    /// keeps no reopenable copy).
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

    /// Begin revealing a sealed secret (the recipient tapped its placeholder). **Atomic + fail
    /// closed:** the transition to `Countdown` (with its deadlines) is committed to durable storage
    /// BEFORE this returns `Ok`. If the state write fails, or the transition is invalid (not sealed,
    /// wrong side, already revealed/consumed — a double tap or replay), this returns `Err` and the
    /// caller MUST NOT show anything. `now_ms` is the caller's monotonic clock.
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

    /// Build (once) the **consumption control message** for a secret whose reveal has begun on THIS
    /// recipient device (ADR-0015, account-wide single-view). Returns the outbound `local_id` to
    /// `encrypt` + broadcast to the account's other devices (through the same MLS group — opaque to
    /// the relay), or `None` if the secret is unknown, is the sender's own copy, or has not been
    /// revealed here. **Idempotent:** repeated calls return the same `local_id`, so the message is
    /// built + ratchet-advanced at most once. A caller that does not broadcast (single device) simply
    /// never calls this — no message is enqueued.
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
        // Route through the self-group (ADR-0015 option 3) when this account has one established, so
        // the conversation's other party never learns the secret was opened. If no self-group exists
        // (a single-device account, or one not yet linked), fall back to the conversation channel
        // (option 2 semantics) — a graceful degradation, documented in SECRET_MESSAGES.md.
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

    /// The current reveal state of a secret (advancing it for `now_ms`). Persists the advance when it
    /// changes state (so a consumption survives a crash). `None` if the id is unknown.
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

    /// The secret's plaintext **iff it is currently visible** at `now_ms` — the plaintext gate.
    /// `None` while sealed/counting down and forever after expiry. Persists a state advance (incl.
    /// expiry-driven consumption + scrub) when it occurs.
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

    /// Remaining countdown / viewing time in ms (0 when not in that phase) — for the UI timer/fade.
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

    /// Force a secret to the terminal tombstone (screenshot/capture detected, or an explicit close).
    /// Idempotent; scrubs the body. Persisted before returning.
    pub fn consume_secret(&mut self, secret_id: &[u8; SECRET_ID_LEN]) -> Result<(), DurableError> {
        let mut meta = self.meta.clone();
        if let Some(rec) = meta.secrets.get_mut(&sid_key(secret_id)) {
            rec.consume();
            self.commit(meta)?;
        }
        Ok(())
    }

    /// The exact non-sensitive tombstone text shown for a consumed/sent secret.
    pub fn secret_tombstone_text() -> &'static str {
        crate::secret::TOMBSTONE_TEXT
    }

    /// Ordered log of stored messages (inbound decrypted + outbound).
    pub fn messages(&self) -> &[Message] {
        &self.meta.messages
    }

    /// Current MLS epoch.
    pub fn epoch(&self) -> u64 {
        self.session.conversation.epoch()
    }

    /// Schema version of the loaded blob (0 for blobs written before versioning).
    pub fn format_version(&self) -> u32 {
        self.meta.format_version
    }

    /// Snapshot the (already-advanced) MLS store together with `meta` and commit atomically, then
    /// adopt `meta` in memory. If the commit fails, `meta` is not adopted; per the recovery
    /// contract the caller must discard this session and `open` again.
    fn commit(&mut self, meta: Meta) -> Result<(), DurableError> {
        commit_blob(&mut self.journal, &self.session, &meta)?;
        self.meta = meta;
        Ok(())
    }
}

/// Apply a decrypted inbound message to `meta`, returning what it yielded. Shared by both the
/// conversation channel ([`DurableSession::process_inbound`]) and the self-group channel
/// ([`DurableSession::process_self_inbound`]) so the content-envelope handling — normal message,
/// sealed secret, or `SecretConsumed` control message — is defined in exactly ONE place regardless
/// of which group decrypted it. The MLS plaintext is a [`Content`] envelope; a decode failure (an
/// authenticated member sent malformed content) is a typed, redacted error and the caller does NOT
/// commit the ratchet advance, matching the existing process-error contract.
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
                    // Replayed secret id (a distinct envelope carrying an already-seen secret).
                    // Never grant a second sealed placeholder / viewing opportunity.
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
            // ADR-0015: another of this account's devices revealed this secret. Force-consume our
            // copy (idempotent) so it can never be opened here — account-wide single-view. No
            // user-visible message; a device that never held this secret simply no-ops.
            Content::SecretConsumed { secret_id } => {
                if let Some(rec) = meta.secrets.get_mut(&sid_key(&secret_id)) {
                    rec.consume();
                }
                InboundOutcome::SecretConsumedRemotely { secret_id }
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
// Reference / test journal: an in-memory, shareable store with an injectable commit failure so a
// crash *before* a commit lands can be simulated. On device, replace with an encrypted-file or DB
// journal that does an atomic temp-file+rename / transactional write.

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

    /// Make the next `commit` fail without storing — simulates a crash before the write lands.
    pub fn fail_next_commit(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.fail_next = true;
        }
    }

    /// Make the next `commit` **panic** — used to prove the FFI boundary contains panics as typed
    /// errors (they must never unwind across the C ABI). Test support only.
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
// - **At rest encryption:** the blob (which contains ratchet secrets + decrypted messages) is
//   sealed with AES-256-GCM (vetted RustCrypto — no custom crypto). The key is supplied by the
//   caller; on device it comes from the Keychain-wrapped local key hierarchy (CRYPTOGRAPHY.md §5),
//   never hard-coded and never in the file.
// - **Atomicity:** each commit writes a temp file (fsync'd) then `rename`s it over the target, so a
//   crash mid-write can never leave a torn/partial blob — you either see the old blob or the new.
// - **Tamper-evidence:** GCM authentication fails closed on any modification of the ciphertext.
//
// File layout: `nonce (12 bytes) || AES-256-GCM ciphertext`. A fresh random nonce per write keeps
// the (key, nonce) pair unique, which AES-GCM requires.

pub struct FileJournal {
    path: PathBuf,
    cipher: Aes256Gcm,
}

impl FileJournal {
    /// `key` is a 32-byte AES-256 key (on device: from the local at-rest key hierarchy). The same
    /// path + key reopen the persisted session after a relaunch.
    pub fn new(path: impl Into<PathBuf>, key: &[u8; 32]) -> Self {
        // 32 bytes is always a valid AES-256 key length, so this cannot fail.
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

// --------------------------------------------------------------------------------------------
// Concrete journal selector.
//
// A `uniffi::Object` cannot be generic, but `DurableSession<J>` is. So the FFI layer wraps a
// `DurableSession<JournalKind>` where `JournalKind` picks the real backend at construction:
// `File` on device / in Swift host tests (device-faithful: real at-rest encryption + atomic
// rename), `Memory` for Rust crash-injection tests. This keeps ONE persistence authority — every
// variant is still just the same `Journal` contract — rather than introducing a second store.

pub enum JournalKind {
    // Boxed: `FileJournal` carries the AES key schedule and is far larger than the `Arc`-sized
    // `Memory` variant, so box it to keep the enum small (clippy::large_enum_variant).
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
