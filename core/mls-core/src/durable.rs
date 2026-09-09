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

use crate::attachment::AttachmentRef;
use crate::content::{
    Content, ContentError, HistoryEntry, ReceiptKind, DELIVERY_KEY_LEN, MESSAGE_ID_LEN,
    SECRET_ID_LEN,
};
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

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
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
    /// Unix milliseconds, stamped by THIS device: when it queued the message (outbound) or
    /// decrypted it (inbound).
    ///
    /// Deliberately not carried on the wire. A sender-claimed timestamp is a value a hostile member
    /// chooses, and it would be rendered as fact; stamping locally means a peer can never forge when
    /// something appeared on your device. The cost, stated honestly, is that a message delivered
    /// after a long offline period is timed when it arrives, not when it was sent.
    ///
    /// Advisory and display-only — unlike the secret-reveal timer, which keeps its injected
    /// monotonic clock precisely because it IS security-relevant and must resist clock changes.
    /// `#[serde(default)]` ⇒ messages logged before this field load as 0 ("unknown time").
    #[serde(default)]
    pub created_at_ms: u64,
    /// For an outbound message, the `outbox` entry it was created from, so its delivery state can be
    /// looked up. `None` for inbound and for replicated history.
    #[serde(default)]
    pub outbox_local_id: Option<u64>,
    /// `Some` when this message is a file: `plaintext` then holds the caption (often empty) and the
    /// bytes are fetched from the relay with this reference. `#[serde(default)]` ⇒ older blobs load
    /// as `None`.
    #[serde(default)]
    pub attachment: Option<AttachmentRef>,
    /// The sender-chosen id every OTHER device knows this message by — what a reply, a reaction or
    /// a receipt names. All-zero for messages logged before ids existed; those simply cannot be
    /// referred to, which is better than pretending an id we never received.
    #[serde(default)]
    pub message_id: [u8; MESSAGE_ID_LEN],
    /// The message this one answers, if any.
    #[serde(default)]
    pub reply_to: Option<[u8; MESSAGE_ID_LEN]>,
    /// The MLS-authenticated credential identity that sent this (ours, for outbound). What a
    /// delete-for-everyone is checked against: only the author may retract. Empty for messages
    /// logged before this field existed — those can never be remotely deleted (fail closed).
    #[serde(default)]
    pub sender: Vec<u8>,
    /// Wall-clock unix ms after which this message is scrubbed locally (disappearing messages).
    /// Stamped when the message is logged, from the timer then in force. Advisory-grade clock use,
    /// like `created_at_ms`: honesty in R-901 — expiry is each client deleting its OWN copy;
    /// nothing forces another device to. `None` = keeps forever.
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    /// Tombstoned by the author's delete-for-everyone: body and attachment are gone, the row
    /// remains so the thread can honestly show "message deleted" instead of silently reflowing.
    #[serde(default)]
    pub deleted: bool,
    /// The author replaced the text after sending (`Content::Edit`). Always shown — an edit is
    /// visible, never silent.
    #[serde(default)]
    pub edited: bool,
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
    /// Unix ms when the user queued it; copied onto the display message so the thread shows when
    /// it was written, not when it happened to encrypt.
    #[serde(default)]
    created_at_ms: u64,
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
    /// A member renamed the group. The new name is already persisted; returned so the UI refreshes.
    GroupRenamed {
        name: String,
    },
    /// A file arrived. Its bytes are still on the relay; the reference (with the key) is durable.
    AttachmentReceived {
        attachment: AttachmentRef,
    },
    /// Someone reacted to (or un-reacted from) a message this device holds.
    ReactionChanged {
        target: [u8; MESSAGE_ID_LEN],
    },
    /// Someone acknowledged `count` of OUR messages. Ids naming anything else were discarded.
    ReceiptsReceived {
        kind: ReceiptKind,
        count: u64,
    },
    /// Ephemeral: someone started or stopped typing. Nothing was persisted.
    Typing {
        sender: Vec<u8>,
        active: bool,
    },
    /// A member changed the conversation's disappearing-message timer (0 = off). Already
    /// persisted; returned so the UI refreshes.
    TimerChanged {
        seconds: u32,
    },
    /// The author retracted a message; the local copy is tombstoned. Returned so the UI redraws
    /// the bubble as "message deleted".
    MessageDeleted {
        target: [u8; MESSAGE_ID_LEN],
    },
    /// The author replaced a message's text; the local copy is updated and marked edited.
    MessageEdited {
        target: [u8; MESSAGE_ID_LEN],
    },
    /// A member set (or, with `removed`, cleared) the group's photo. Already persisted; refresh.
    GroupAvatarChanged {
        removed: bool,
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
    /// The group's name, as last set by any member over the E2EE channel. `None` = never named;
    /// the UI then falls back to describing the group by its members. Never sent to the relay.
    #[serde(default)]
    group_name: Option<String>,
    /// Reactions, keyed by the hex of the message they are attached to. Bounded per message, and
    /// only kept for messages this device actually has — see `apply_reaction`.
    #[serde(default)]
    reactions: BTreeMap<String, Vec<Reaction>>,
    /// Who has received/read the messages THIS device sent, keyed by hex message id. Only our own
    /// outbound messages get an entry: a receipt naming anything else is discarded.
    #[serde(default)]
    receipts: BTreeMap<String, ReceiptRecord>,
    /// Ids we have already sent a delivered/read receipt for, so a sync never re-sends one.
    #[serde(default)]
    sent_delivery_receipts: BTreeSet<String>,
    #[serde(default)]
    sent_read_receipts: BTreeSet<String>,
    /// The highest local id the user has seen; everything above it that is INBOUND is unread.
    ///
    /// `Option`, not a bare `u64`, because local ids start at **0**: a sentinel of 0 would make the
    /// very first message in a conversation permanently "already read". `None` = nothing read yet.
    /// `#[serde(default)]` ⇒ existing blobs load as `None`, so a returning user sees their backlog
    /// as unread rather than silently zeroed.
    #[serde(default)]
    last_read_local_id: Option<u64>,
    /// Disappearing-messages timer in seconds; 0 = off. Set over the E2EE channel
    /// (`Content::TimerChange`) and applied to messages logged AFTER the change — existing history
    /// keeps the expiry it was stamped with, matching what other members' clients do.
    #[serde(default)]
    disappear_after_secs: u32,
    /// The group's photo thumbnail, E2EE like the name. `None` = never set / removed.
    #[serde(default)]
    group_avatar: Option<Vec<u8>>,
    /// R-105: every message with `local_id` below this lives in the append-only ARCHIVE, not in
    /// this blob. The hot window (`messages`) is what every commit rewrites; the archive is
    /// written once per message and never again — which is the whole fix: the blob stops growing
    /// with history. `#[serde(default)]` ⇒ pre-archive blobs load with everything hot.
    #[serde(default)]
    archived_below_local_id: u64,
    /// How many messages the archive holds (kept here so counting needs no archive read).
    #[serde(default)]
    archived_count: u64,
}

/// Wall-clock unix milliseconds for a DISPLAY timestamp.
///
/// The system clock is used deliberately here and nowhere security-relevant: a message's rendered
/// time is advisory, and a user who moves their clock only misdates their own history. Every
/// decision that must resist clock manipulation — the secret-reveal countdown — takes an injected
/// monotonic clock instead. A clock before the epoch reads as 0 ("unknown time") rather than
/// panicking.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The expiry a message logged now should carry, given the timer currently in force.
fn expiry_for(disappear_after_secs: u32, created_at_ms: u64) -> Option<u64> {
    (disappear_after_secs > 0)
        .then(|| created_at_ms.saturating_add(u64::from(disappear_after_secs) * 1000))
}

/// Erase a message's content in place, leaving an honest tombstone row.
fn tombstone_message(message: &mut Message) {
    message.plaintext = Vec::new();
    message.attachment = None;
    message.secret_id = None;
    message.deleted = true;
}

/// One person's reaction to one message. The sender is the MLS-authenticated credential identity,
/// so a member cannot attribute a reaction to someone else.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Reaction {
    pub emoji: String,
    pub sender: Vec<u8>,
}

/// Who acknowledged one of our own messages. Sets, so a redelivered receipt cannot inflate a count.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Eq, Debug)]
pub struct ReceiptRecord {
    pub delivered_by: BTreeSet<Vec<u8>>,
    pub read_by: BTreeSet<Vec<u8>>,
}

/// A cap on reactions kept per message. A group member who spams distinct emoji must not be able to
/// grow another device's durable blob without bound; past this, further reactions are dropped.
const MAX_REACTIONS_PER_MESSAGE: usize = 64;

/// A message plus the delivery state the UI needs, resolved against the outbox at read time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageView {
    pub local_id: u64,
    pub direction: Direction,
    pub plaintext: Vec<u8>,
    pub envelope_id: Option<u64>,
    pub secret_id: Option<[u8; SECRET_ID_LEN]>,
    pub created_at_ms: u64,
    /// Outbound only: the relay has not accepted it yet (queued, or encrypted and awaiting upload).
    /// Always false for inbound, which by definition arrived.
    pub pending: bool,
    /// `Some` when this message is a file; `plaintext` is then its caption.
    pub attachment: Option<AttachmentRef>,
    pub message_id: [u8; MESSAGE_ID_LEN],
    /// The message this one answers; the UI resolves it against the log to render a quote.
    pub reply_to: Option<[u8; MESSAGE_ID_LEN]>,
    /// Reactions on this message, as currently known.
    pub reactions: Vec<Reaction>,
    /// For OUR OWN messages: how many other members have received it, and how many have read it.
    /// Always (0, 0) for inbound — a receipt is something we send about someone else's message.
    pub delivered_count: u32,
    pub read_count: u32,
    /// Wall-clock ms after which this device scrubs its copy (disappearing messages); `None` =
    /// keeps forever. Display-grade, like `created_at_ms`.
    pub expires_at_ms: Option<u64>,
    /// Retracted by its author (delete-for-everyone); body and attachment are gone.
    pub deleted: bool,
    /// The author replaced the text after sending; rendered with an "edited" tag.
    pub edited: bool,
    /// The MLS-authenticated credential identity that sent this (empty for pre-field history and
    /// replicated history). What a REPORT identifies a group message's author by — the relay
    /// resolves the device to its account server-side.
    pub sender: Vec<u8>,
}

/// Add or remove one person's reaction, idempotently: reacting twice with the same emoji is one
/// reaction, and removing one that is not there is a no-op. Bounded per message.
fn apply_reaction(
    meta: &mut Meta,
    target: &[u8; MESSAGE_ID_LEN],
    emoji: &str,
    remove: bool,
    sender: &[u8],
) {
    let entry = meta.reactions.entry(hex16(target)).or_default();
    let existing = entry
        .iter()
        .position(|r| r.sender == sender && r.emoji == emoji);
    match (remove, existing) {
        (true, Some(i)) => {
            entry.remove(i);
        }
        (false, None) if entry.len() < MAX_REACTIONS_PER_MESSAGE => entry.push(Reaction {
            emoji: emoji.to_string(),
            sender: sender.to_vec(),
        }),
        _ => {}
    }
    if entry.is_empty() {
        meta.reactions.remove(&hex16(target));
    }
}

/// A fresh message id. Random rather than a counter: ids are shared with the group, and a counter
/// would tell every member how much this device has ever sent.
fn new_message_id() -> [u8; MESSAGE_ID_LEN] {
    let mut id = [0u8; MESSAGE_ID_LEN];
    OsRng.fill_bytes(&mut id);
    id
}

/// Hex of a 16-byte id, for JSON map keys.
fn hex16(id: &[u8; MESSAGE_ID_LEN]) -> String {
    let mut s = String::with_capacity(MESSAGE_ID_LEN * 2);
    for b in id {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
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

    /// Append one immutable, already-serialized archived message (R-105). MUST be durable when it
    /// returns: the archive write happens BEFORE the blob commit that drops the message from the
    /// hot window (write-ahead), so a crash between the two leaves a harmless duplicate, never a
    /// lost message. The default refuses — a journal that cannot archive fails the spill closed
    /// rather than silently discarding history.
    fn archive_append(&mut self, record: &[u8]) -> Result<(), DurableError> {
        let _ = record;
        Err(DurableError::Journal)
    }

    /// Every archive record, in append order. Duplicated `local_id`s are possible after a crash
    /// between archive-append and blob-commit; readers collapse them (last write wins — the
    /// records are identical by construction, since messages are immutable once spilled).
    fn archive_load(&self) -> Result<Vec<Vec<u8>>, DurableError> {
        Ok(Vec::new())
    }

    /// Drop the archive (local history erase). Best-effort by contract; called AFTER the blob
    /// commit that zeroes the archive counters, so a crash in between leaves only invisible
    /// stale records (their ids sit above the reset watermark).
    fn archive_clear(&mut self) -> Result<(), DurableError> {
        Ok(())
    }
}

/// A joiner identity awaiting its Welcome, **persisted from the moment it exists**.
///
/// A key package is only redeemable by the provider store that generated its private key. Before
/// this type, a joiner lived only in memory: a Welcome that arrived after a relaunch — a group
/// created for you while the app was closed, which is the common case — could never be joined.
/// Every `key_package` re-commits the store, so each published prekey stays redeemable until the
/// identity joins (at which point [`DurableSession::adopt`] overwrites the blob with the session).
///
/// The blob is distinguishable from an Active session blob by construction: it carries
/// `pending_format_version` and no `meta`, so neither loader can mistake one for the other.
#[derive(Serialize, Deserialize)]
struct PendingBlob {
    pending_format_version: u32,
    identity: Vec<u8>,
    public_key: Vec<u8>,
    store: Vec<u8>,
}

const PENDING_BLOB_FORMAT_VERSION: u32 = 1;

pub struct PendingIdentity<J: Journal> {
    member: Member,
    journal: J,
}

/// Why a join did not produce a session.
pub enum PendingJoinError<J: Journal> {
    /// The Welcome was not for this identity (or malformed). The identity is handed back intact so
    /// the caller can try the next one — a lobby of joiners tries each until one fits.
    BadWelcome(Box<PendingIdentity<J>>, crate::MlsError),
    /// The first commit of the new session failed; nothing durable exists for it.
    Commit(DurableError),
}

impl<J: Journal> std::fmt::Debug for PendingJoinError<J> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadWelcome(_, e) => write!(f, "BadWelcome({e:?})"),
            Self::Commit(e) => write!(f, "Commit({e:?})"),
        }
    }
}

impl<J: Journal> PendingIdentity<J> {
    /// A fresh identity, persisted before returning.
    pub fn create(identity: &[u8], journal: J) -> Result<Self, DurableError> {
        let member = Member::new(identity)?;
        let mut this = Self { member, journal };
        this.persist()?;
        Ok(this)
    }

    /// Reopen a pending identity. A blob holding an Active session is `Codec` here (and vice
    /// versa), so a caller that does not know which it has tries both.
    pub fn open(journal: J) -> Result<Self, DurableError> {
        let bytes = journal.load()?.ok_or(DurableError::NoSession)?;
        let blob: PendingBlob = serde_json::from_slice(&bytes).map_err(|_| DurableError::Codec)?;
        if blob.pending_format_version != PENDING_BLOB_FORMAT_VERSION {
            return Err(DurableError::Codec);
        }
        let member = Member::restore(&blob.identity, &blob.store, &blob.public_key)?;
        Ok(Self { member, journal })
    }

    pub fn identity(&self) -> &[u8] {
        self.member.identity()
    }

    /// A one-time prekey. The provider store now holds its private key, so the identity is
    /// re-committed before the package is handed out: a prekey that reaches the relay is always
    /// one this store can redeem after a relaunch.
    pub fn key_package(&mut self) -> Result<Vec<u8>, DurableError> {
        let kp = self.member.key_package_bytes()?;
        self.persist()?;
        Ok(kp)
    }

    /// Join with a Welcome addressed to one of this identity's prekeys. On success the Active
    /// session overwrites the pending blob.
    pub fn join(self, welcome: &[u8]) -> Result<DurableSession<J>, PendingJoinError<J>> {
        let Self { member, journal } = self;
        match member.join_from_welcome(welcome) {
            Ok(conversation) => DurableSession::adopt(member, conversation, journal)
                .map_err(PendingJoinError::Commit),
            Err(e) => Err(PendingJoinError::BadWelcome(
                Box::new(Self { member, journal }),
                e,
            )),
        }
    }

    fn persist(&mut self) -> Result<(), DurableError> {
        let blob = PendingBlob {
            pending_format_version: PENDING_BLOB_FORMAT_VERSION,
            identity: self.member.identity().to_vec(),
            public_key: self.member.public_key(),
            store: self.member.export_store()?,
        };
        let bytes = serde_json::to_vec(&blob).map_err(|_| DurableError::Codec)?;
        self.journal.commit(&bytes)
    }
}

/// A conversation with crash-safe local persistence.
/// Default hot-window size (R-105): messages beyond this spill to the append-only archive. Large
/// enough that ordinary scrollback never touches the archive; small enough that the per-commit
/// blob rewrite stays O(window), not O(history).
pub const MAX_HOT_MESSAGES: usize = 512;

pub struct DurableSession<J: Journal> {
    session: Session,
    meta: Meta,
    journal: J,
    /// Spill threshold; [`MAX_HOT_MESSAGES`] in production, small in tests that exercise the
    /// archive without generating hundreds of messages.
    hot_limit: usize,
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
            hot_limit: MAX_HOT_MESSAGES,
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
            hot_limit: MAX_HOT_MESSAGES,
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
            hot_limit: MAX_HOT_MESSAGES,
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
        self.enqueue_reply(body, None)
    }

    /// As [`Self::enqueue`], optionally answering another message. A reply carries only the id it
    /// answers — never a copy of the original's text, which a hostile client could otherwise use to
    /// display words the quoted person never wrote.
    pub fn enqueue_reply(
        &mut self,
        body: &[u8],
        reply_to: Option<[u8; MESSAGE_ID_LEN]>,
    ) -> Result<u64, DurableError> {
        self.enqueue_content(
            Content::Normal {
                message_id: new_message_id(),
                reply_to,
                body: body.to_vec(),
            },
            None,
        )
    }

    /// React to a message (or, with `remove`, take the reaction back). The local view updates when
    /// the reaction is encrypted, so what this device shows matches what the group was told.
    pub fn enqueue_reaction(
        &mut self,
        target: [u8; MESSAGE_ID_LEN],
        emoji: &str,
        remove: bool,
    ) -> Result<u64, DurableError> {
        let content = Content::Reaction {
            target,
            emoji: emoji.to_string(),
            remove,
        };
        // Refuse locally what every recipient's decoder would refuse anyway.
        Content::decode(&content.encode()).map_err(map_content)?;
        self.enqueue_content(content, None)
    }

    /// Acknowledge messages: `Delivered` when they decrypted here, `Read` when a person saw them.
    /// Batched — a device returning from offline acknowledges a backlog in one message.
    pub fn enqueue_receipt(
        &mut self,
        kind: ReceiptKind,
        message_ids: Vec<[u8; MESSAGE_ID_LEN]>,
    ) -> Result<u64, DurableError> {
        let content = Content::Receipt { kind, message_ids };
        Content::decode(&content.encode()).map_err(map_content)?;
        self.enqueue_content(content, None)
    }

    /// A typing indicator. Ephemeral by design: nothing about it is logged on either side, and a
    /// dropped one costs nothing, so the client is free to throttle hard.
    pub fn enqueue_typing(&mut self, active: bool) -> Result<u64, DurableError> {
        self.enqueue_content(Content::Typing { active }, None)
    }

    /// The disappearing-message timer currently in force (seconds; 0 = off).
    pub fn disappear_after_secs(&self) -> u32 {
        self.meta.disappear_after_secs
    }

    /// Change the conversation's disappearing-message timer (0 = off). Like a rename, the local
    /// timer applies when the change is ENCRYPTED — the moment the group is actually told.
    pub fn enqueue_timer_change(&mut self, seconds: u32) -> Result<u64, DurableError> {
        let content = Content::TimerChange { seconds };
        // Refuse locally what every recipient's decoder would refuse (an over-cap timer).
        Content::decode(&content.encode()).map_err(map_content)?;
        self.enqueue_content(content, None)
    }

    /// Retract one of OUR OWN messages everywhere (delete-for-everyone). Refused for a message
    /// this device did not send, or one with no wire id — recipients would refuse it anyway
    /// (only the author's delete is honored) and the UI must not pretend otherwise. The local
    /// tombstone lands at encrypt time, when the group is actually told. R-901: best-effort.
    pub fn enqueue_delete(&mut self, target: [u8; MESSAGE_ID_LEN]) -> Result<u64, DurableError> {
        let ours = self.meta.messages.iter().any(|m| {
            m.message_id == target
                && m.direction == Direction::Outbound
                && m.message_id != [0u8; MESSAGE_ID_LEN]
        });
        if !ours {
            return Err(DurableError::UnknownLocal);
        }
        self.enqueue_content(Content::Delete { target }, None)
    }

    /// Replace the text of one of OUR OWN messages (edit). Refused for someone else's message, a
    /// non-text message (attachments and secrets don't edit), a deleted one, or one with no wire
    /// id. Recipients would refuse all of those anyway; the local rule matches. The local text
    /// changes at encrypt, when the group is actually told — same rule as rename and delete.
    pub fn enqueue_edit(
        &mut self,
        target: [u8; MESSAGE_ID_LEN],
        body: &[u8],
    ) -> Result<u64, DurableError> {
        let editable = self.meta.messages.iter().any(|m| {
            m.message_id == target
                && m.direction == Direction::Outbound
                && m.message_id != [0u8; MESSAGE_ID_LEN]
                && !m.deleted
                && m.attachment.is_none()
                && m.secret_id.is_none()
        });
        if !editable {
            return Err(DurableError::UnknownLocal);
        }
        let content = Content::Edit {
            target,
            body: body.to_vec(),
        };
        Content::decode(&content.encode()).map_err(map_content)?;
        self.enqueue_content(content, None)
    }

    /// Scrub every message past its expiry (disappearing messages): the row is removed outright,
    /// with its reactions and receipt bookkeeping. Returns how many were removed; commits only
    /// when something changed. Wall clock, deliberately — see `Message::expires_at_ms`.
    pub fn scrub_expired(&mut self) -> Result<u64, DurableError> {
        let now = now_ms();
        let expired: Vec<[u8; MESSAGE_ID_LEN]> = self
            .meta
            .messages
            .iter()
            .filter(|m| m.expires_at_ms.is_some_and(|at| at <= now))
            .map(|m| m.message_id)
            .collect();
        if expired.is_empty() {
            return Ok(0);
        }
        let mut meta = self.meta.clone();
        let before = meta.messages.len();
        meta.messages
            .retain(|m| !m.expires_at_ms.is_some_and(|at| at <= now));
        for id in &expired {
            meta.reactions.remove(&hex16(id));
            meta.receipts.remove(&hex16(id));
        }
        let removed = (before - meta.messages.len()) as u64;
        self.commit(meta)?;
        Ok(removed)
    }

    /// Reactions on a message, as currently known.
    pub fn reactions(&self, message_id: &[u8; MESSAGE_ID_LEN]) -> &[Reaction] {
        self.meta
            .reactions
            .get(&hex16(message_id))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Message ids received here that have not been acknowledged to their senders yet, oldest
    /// first — what a `Delivered` receipt should name. Excludes our own messages and anything with
    /// no id (logged before ids existed).
    pub fn unacknowledged_inbound(&self, kind: ReceiptKind) -> Vec<[u8; MESSAGE_ID_LEN]> {
        let sent = match kind {
            ReceiptKind::Delivered => &self.meta.sent_delivery_receipts,
            ReceiptKind::Read => &self.meta.sent_read_receipts,
        };
        self.meta
            .messages
            .iter()
            .filter(|m| m.direction == Direction::Inbound && m.message_id != [0u8; MESSAGE_ID_LEN])
            .filter(|m| match kind {
                // A read receipt is only owed for something the user has actually seen.
                ReceiptKind::Read => self
                    .meta
                    .last_read_local_id
                    .is_some_and(|mark| m.local_id <= mark),
                ReceiptKind::Delivered => true,
            })
            .map(|m| m.message_id)
            .filter(|id| !sent.contains(&hex16(id)))
            .take(crate::content::MAX_RECEIPT_IDS)
            .collect()
    }

    /// Remember that receipts of `kind` were sent for these ids, so they are not sent again on
    /// every sync — which would turn one delivered message into an unbounded stream of receipts.
    pub fn record_receipts_sent(
        &mut self,
        kind: ReceiptKind,
        ids: &[[u8; MESSAGE_ID_LEN]],
    ) -> Result<(), DurableError> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut meta = self.meta.clone();
        let set = match kind {
            ReceiptKind::Delivered => &mut meta.sent_delivery_receipts,
            ReceiptKind::Read => &mut meta.sent_read_receipts,
        };
        for id in ids {
            set.insert(hex16(id));
        }
        self.commit(meta)
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
                message_id: new_message_id(),
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
                created_at_ms: now_ms(),
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
                created_at_ms: now_ms(),
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
        // The user wrote it when they queued it, not when it happened to encrypt.
        let created_at_ms = meta
            .outbox
            .get(&local_id)
            .map(|o| o.created_at_ms)
            .unwrap_or_else(now_ms);
        let display = match &content {
            Content::Normal {
                message_id,
                reply_to,
                body,
            } => Some(Message {
                local_id: local_id_for_msg,
                direction: Direction::Outbound,
                plaintext: body.clone(),
                envelope_id: None,
                secret_id: None,
                created_at_ms,
                outbox_local_id: Some(local_id),
                attachment: None,
                message_id: *message_id,
                reply_to: *reply_to,
                sender: self.session.member.identity().to_vec(),
                expires_at_ms: expiry_for(meta.disappear_after_secs, created_at_ms),
                deleted: false,
                edited: false,
            }),
            Content::Secret {
                message_id,
                secret_id,
                ..
            } => {
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
                    created_at_ms,
                    outbox_local_id: Some(local_id),
                    attachment: None,
                    message_id: *message_id,
                    reply_to: None,
                    sender: self.session.member.identity().to_vec(),
                    // A view-once secret has its own (stricter) lifecycle; no disappearing stamp.
                    expires_at_ms: None,
                    deleted: false,
                    edited: false,
                })
            }
            // A file the user sent: the caption is the display text, and the reference is kept so
            // this device can reopen the file later without asking anyone.
            Content::Attachment {
                message_id,
                blob_id,
                key,
                digest,
                size,
                mime,
                filename,
                caption,
            } => Some(Message {
                local_id: local_id_for_msg,
                direction: Direction::Outbound,
                plaintext: caption.clone().into_bytes(),
                envelope_id: None,
                secret_id: None,
                created_at_ms,
                outbox_local_id: Some(local_id),
                message_id: *message_id,
                reply_to: None,
                sender: self.session.member.identity().to_vec(),
                expires_at_ms: expiry_for(meta.disappear_after_secs, created_at_ms),
                deleted: false,
                edited: false,
                attachment: Some(AttachmentRef {
                    blob_id: *blob_id,
                    key: *key,
                    digest: *digest,
                    size: *size,
                    mime: mime.clone(),
                    filename: filename.clone(),
                }),
            }),
            // The sender's own reaction shows when the group is told, not before — the same rule
            // the rename follows, so the local view never runs ahead of what was sent.
            Content::Reaction {
                target,
                emoji,
                remove,
            } => {
                // The IDENTITY, not the public key: this must be the same value recipients derive
                // from the MLS credential, or a device would not recognise its own reaction — and
                // the toggle would add a second one instead of taking the first back.
                let me = self.session.member.identity().to_vec();
                apply_reaction(&mut meta, target, emoji, *remove, &me);
                None
            }
            // Receipts and typing are about other people's messages, or about nothing at all.
            Content::Receipt { .. } | Content::Typing { .. } => None,
            // The sender applies its own rename locally, at the moment the group actually learns
            // it — encrypt is the point of no return, so the local name can never run ahead of
            // what the other members were told.
            Content::GroupName { name } => {
                meta.group_name = Some(name.clone());
                None
            }
            // Same rule for the disappearing timer: applied when the group is actually told.
            Content::TimerChange { seconds } => {
                meta.disappear_after_secs = *seconds;
                None
            }
            // And for a retraction: the sender's own copy tombstones when the delete is sealed
            // into the group — never before, so the local view can't run ahead of the send.
            Content::Delete { target } => {
                if let Some(message) = meta
                    .messages
                    .iter_mut()
                    .find(|m| m.message_id == *target && m.direction == Direction::Outbound)
                {
                    tombstone_message(message);
                    meta.reactions.remove(&hex16(target));
                }
                None
            }
            // The photo, like the name, applies when the group is actually told.
            Content::GroupAvatar { image } => {
                meta.group_avatar = if image.is_empty() {
                    None
                } else {
                    Some(image.clone())
                };
                None
            }
            // An edit lands locally when the group is told, marked visibly.
            Content::Edit { target, body } => {
                if let Some(message) = meta
                    .messages
                    .iter_mut()
                    .find(|m| m.message_id == *target && m.direction == Direction::Outbound)
                {
                    message.plaintext = body.clone();
                    message.edited = true;
                }
                None
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
                created_at_ms: now_ms(),
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

    /// The HOT window: the most recent messages (up to the spill threshold), in order. Older
    /// history lives in the archive — page it with [`Self::message_views_page`]. Everything the
    /// UI renders live comes from here.
    pub fn messages(&self) -> &[Message] {
        &self.meta.messages
    }

    /// The group's name as last set by any member, or `None` if it has never been named.
    pub fn group_name(&self) -> Option<&str> {
        self.meta.group_name.as_deref()
    }

    /// The group's photo thumbnail, or `None`.
    pub fn group_avatar(&self) -> Option<&[u8]> {
        self.meta.group_avatar.as_deref()
    }

    /// Queue a group-photo change (empty = remove); applies at encrypt, like a rename.
    pub fn enqueue_group_avatar(&mut self, image: &[u8]) -> Result<u64, DurableError> {
        let content = Content::GroupAvatar {
            image: image.to_vec(),
        };
        Content::decode(&content.encode()).map_err(map_content)?;
        self.enqueue_content(content, None)
    }

    /// Queue a rename for the whole group. Like any message it becomes real when it is encrypted
    /// and sent, so the local name changes then — never before the members are told.
    pub fn enqueue_group_name(&mut self, name: &str) -> Result<u64, DurableError> {
        let content = Content::GroupName {
            name: name.to_string(),
        };
        // Refuse locally what a recipient's decoder would refuse anyway (over-long, empty, or
        // unsafe to render), so a bad name fails at the source instead of being silently dropped
        // by every peer.
        Content::decode(&content.encode()).map_err(map_content)?;
        self.enqueue_content(content, None)
    }

    /// Queue a file that has ALREADY been encrypted and uploaded: `blob_id` is what the relay
    /// returned, and the key/digest come from [`crate::attachment::seal`]. The reference travels to
    /// the group inside the MLS ciphertext, so the relay — which holds the bytes — never holds the
    /// key that opens them.
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_attachment(
        &mut self,
        blob_id: [u8; 16],
        key: [u8; 32],
        digest: [u8; 32],
        size: u64,
        mime: &str,
        filename: &str,
        caption: &str,
    ) -> Result<u64, DurableError> {
        let content = Content::Attachment {
            message_id: new_message_id(),
            blob_id,
            key,
            digest,
            size,
            mime: mime.to_string(),
            filename: filename.to_string(),
            caption: caption.to_string(),
        };
        // Refuse here what a recipient's decoder would refuse anyway, so a bad reference fails at
        // the source rather than being silently dropped by every peer.
        Content::decode(&content.encode()).map_err(map_content)?;
        self.enqueue_content(content, None)
    }

    /// Mark everything currently in the log as read.
    pub fn mark_read(&mut self) -> Result<(), DurableError> {
        let Some(highest) = self.meta.messages.last().map(|m| m.local_id) else {
            return Ok(()); // nothing to read
        };
        if self.meta.last_read_local_id >= Some(highest) {
            return Ok(()); // already current: no write, so opening a quiet thread is free
        }
        let mut meta = self.meta.clone();
        meta.last_read_local_id = Some(highest);
        self.commit(meta)
    }

    /// Inbound messages newer than the last read mark. Outbound is never unread — you wrote it.
    pub fn unread_count(&self) -> u64 {
        self.meta
            .messages
            .iter()
            .filter(|m| {
                m.direction == Direction::Inbound
                    && self
                        .meta
                        .last_read_local_id
                        .is_none_or(|mark| m.local_id > mark)
            })
            .count() as u64
    }

    /// The message log with delivery state resolved, for rendering. An outbound message is
    /// `pending` until the relay has accepted it, which is what lets the UI show "sending" rather
    /// than pretending an undelivered message is on its way.
    pub fn message_views(&self) -> Vec<MessageView> {
        self.meta.messages.iter().map(|m| self.view(m)).collect()
    }

    fn view(&self, m: &Message) -> MessageView {
        // Receipts exist only for our own messages: nobody sends us acknowledgements of theirs.
        let receipt = (m.direction == Direction::Outbound)
            .then(|| self.meta.receipts.get(&hex16(&m.message_id)))
            .flatten();
        let pending = m.direction == Direction::Outbound
            && m.outbox_local_id
                .and_then(|id| self.meta.outbox.get(&id))
                .map(|o| o.status != OutboundStatus::Sent)
                // No outbox entry (replicated history, or an older blob) ⇒ nothing is in flight.
                .unwrap_or(false);
        MessageView {
            local_id: m.local_id,
            direction: m.direction,
            plaintext: m.plaintext.clone(),
            envelope_id: m.envelope_id,
            secret_id: m.secret_id,
            created_at_ms: m.created_at_ms,
            pending,
            attachment: m.attachment.clone(),
            message_id: m.message_id,
            reply_to: m.reply_to,
            reactions: self.reactions(&m.message_id).to_vec(),
            delivered_count: receipt.map(|r| r.delivered_by.len() as u32).unwrap_or(0),
            read_count: receipt.map(|r| r.read_by.len() as u32).unwrap_or(0),
            expires_at_ms: m.expires_at_ms,
            deleted: m.deleted,
            edited: m.edited,
            sender: m.sender.clone(),
        }
    }

    /// Outbound messages the server has NOT yet accepted (`Queued` or `Encrypted`), oldest first.
    /// This is what a relaunch replays: `encrypt` returns the cached ciphertext for an `Encrypted`
    /// entry (no second ratchet advance), the upload is retried, and `mark_sent` closes it.
    pub fn unsent_outbound(&self) -> Vec<u64> {
        self.meta
            .outbox
            .iter()
            .filter(|(_, o)| o.status != OutboundStatus::Sent)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Drop the user-visible message log ONLY. Every protocol input a future message depends on is
    /// deliberately retained: the MLS store/ratchet, `dedup_watermark` + `seen_inbound` (replay
    /// protection), `ack_eligible`, the pending `outbox`, and `secrets`. Keeping `secrets` is
    /// load-bearing — dropping it would let a replayed secret id earn a second viewing.
    pub fn clear_visible_history(&mut self) -> Result<(), DurableError> {
        let mut meta = self.meta.clone();
        meta.messages.clear();
        meta.archived_below_local_id = 0;
        meta.archived_count = 0;
        self.commit(meta)?;
        // AFTER the counters land: a crash in between leaves stale records whose ids sit above
        // the reset watermark — invisible, and harmlessly re-collapsed if ids recur.
        self.journal.archive_clear()
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
    fn commit(&mut self, mut meta: Meta) -> Result<(), DurableError> {
        self.spill_history(&mut meta)?;
        commit_blob(&mut self.journal, &self.session, &meta)?;
        self.meta = meta;
        Ok(())
    }

    /// R-105: move the oldest hot messages into the append-only archive when the window
    /// overflows, WRITE-AHEAD — archive records land (durably) before the blob commit that drops
    /// them, so a crash between the two duplicates a record (collapsed on read via the
    /// watermark + last-write-wins) and can never lose one.
    ///
    /// Only a CONTIGUOUS oldest prefix spills, so `archived_below_local_id` stays a true
    /// watermark. A message still owed work stays hot and blocks the prefix behind it:
    /// a disappearing message (the expiry scrub owns its deletion — the archive is immutable)
    /// or an outbound not yet accepted by the relay (retry state must remain visible).
    fn spill_history(&mut self, meta: &mut Meta) -> Result<(), DurableError> {
        let mut spill = 0usize;
        while meta.messages.len() - spill > self.hot_limit {
            let m = &meta.messages[spill];
            let sent = m
                .outbox_local_id
                .map(|id| {
                    meta.outbox
                        .get(&id)
                        .map(|o| o.status == OutboundStatus::Sent)
                        .unwrap_or(true)
                })
                .unwrap_or(true);
            if m.expires_at_ms.is_some() || !sent {
                break;
            }
            spill += 1;
        }
        if spill == 0 {
            return Ok(());
        }
        for m in &meta.messages[..spill] {
            let record = serde_json::to_vec(m).map_err(|_| DurableError::Codec)?;
            self.journal.archive_append(&record)?;
        }
        let last_id = meta.messages[spill - 1].local_id;
        for m in meta.messages.drain(..spill) {
            // A spilled outbound's delivery is settled; its cached ciphertext (the other
            // whole-blob growth vector) goes with it.
            if let Some(oid) = m.outbox_local_id {
                meta.outbox.remove(&oid);
            }
        }
        meta.archived_below_local_id = last_id + 1;
        meta.archived_count += spill as u64;
        Ok(())
    }

    /// Archived history, oldest first, decoded and deduplicated (see [`Journal::archive_load`]).
    /// Loads the whole archive: callers page rarely (scrollback past the hot window, search) and
    /// the hot path never comes here.
    fn archived_messages(&self) -> Result<Vec<Message>, DurableError> {
        let records = self.journal.archive_load()?;
        let mut by_id: std::collections::BTreeMap<u64, Message> = std::collections::BTreeMap::new();
        for record in records {
            let m: Message = serde_json::from_slice(&record).map_err(|_| DurableError::Codec)?;
            // Records at/above the watermark are crash leftovers whose message is still hot.
            if m.local_id < self.meta.archived_below_local_id {
                by_id.insert(m.local_id, m);
            }
        }
        Ok(by_id.into_values().collect())
    }

    /// Total history: archive + hot window.
    pub fn total_message_count(&self) -> u64 {
        self.meta.archived_count + self.meta.messages.len() as u64
    }

    /// One page of the FULL history (archive + hot), oldest first. Offsets inside the hot window
    /// never touch the archive — the common path (rendering recent messages) stays cheap.
    pub fn message_views_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<MessageView>, DurableError> {
        let archived = self.meta.archived_count as usize;
        if offset >= archived {
            let hot = &self.meta.messages;
            let start = (offset - archived).min(hot.len());
            let end = start.saturating_add(limit).min(hot.len());
            return Ok(hot[start..end].iter().map(|m| self.view(m)).collect());
        }
        let mut out: Vec<MessageView> = self
            .archived_messages()?
            .iter()
            .skip(offset)
            .take(limit)
            .map(|m| self.view(m))
            .collect();
        if out.len() < limit {
            let want = limit - out.len();
            out.extend(self.meta.messages.iter().take(want).map(|m| self.view(m)));
        }
        Ok(out)
    }

    /// Test hook: exercise the spill without generating [`MAX_HOT_MESSAGES`] messages.
    #[doc(hidden)]
    pub fn set_hot_limit(&mut self, limit: usize) {
        self.hot_limit = limit.max(1);
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
        // `sender` is the MLS-authenticated credential identity — the only trustworthy answer to
        // "who did this", and what makes a reaction or a receipt attributable rather than claimed.
        Incoming::Application { sender, payload } => {
            match Content::decode(&payload).map_err(map_content)? {
                Content::Normal {
                    message_id,
                    reply_to,
                    body,
                } => {
                    let local_id = meta.take_local_id();
                    let created_at_ms = now_ms();
                    meta.messages.push(Message {
                        local_id,
                        direction: Direction::Inbound,
                        plaintext: body.clone(),
                        envelope_id: Some(envelope_id),
                        secret_id: None,
                        created_at_ms,
                        outbox_local_id: None,
                        attachment: None,
                        message_id,
                        reply_to,
                        sender,
                        expires_at_ms: expiry_for(meta.disappear_after_secs, created_at_ms),
                        deleted: false,
                        edited: false,
                    });
                    InboundOutcome::Application(body)
                }
                // The conversation's disappearing-message timer. Applied to messages logged from
                // now on; history keeps the expiry it was stamped with (R-901: local, best-effort).
                Content::TimerChange { seconds } => {
                    meta.disappear_after_secs = seconds;
                    InboundOutcome::TimerChanged { seconds }
                }
                // Delete-for-everyone. Honored ONLY when the deleter authored the message —
                // otherwise any member could erase anyone's words. A target this device does not
                // hold (or was logged before senders were recorded) is a durable no-op.
                Content::Delete { target } => {
                    let authored = meta.messages.iter_mut().find(|m| {
                        m.message_id == target
                            && m.direction == Direction::Inbound
                            && !m.sender.is_empty()
                            && m.sender == sender
                    });
                    match authored {
                        Some(message) => {
                            tombstone_message(message);
                            meta.reactions.remove(&hex16(&target));
                            InboundOutcome::MessageDeleted { target }
                        }
                        None => InboundOutcome::Duplicate,
                    }
                }
                // Edits share Delete's authorship rule; a deleted message stays deleted (an edit
                // must not resurrect retracted words), and the change is always VISIBLY marked.
                Content::Edit { target, body } => {
                    let authored = meta.messages.iter_mut().find(|m| {
                        m.message_id == target
                            && m.direction == Direction::Inbound
                            && !m.sender.is_empty()
                            && m.sender == sender
                            && !m.deleted
                            && m.attachment.is_none()
                            && m.secret_id.is_none()
                    });
                    match authored {
                        Some(message) => {
                            message.plaintext = body;
                            message.edited = true;
                            InboundOutcome::MessageEdited { target }
                        }
                        None => InboundOutcome::Duplicate,
                    }
                }
                // A reaction to a message this device does not have is DROPPED, not stored for later:
                // keeping it would let any member grow this blob without bound by reacting to ids they
                // invent. The cost is a reaction that arrives before its message is lost, which is
                // rare and self-correcting on the next one.
                Content::Reaction {
                    target,
                    emoji,
                    remove,
                } => {
                    let known = meta.messages.iter().any(|m| m.message_id == target);
                    if known {
                        apply_reaction(meta, &target, &emoji, remove, &sender);
                        InboundOutcome::ReactionChanged { target }
                    } else {
                        InboundOutcome::Duplicate
                    }
                }
                // Receipts are only accepted for messages WE sent; anything else is discarded for the
                // same bounding reason, and would be meaningless anyway.
                Content::Receipt { kind, message_ids } => {
                    let mut applied = 0u64;
                    for id in message_ids {
                        let ours = meta
                            .messages
                            .iter()
                            .any(|m| m.direction == Direction::Outbound && m.message_id == id);
                        if !ours {
                            continue;
                        }
                        let record = meta.receipts.entry(hex16(&id)).or_default();
                        let set = match kind {
                            ReceiptKind::Delivered => &mut record.delivered_by,
                            ReceiptKind::Read => &mut record.read_by,
                        };
                        set.insert(sender.clone());
                        applied += 1;
                    }
                    InboundOutcome::ReceiptsReceived {
                        kind,
                        count: applied,
                    }
                }
                // Never logged and never persisted beyond the dedup bookkeeping every envelope gets:
                // a typing indicator is a hint, and a stale one is worse than none.
                Content::Typing { active } => InboundOutcome::Typing { sender, active },
                Content::Secret {
                    message_id,
                    secret_id,
                    body,
                } => {
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
                            created_at_ms: now_ms(),
                            outbox_local_id: None,
                            attachment: None,
                            message_id,
                            reply_to: None,
                            sender,
                            // A view-once secret has its own (stricter) lifecycle; no expiry stamp.
                            expires_at_ms: None,
                            deleted: false,
                            edited: false,
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
                // A file: logged now, fetched from the relay when the user opens it (or eagerly by the
                // client). The reference — including its key — is durable, so a relaunch can still open
                // it.
                Content::Attachment {
                    message_id,
                    blob_id,
                    key,
                    digest,
                    size,
                    mime,
                    filename,
                    caption,
                } => {
                    let local_id = meta.take_local_id();
                    let attachment = AttachmentRef {
                        blob_id,
                        key,
                        digest,
                        size,
                        mime,
                        filename,
                    };
                    let created_at_ms = now_ms();
                    meta.messages.push(Message {
                        local_id,
                        direction: Direction::Inbound,
                        plaintext: caption.into_bytes(),
                        envelope_id: Some(envelope_id),
                        secret_id: None,
                        created_at_ms,
                        outbox_local_id: None,
                        attachment: Some(attachment.clone()),
                        message_id,
                        reply_to: None,
                        sender,
                        expires_at_ms: expiry_for(meta.disappear_after_secs, created_at_ms),
                        deleted: false,
                        edited: false,
                    });
                    InboundOutcome::AttachmentReceived { attachment }
                }
                // A member renamed the group. Persisted with the rest of this commit, so the name and
                // the ratchet advance land together or not at all.
                Content::GroupName { name } => {
                    meta.group_name = Some(name.clone());
                    InboundOutcome::GroupRenamed { name }
                }
                Content::GroupAvatar { image } => {
                    let removed = image.is_empty();
                    meta.group_avatar = if removed { None } else { Some(image) };
                    InboundOutcome::GroupAvatarChanged { removed }
                }
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
                            // Stamped on arrival: the sync carries no times, and inventing one would
                            // be a claim this device cannot support.
                            created_at_ms: now_ms(),
                            outbox_local_id: None,
                            attachment: None,
                            // Replicated history carries no ids, so these messages cannot be replied
                            // to or reacted to on the new device. Minting ids here would invent
                            // handles no other member knows.
                            message_id: [0u8; MESSAGE_ID_LEN],
                            reply_to: None,
                            // The sync says which SIDE sent each entry, not which member device —
                            // and no sender means no remote delete can ever target it (fail closed).
                            sender: Vec::new(),
                            expires_at_ms: None,
                            deleted: false,
                            edited: false,
                        });
                    }
                    InboundOutcome::HistorySynced { count }
                }
            }
        }
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
    archive: Vec<Vec<u8>>,
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

    fn archive_append(&mut self, record: &[u8]) -> Result<(), DurableError> {
        let mut g = self.inner.lock().map_err(|_| DurableError::Journal)?;
        g.archive.push(record.to_vec());
        Ok(())
    }

    fn archive_load(&self) -> Result<Vec<Vec<u8>>, DurableError> {
        let g = self.inner.lock().map_err(|_| DurableError::Journal)?;
        Ok(g.archive.clone())
    }

    fn archive_clear(&mut self) -> Result<(), DurableError> {
        let mut g = self.inner.lock().map_err(|_| DurableError::Journal)?;
        g.archive.clear();
        Ok(())
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

impl FileJournal {
    fn archive_path(&self) -> PathBuf {
        let mut p = self.path.clone();
        let mut name = p.file_name().map(|n| n.to_os_string()).unwrap_or_default();
        name.push(".archive");
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

    /// R-105 archive: an append-only sibling file (`<blob>.archive`) of records, each
    /// `u32-BE(len) || nonce(12) || AES-256-GCM ciphertext` under the SAME at-rest key. Appended
    /// with fsync before the blob commit that relies on it (write-ahead).
    fn archive_append(&mut self, record: &[u8]) -> Result<(), DurableError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(&nonce_bytes.into(), record)
            .map_err(|_| DurableError::Journal)?;
        let mut out = Vec::with_capacity(4 + 12 + ciphertext.len());
        out.extend_from_slice(&((12 + ciphertext.len()) as u32).to_be_bytes());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.archive_path())
            .map_err(|_| DurableError::Journal)?;
        f.write_all(&out).map_err(|_| DurableError::Journal)?;
        f.sync_all().map_err(|_| DurableError::Journal)?;
        Ok(())
    }

    fn archive_load(&self) -> Result<Vec<Vec<u8>>, DurableError> {
        let data = match std::fs::read(self.archive_path()) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(DurableError::Journal),
        };
        let mut out = Vec::new();
        let mut at = 0usize;
        while at + 4 <= data.len() {
            let len = u32::from_be_bytes(data[at..at + 4].try_into().unwrap()) as usize;
            let end = at + 4 + len;
            if len < 12 || end > data.len() {
                break; // a torn tail from a crash mid-append: everything before it is intact
            }
            let nonce: [u8; 12] = data[at + 4..at + 16].try_into().unwrap();
            let plaintext = self
                .cipher
                .decrypt(&nonce.into(), &data[at + 16..end])
                .map_err(|_| DurableError::Journal)?; // tamper of a COMPLETE record fails closed
            out.push(plaintext);
            at = end;
        }
        Ok(out)
    }

    fn archive_clear(&mut self) -> Result<(), DurableError> {
        match std::fs::remove_file(self.archive_path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(DurableError::Journal),
        }
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

    fn archive_append(&mut self, record: &[u8]) -> Result<(), DurableError> {
        match self {
            JournalKind::File(j) => j.archive_append(record),
            JournalKind::Memory(j) => j.archive_append(record),
        }
    }

    fn archive_load(&self) -> Result<Vec<Vec<u8>>, DurableError> {
        match self {
            JournalKind::File(j) => j.archive_load(),
            JournalKind::Memory(j) => j.archive_load(),
        }
    }

    fn archive_clear(&mut self) -> Result<(), DurableError> {
        match self {
            JournalKind::File(j) => j.archive_clear(),
            JournalKind::Memory(j) => j.archive_clear(),
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

#[cfg(test)]
mod forged_delete_tests {
    use super::*;
    use crate::Incoming;

    /// The authorship check, exercised directly: a member who did NOT write a message sends a
    /// `Delete` naming it. A modified client can always emit such bytes — `enqueue_delete`'s
    /// refusal is UX, this check is the security property — so the recipient must ignore it.
    #[test]
    fn a_forged_delete_from_a_non_author_is_ignored() {
        let mut meta = Meta::default();
        let local_id = meta.take_local_id();
        let target = [7u8; MESSAGE_ID_LEN];
        meta.messages.push(Message {
            local_id,
            direction: Direction::Inbound,
            plaintext: b"alice wrote this".to_vec(),
            envelope_id: Some(1),
            secret_id: None,
            created_at_ms: 0,
            outbox_local_id: None,
            attachment: None,
            message_id: target,
            reply_to: None,
            sender: b"alice-device".to_vec(),
            expires_at_ms: None,
            deleted: false,
            edited: false,
        });

        let forged = Content::Delete { target }.encode();
        let outcome = apply_incoming(
            &mut meta,
            Incoming::Application {
                sender: b"mallory-device".to_vec(),
                payload: forged,
            },
            2,
        )
        .expect("apply");
        assert_eq!(outcome, InboundOutcome::Duplicate, "not honored");
        assert!(!meta.messages[0].deleted);
        assert_eq!(meta.messages[0].plaintext, b"alice wrote this");

        // And a message logged before senders were recorded (empty sender) can never be remotely
        // deleted, even by a sender who ALSO claims an empty identity.
        meta.messages[0].sender = Vec::new();
        let outcome = apply_incoming(
            &mut meta,
            Incoming::Application {
                sender: Vec::new(),
                payload: Content::Delete { target }.encode(),
            },
            3,
        )
        .expect("apply");
        assert_eq!(outcome, InboundOutcome::Duplicate, "fail closed");
        assert!(!meta.messages[0].deleted);
    }
}

#[cfg(test)]
mod forged_edit_tests {
    use super::*;
    use crate::Incoming;

    /// A hostile member's Edit naming someone else's message — or a deleted one — is ignored.
    #[test]
    fn forged_or_necromantic_edits_are_ignored() {
        let mut meta = Meta::default();
        let target = [8u8; MESSAGE_ID_LEN];
        let local_id = meta.take_local_id();
        meta.messages.push(Message {
            local_id,
            direction: Direction::Inbound,
            plaintext: b"original".to_vec(),
            envelope_id: Some(1),
            secret_id: None,
            created_at_ms: 0,
            outbox_local_id: None,
            attachment: None,
            message_id: target,
            reply_to: None,
            sender: b"alice-device".to_vec(),
            expires_at_ms: None,
            deleted: false,
            edited: false,
        });

        // Wrong sender: ignored.
        let outcome = apply_incoming(
            &mut meta,
            Incoming::Application {
                sender: b"mallory-device".to_vec(),
                payload: Content::Edit {
                    target,
                    body: b"forged".to_vec(),
                }
                .encode(),
            },
            2,
        )
        .expect("apply");
        assert_eq!(outcome, InboundOutcome::Duplicate);
        assert_eq!(meta.messages[0].plaintext, b"original");

        // Right sender, but the message was deleted: an edit must not resurrect it.
        meta.messages[0].deleted = true;
        meta.messages[0].plaintext.clear();
        let outcome = apply_incoming(
            &mut meta,
            Incoming::Application {
                sender: b"alice-device".to_vec(),
                payload: Content::Edit {
                    target,
                    body: b"back from the dead".to_vec(),
                }
                .encode(),
            },
            3,
        )
        .expect("apply");
        assert_eq!(outcome, InboundOutcome::Duplicate);
        assert!(meta.messages[0].plaintext.is_empty());
        assert!(meta.messages[0].deleted);
    }
}
