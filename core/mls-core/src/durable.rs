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

use crate::{Conversation, Incoming, Member};

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
}

impl From<crate::MlsError> for DurableError {
    fn from(_: crate::MlsError) -> Self {
        DurableError::Mls
    }
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
    plaintext: Vec<u8>,
    status: OutboundStatus,
    ciphertext: Option<Vec<u8>>,
}

/// What processing an inbound envelope yielded.
#[derive(Debug, PartialEq, Eq)]
pub enum InboundOutcome {
    Application(Vec<u8>),
    StateAdvanced,
    /// Already processed (at-least-once redelivery). A durable no-op.
    Duplicate,
}

/// Serializable metadata that travels in the committed blob alongside the MLS store snapshot.
#[derive(Serialize, Deserialize, Clone, Default)]
struct Meta {
    identity: Vec<u8>,
    public_key: Vec<u8>,
    group_id: Vec<u8>,
    /// Envelope ids already processed — dedup for at-least-once delivery.
    seen_inbound: BTreeSet<u64>,
    /// Envelope ids durably processed and therefore safe to acknowledge to the server.
    ack_eligible: BTreeSet<u64>,
    next_local_id: u64,
    messages: Vec<Message>,
    outbox: BTreeMap<u64, Outbound>,
}

impl Meta {
    fn take_local_id(&mut self) -> u64 {
        let id = self.next_local_id;
        self.next_local_id += 1;
        id
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
            public_key,
            group_id,
        }
    }

    fn restore(meta: &Meta, store: &[u8]) -> Result<Self, DurableError> {
        let member = Member::restore(&meta.identity, store, &meta.public_key)?;
        let conversation = Conversation::reload(&member, &meta.group_id)?;
        Ok(Self::wrap(member, conversation))
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
    pub fn open(journal: J) -> Result<Self, DurableError> {
        let bytes = journal.load()?.ok_or(DurableError::NoSession)?;
        let blob: Blob = serde_json::from_slice(&bytes).map_err(|_| DurableError::Codec)?;
        let session = Session::restore(&blob.meta, &blob.store)?;
        Ok(Self {
            session,
            meta: blob.meta,
            journal,
        })
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

    /// Process an inbound envelope. Idempotent per `envelope_id` (at-least-once redelivery is a
    /// no-op). On success the advanced MLS state, the decrypted message, dedup marker, and
    /// ack-eligibility are all durable **together** before this returns.
    pub fn process_inbound(
        &mut self,
        envelope_id: u64,
        ciphertext: &[u8],
    ) -> Result<InboundOutcome, DurableError> {
        if self.meta.seen_inbound.contains(&envelope_id) {
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
        let outcome = match incoming {
            Incoming::Application(plaintext) => {
                let local_id = meta.take_local_id();
                meta.messages.push(Message {
                    local_id,
                    direction: Direction::Inbound,
                    plaintext: plaintext.clone(),
                    envelope_id: Some(envelope_id),
                });
                InboundOutcome::Application(plaintext)
            }
            Incoming::StateAdvanced => InboundOutcome::StateAdvanced,
        };
        meta.seen_inbound.insert(envelope_id);
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

    /// Queue an outbound message (durable draft). Does NOT advance the ratchet. Returns a local id.
    pub fn enqueue(&mut self, plaintext: &[u8]) -> Result<u64, DurableError> {
        let mut meta = self.meta.clone();
        let local_id = meta.take_local_id();
        meta.outbox.insert(
            local_id,
            Outbound {
                local_id,
                plaintext: plaintext.to_vec(),
                status: OutboundStatus::Queued,
                ciphertext: None,
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
        let ciphertext = {
            let Session {
                member,
                conversation,
                ..
            } = &mut self.session;
            conversation.encrypt(member, &plaintext)?
        };
        let mut meta = self.meta.clone();
        let local_id_for_msg = meta.take_local_id();
        if let Some(entry) = meta.outbox.get_mut(&local_id) {
            entry.ciphertext = Some(ciphertext.clone());
            entry.status = OutboundStatus::Encrypted;
        }
        meta.messages.push(Message {
            local_id: local_id_for_msg,
            direction: Direction::Outbound,
            plaintext,
            envelope_id: None,
        });
        self.commit(meta)?;
        Ok(ciphertext)
    }

    /// Mark a message accepted by the server. Persisted before returning.
    pub fn mark_sent(&mut self, local_id: u64) -> Result<(), DurableError> {
        let mut meta = self.meta.clone();
        if let Some(entry) = meta.outbox.get_mut(&local_id) {
            entry.status = OutboundStatus::Sent;
        } else {
            return Err(DurableError::UnknownLocal);
        }
        self.commit(meta)
    }

    /// Ordered log of stored messages (inbound decrypted + outbound).
    pub fn messages(&self) -> &[Message] {
        &self.meta.messages
    }

    /// Current MLS epoch.
    pub fn epoch(&self) -> u64 {
        self.session.conversation.epoch()
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
}

impl Journal for InMemoryJournal {
    fn commit(&mut self, blob: &[u8]) -> Result<(), DurableError> {
        let mut g = self.inner.lock().map_err(|_| DurableError::Journal)?;
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
