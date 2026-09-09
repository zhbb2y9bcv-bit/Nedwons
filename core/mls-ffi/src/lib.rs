//! UniFFI boundary exposing `mls-core`'s client to Swift (ADR-0007). A thin marshalling shim: all
//! MLS/crypto logic stays in `mls-core` (`#![forbid(unsafe_code)]`); the unavoidable `unsafe
//! extern "C"` scaffolding is generated here, confined to this small, fuzzable boundary.
//!
//! ## Contract (frozen in ADR-0007 v2)
//! - **Object per client, not a handle registry.** Swift holds an ARC-managed `Arc<MlsClient>` — no
//!   shared `u64` registry, so no stale-handle/ABA/cross-client hazards. `close()` invalidates.
//! - **Single-writer per client.** One `Mutex<ClientState>`; a given MLS group lives in exactly one
//!   client, so concurrent mutation of one group is impossible.
//! - **One persistence authority.** Only `DurableSession` over a `Journal`; never a second store.
//! - **Bytes only cross.** No OpenMLS object, store blob, ratchet secret, or signing key ever
//!   crosses; there is deliberately no `export_store` on this surface.
//! - **Bounded, typed, redacted.** Inputs length-checked before parsing; variant-only error
//!   messages; every entry point `catch_unwind`-wrapped so no panic unwinds across the C ABI.

uniffi::setup_scaffolding!();

use std::panic::catch_unwind;
use std::sync::{Arc, Mutex};

use mls_core::attachment::{self, AttachmentRef as CoreAttachmentRef};
use mls_core::client::{
    MAX_ENVELOPE_LEN, MAX_IDENTITY_LEN, MAX_KEY_PACKAGE_LEN, MAX_PLAINTEXT_LEN, MAX_WELCOME_LEN,
};
use mls_core::content::ReceiptKind as CoreReceiptKind;
use mls_core::content::{HistoryEntry as CoreHistoryEntry, SECRET_ID_LEN};
use mls_core::durable::{
    Direction as CoreDirection, DurableError, DurableSession, FileJournal, InMemoryJournal,
    InboundOutcome, JournalKind, MessageView as CoreMessageView, PendingIdentity, PendingJoinError,
    BLOB_FORMAT_VERSION,
};
use mls_core::{MlsError, CIPHERSUITE_NAME, VERSION as CORE_VERSION};

/// Bounds per-call FFI marshalling.
pub const MAX_PAGE_MESSAGES: u32 = 256;

/// Messages are variant-only: no library internals, key bytes, plaintext, or paths ever appear
/// (asserted by a redaction test).
#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum MlsClientError {
    #[error("input too large")]
    InputTooLarge,
    #[error("at-rest key must be 32 bytes")]
    BadKeyLength,
    #[error("operation not valid in the client's current state")]
    WrongState,
    #[error("not found")]
    NotFound,
    #[error("invalid message")]
    InvalidMessage,
    #[error("no persisted session")]
    NoSession,
    #[error("storage error")]
    Journal,
    #[error("client is closed")]
    Closed,
    #[error("internal error")]
    Internal,
}

/// Commit fans out to existing members; welcome goes to the new one. Both opaque.
#[derive(uniffi::Record)]
pub struct AddOutcome {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

#[derive(uniffi::Enum)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// What the UI renders.
#[derive(uniffi::Record)]
pub struct StoredMessage {
    pub local_id: u64,
    pub direction: Direction,
    pub plaintext: Vec<u8>,
    pub envelope_id: Option<u64>,
    /// `Some` (16 bytes) for a secret; `plaintext` is then empty — render a placeholder/tombstone
    /// driven by [`MlsClient::secret_phase`], never the body.
    pub secret_id: Option<Vec<u8>>,
    /// Unix ms stamped by THIS device (queued, for outbound; decrypted, for inbound). Never carried
    /// on the wire, so a peer cannot forge when a message appeared here. 0 = unknown (logged before
    /// timestamps existed).
    pub created_at_ms: u64,
    /// Outbound only: the relay has not accepted it yet, so render it as sending rather than sent.
    pub pending: bool,
    /// `Some` when this message is a file; `plaintext` is then its caption.
    pub attachment: Option<AttachmentInfo>,
    /// The id every other device knows this message by — what a reply, reaction or receipt names.
    /// All-zero for messages logged before ids existed; those cannot be referred to.
    pub message_id: Vec<u8>,
    /// The message this one answers, if any.
    pub reply_to: Option<Vec<u8>>,
    pub reactions: Vec<ReactionInfo>,
    /// For our own messages: how many other members have received / read it.
    pub delivered_count: u32,
    pub read_count: u32,
    /// Wall-clock ms after which this device scrubs its copy (disappearing messages); `None` =
    /// keeps forever.
    pub expires_at_ms: Option<u64>,
    /// Retracted by its author (delete-for-everyone): render "message deleted", body is gone.
    pub deleted: bool,
    /// The author replaced the text after sending; render an "edited" tag.
    pub edited: bool,
    /// The MLS-authenticated sender identity (device id bytes; empty for pre-field history).
    pub sender: Vec<u8>,
}

/// Mirrors `mls_core::secret::SecretState`.
#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SecretPhase {
    /// Not tapped; no timer running.
    Sealed,
    Countdown,
    Visible,
    /// Terminal: plaintext gone, cannot reopen.
    Consumed,
    /// No secret with this id is known here.
    Unknown,
}

#[derive(uniffi::Record)]
pub struct SecretHandle {
    pub local_id: u64,
    pub secret_id: Vec<u8>,
}

/// Both 0 outside that phase.
#[derive(uniffi::Record)]
pub struct SecretRemaining {
    pub countdown_ms: u64,
    pub view_ms: u64,
}

/// One past message in a history-sync batch (#7). Secrets are never included.
#[derive(uniffi::Record)]
pub struct HistoryEntry {
    pub outbound: bool,
    pub body: Vec<u8>,
}

#[derive(Debug, uniffi::Enum)]
pub enum InboundResult {
    Application {
        plaintext: Vec<u8>,
    },
    /// A commit advanced group state; no user-visible content.
    StateAdvanced,
    /// At-least-once redelivery or a replayed secret id — a durable no-op.
    Duplicate,
    /// Stored sealed; the body is NOT delivered here. Show a placeholder and reveal later via
    /// [`MlsClient::begin_secret_reveal`].
    SecretSealed {
        secret_id: Vec<u8>,
    },
    /// ADR-0015: another device revealed `secret_id`; this copy is consumed. Refresh any
    /// placeholder to its tombstone.
    SecretConsumedRemotely {
        secret_id: Vec<u8>,
    },
    /// ADR-0014 Slice 2c: store `K_r` keyed by the sender for future sealed sends.
    DeliveryKeyGranted {
        key_r: Vec<u8>,
    },
    /// #7: `count` past messages were appended to this device's log.
    HistorySynced {
        count: u64,
    },
    /// A member renamed the group; the new name is already persisted. Refresh the title.
    GroupRenamed {
        name: String,
    },
    /// A file arrived: the reference is durable, the bytes are still on the relay.
    AttachmentReceived {
        attachment: AttachmentInfo,
    },
    /// Someone reacted to (or un-reacted from) a message this device holds. Re-read the thread.
    ReactionChanged {
        target: Vec<u8>,
    },
    /// Someone acknowledged `count` of OUR messages.
    ReceiptsReceived {
        kind: ReceiptKindFfi,
        count: u64,
    },
    /// Ephemeral: someone started or stopped typing. Nothing was persisted, and it is safe to
    /// ignore — the UI should time it out on its own rather than trusting a "stopped" to arrive.
    Typing {
        sender: Vec<u8>,
        active: bool,
    },
    /// A member changed the disappearing-message timer (0 = off). Already persisted; refresh.
    TimerChanged {
        seconds: u32,
    },
    /// The author retracted a message; the local copy is tombstoned. Redraw the bubble.
    MessageDeleted {
        target: Vec<u8>,
    },
    /// The author replaced a message's text; the copy is updated and marked edited. Redraw.
    MessageEdited {
        target: Vec<u8>,
    },
    /// A member set or cleared the group's photo. Already persisted; refresh the header.
    GroupAvatarChanged {
        removed: bool,
    },
    /// A cover-traffic decoy (R-204). Nothing happened — discard it. Surfaced only so the caller
    /// can see it was recognised (and still ack the envelope).
    Cover,
}

/// A file referenced by a message. The bytes live on the relay as ciphertext; this is everything
/// needed to fetch and open them, and it never leaves the E2EE channel.
#[derive(uniffi::Record, Clone, Debug)]
pub struct AttachmentInfo {
    pub blob_id: Vec<u8>,
    pub key: Vec<u8>,
    pub digest: Vec<u8>,
    /// Plaintext size in bytes.
    pub size: u64,
    pub mime: String,
    pub filename: String,
}

/// One person's reaction to one message.
#[derive(uniffi::Record, Clone, Debug)]
pub struct ReactionInfo {
    pub emoji: String,
    /// The MLS-authenticated credential identity of whoever reacted — not a name from the payload.
    pub sender: Vec<u8>,
}

/// Which way a receipt points.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptKindFfi {
    Delivered,
    Read,
}

/// An encrypted file ready to upload, plus the secrets to put in the message that references it.
#[derive(uniffi::Record)]
pub struct SealedAttachment {
    /// Upload these bytes; the relay learns nothing from them.
    pub ciphertext: Vec<u8>,
    pub key: Vec<u8>,
    pub digest: Vec<u8>,
}

/// Lets Swift assert it links a compatible core and refuse on mismatch (ADR-0007).
#[derive(uniffi::Record)]
pub struct Capabilities {
    pub binding_version: String,
    pub core_version: String,
    pub protocol: String,
    pub ciphersuite: String,
    pub storage_format_version: u32,
    pub max_identity: u64,
    pub max_key_package: u64,
    pub max_welcome: u64,
    pub max_envelope: u64,
    pub max_plaintext: u64,
}

/// `Pending` = identity but no group yet (a joiner awaiting a Welcome). `Active` = a durable
/// conversation. `Closed` = invalidated.
enum ClientState {
    // Boxed: both carry heap-heavy MLS payloads next to the zero-size `Closed`
    // (clippy::large_enum_variant).
    Pending {
        pending: Box<PendingIdentity<JournalKind>>,
    },
    Active {
        session: Box<DurableSession<JournalKind>>,
    },
    Closed,
}

/// One identity + one conversation, owned by Swift as an `Arc<MlsClient>`.
#[derive(uniffi::Object)]
pub struct MlsClient {
    inner: Mutex<ClientState>,
}

#[uniffi::export]
impl MlsClient {
    /// This client becomes the group creator/first member. Persists before returning.
    #[uniffi::constructor]
    pub fn create_group(
        identity: Vec<u8>,
        db_path: String,
        at_rest_key: Vec<u8>,
    ) -> Result<Arc<Self>, MlsClientError> {
        catch(move || {
            bound(identity.len(), MAX_IDENTITY_LEN)?;
            let journal = file_journal(&db_path, &at_rest_key)?;
            let session = DurableSession::create(&identity, journal).map_err(map_durable)?;
            Ok(Arc::new(Self {
                inner: Mutex::new(ClientState::Active {
                    session: Box::new(session),
                }),
            }))
        })
    }

    /// Create a fresh identity that will JOIN an existing group. Call `key_package()` to publish a
    /// prekey, then `join_group(welcome)` once added. The pending identity IS durable: `open` on
    /// the same path after a relaunch returns it still Pending, and every prekey it published
    /// stays redeemable.
    #[uniffi::constructor]
    pub fn new_joiner(
        identity: Vec<u8>,
        db_path: String,
        at_rest_key: Vec<u8>,
    ) -> Result<Arc<Self>, MlsClientError> {
        catch(move || {
            bound(identity.len(), MAX_IDENTITY_LEN)?;
            let journal = file_journal(&db_path, &at_rest_key)?;
            let pending = PendingIdentity::create(&identity, journal).map_err(map_durable)?;
            Ok(Arc::new(Self {
                inner: Mutex::new(ClientState::Pending {
                    pending: Box::new(pending),
                }),
            }))
        })
    }

    /// Reopen the last durably-committed state (relaunch / crash recovery): an Active session, or
    /// a still-Pending joiner whose published prekeys remain redeemable.
    #[uniffi::constructor]
    pub fn open(db_path: String, at_rest_key: Vec<u8>) -> Result<Arc<Self>, MlsClientError> {
        catch(move || {
            let journal = file_journal(&db_path, &at_rest_key)?;
            match DurableSession::open(journal) {
                Ok(session) => Ok(Arc::new(Self {
                    inner: Mutex::new(ClientState::Active {
                        session: Box::new(session),
                    }),
                })),
                // Not an Active blob: a Pending one decodes here. Any other failure is reported
                // as the ACTIVE loader saw it, so a corrupt session is never mislabelled.
                Err(DurableError::Codec) => {
                    let journal = file_journal(&db_path, &at_rest_key)?;
                    let pending = PendingIdentity::open(journal).map_err(map_durable)?;
                    Ok(Arc::new(Self {
                        inner: Mutex::new(ClientState::Pending {
                            pending: Box::new(pending),
                        }),
                    }))
                }
                Err(e) => Err(map_durable(e)),
            }
        })
    }

    /// Whether this client is still a joiner awaiting its Welcome (no conversation yet).
    pub fn is_pending(&self) -> Result<bool, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Pending { .. } => Ok(true),
                ClientState::Active { .. } => Ok(false),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// A one-time prekey to publish so others can add this client.
    pub fn key_package(&self) -> Result<Vec<u8>, MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            match &mut *g {
                ClientState::Pending { pending } => pending.key_package().map_err(map_durable),
                ClientState::Active { session } => session.key_package().map_err(map_durable),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// `Pending` → `Active`, persisted. On a bad Welcome the client stays `Pending` (retryable).
    pub fn join_group(&self, welcome: Vec<u8>) -> Result<(), MlsClientError> {
        catch(move || {
            bound(welcome.len(), MAX_WELCOME_LEN)?;
            let mut g = self.lock()?;
            match std::mem::replace(&mut *g, ClientState::Closed) {
                ClientState::Pending { pending } => match pending.join(&welcome) {
                    Ok(session) => {
                        *g = ClientState::Active {
                            session: Box::new(session),
                        };
                        Ok(())
                    }
                    // Restore so the caller can retry with a correct Welcome (or a different
                    // lobby identity can try this one).
                    Err(PendingJoinError::BadWelcome(pending, e)) => {
                        *g = ClientState::Pending { pending };
                        Err(map_mls_input(e))
                    }
                    // First commit failed: nothing durable to recover, client is dead → Closed.
                    Err(PendingJoinError::Commit(e)) => Err(map_durable(e)),
                },
                ClientState::Active { session } => {
                    *g = ClientState::Active { session };
                    Err(MlsClientError::WrongState)
                }
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// The grown group is durable before returning.
    ///
    /// `commit` is a versioned app envelope (like `add_self_device`'s), so the members already in
    /// the group apply it through `process_inbound` and advance to the new epoch. Before this
    /// wrap the raw commit was refused by that path, which made every group beyond two people
    /// undecryptable for its earlier members. `welcome` stays raw: `join_group` takes it directly.
    pub fn add_member(&self, key_package: Vec<u8>) -> Result<AddOutcome, MlsClientError> {
        catch(move || {
            bound(key_package.len(), MAX_KEY_PACKAGE_LEN)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            let (commit, welcome) = session
                .add_member(&key_package)
                .map_err(map_durable_input)?;
            Ok(AddOutcome {
                commit: mls_core::envelope::wrap(&commit),
                welcome,
            })
        })
    }

    // --- Device self-group (ADR-0015 option 3) ---------------------------------------------------
    //
    // A second MLS group of only this account's devices, syncing `SecretConsumed` so the
    // conversation's other party never learns of an open. Shares the provider store with the
    // conversation, so one atomic blob persists both. Mirrors the conversation handshake.

    pub fn has_self_group(&self) -> Result<bool, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Active { session } => Ok(session.has_self_group()),
                ClientState::Pending { .. } => Err(MlsClientError::WrongState),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// `WrongState` if one already exists.
    pub fn create_self_group(&self) -> Result<(), MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.create_self_group().map_err(map_durable)
        })
    }

    /// Returns a **wrapped** `commit` (for existing members via [`Self::process_self_inbound`],
    /// which unwraps) plus the **raw** `welcome` (for the new device via [`Self::join_self_group`],
    /// which does not).
    pub fn add_self_device(&self, key_package: Vec<u8>) -> Result<AddOutcome, MlsClientError> {
        catch(move || {
            bound(key_package.len(), MAX_KEY_PACKAGE_LEN)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            let (commit, welcome) = session
                .add_self_device(&key_package)
                .map_err(map_durable_input)?;
            Ok(AddOutcome {
                commit: mls_core::envelope::wrap(&commit),
                welcome,
            })
        })
    }

    /// `WrongState` if a self-group is already established here.
    pub fn join_self_group(&self, welcome: Vec<u8>) -> Result<(), MlsClientError> {
        catch(move || {
            bound(welcome.len(), MAX_WELCOME_LEN)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.join_self_group(&welcome).map_err(map_durable_input)
        })
    }

    /// Used when that device is revoked. The returned remove-commit advances the epoch, so the
    /// removed device can no longer decrypt self-group traffic.
    pub fn remove_self_device(&self, identity: Vec<u8>) -> Result<Vec<u8>, MlsClientError> {
        catch(move || {
            bound(identity.len(), MAX_IDENTITY_LEN)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            let commit = session
                .remove_self_device(&identity)
                .map_err(map_durable_input)?;
            Ok(mls_core::envelope::wrap(&commit))
        })
    }

    /// ADR-0010: builds commit + welcome WITHOUT advancing the group. Sign a manifest, POST
    /// `/commit`, then [`merge_staged`](Self::merge_staged) on success or
    /// [`clear_staged`](Self::clear_staged) on rejection. Never merge before the server's epoch CAS
    /// confirms — that is how a race loser desyncs.
    pub fn stage_add(&self, key_package: Vec<u8>) -> Result<AddOutcome, MlsClientError> {
        catch(move || {
            bound(key_package.len(), MAX_KEY_PACKAGE_LEN)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            let (commit, welcome) = session
                .stage_add_member(&key_package)
                .map_err(map_durable_input)?;
            Ok(AddOutcome { commit, welcome })
        })
    }

    /// Stage a remove (see [`stage_add`](Self::stage_add)). `identity` is the target member's
    /// credential identity bytes. Returns the commit; the group is not advanced until merged.
    pub fn stage_remove(&self, identity: Vec<u8>) -> Result<Vec<u8>, MlsClientError> {
        catch(move || {
            bound(identity.len(), MAX_IDENTITY_LEN)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.stage_remove_member(&identity).map_err(map_durable)
        })
    }

    /// Server accepted: advance the epoch and persist.
    pub fn merge_staged(&self) -> Result<(), MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.merge_staged().map_err(map_durable)
        })
    }

    /// Server rejected, or we're rebasing. State unchanged.
    pub fn clear_staged(&self) -> Result<(), MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.clear_staged().map_err(map_durable)
        })
    }

    /// ADR-0010 recipient path: merges ONLY if the commit's actual effect equals the sender's signed
    /// manifest (`next_epoch`/`added`/`removed` come from it). On mismatch: discarded unmerged,
    /// `InvalidMessage`, state unchanged.
    pub fn process_commit(
        &self,
        envelope: Vec<u8>,
        next_epoch: u64,
        added: Vec<Vec<u8>>,
        removed: Vec<Vec<u8>>,
    ) -> Result<(), MlsClientError> {
        catch(move || {
            bound(envelope.len(), MAX_ENVELOPE_LEN)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session
                .process_commit_checked(&envelope, next_epoch, &added, &removed)
                .map_err(map_durable_input)
        })
    }

    /// Durable draft; does NOT advance the ratchet.
    pub fn enqueue(&self, plaintext: Vec<u8>) -> Result<u64, MlsClientError> {
        catch(move || {
            bound(plaintext.len(), MAX_PLAINTEXT_LEN)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.enqueue(&plaintext).map_err(map_durable)
        })
    }

    /// Produces the versioned opaque envelope (`app-envelope v1`). **Idempotent:** a retry returns
    /// the same bytes and never advances the ratchet again — no double-spend of a message key.
    pub fn encrypt(&self, local_id: u64) -> Result<Vec<u8>, MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            let payload = session.encrypt(local_id).map_err(map_durable)?;
            Ok(mls_core::envelope::wrap(&payload))
        })
    }

    pub fn mark_sent(&self, local_id: u64) -> Result<(), MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.mark_sent(local_id).map_err(map_durable)
        })
    }

    // --- Secret (view-once) messages -------------------------------------------------------------

    /// The classification + body are encrypted inside the content envelope, so the relay never
    /// learns it is secret. `encrypt`/`mark_sent` then proceed exactly as for a normal message.
    pub fn enqueue_secret(&self, body: Vec<u8>) -> Result<SecretHandle, MlsClientError> {
        catch(move || {
            bound(body.len(), MAX_PLAINTEXT_LEN)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            let (local_id, secret_id) = session.enqueue_secret(&body).map_err(map_durable)?;
            Ok(SecretHandle {
                local_id,
                secret_id: secret_id.to_vec(),
            })
        })
    }

    /// ADR-0014 Slice 2c: share `K_r` (exactly 32 bytes) over the E2EE channel — the relay never
    /// sees it. `encrypt`/`mark_sent` then proceed as for a normal message.
    pub fn enqueue_delivery_key_grant(&self, key_r: Vec<u8>) -> Result<u64, MlsClientError> {
        catch(move || {
            let key: [u8; 32] = key_r
                .as_slice()
                .try_into()
                .map_err(|_| MlsClientError::InvalidMessage)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session
                .enqueue_delivery_key_grant(&key)
                .map_err(map_durable)
        })
    }

    /// Up to `max` recent non-secret messages, for replication to a newly-linked device (#7).
    pub fn history_entries(&self, max: u32) -> Result<Vec<HistoryEntry>, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Active { session } => Ok(session
                    .history_entries(max as usize)
                    .into_iter()
                    .map(|e| HistoryEntry {
                        outbound: e.outbound,
                        body: e.body,
                    })
                    .collect()),
                ClientState::Pending { .. } => Err(MlsClientError::WrongState),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// #7: replicate `entries` over the self-group. `WrongState` if none is established.
    pub fn enqueue_history_sync(&self, entries: Vec<HistoryEntry>) -> Result<u64, MlsClientError> {
        catch(move || {
            let core: Vec<CoreHistoryEntry> = entries
                .into_iter()
                .map(|e| CoreHistoryEntry {
                    outbound: e.outbound,
                    body: e.body,
                })
                .collect();
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.enqueue_history_sync(core).map_err(map_durable)
        })
    }

    /// **Atomic + fail-closed:** the transition + deadlines are committed before this returns `Ok`;
    /// an invalid transition (double tap, replay) or failed write returns `Err` and reveals nothing.
    /// `now_ms` is the caller's monotonic clock.
    pub fn begin_secret_reveal(
        &self,
        secret_id: Vec<u8>,
        now_ms: u64,
    ) -> Result<(), MlsClientError> {
        catch(move || {
            let id = secret_id_arg(&secret_id)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session
                .begin_secret_reveal(&id, now_ms)
                .map_err(map_durable_input)
        })
    }

    /// The consumption control message for a secret this device revealed (ADR-0015). `None` if the
    /// secret is unknown, the sender's own, or unrevealed here. Encrypted with the self-group when
    /// one exists (option 3 — the sender never learns of the open; recipients apply via
    /// [`Self::process_self_inbound`]), else the conversation (option 2). Idempotent: repeated calls
    /// return the same envelope and never double-advance the ratchet.
    pub fn secret_consumption_envelope(
        &self,
        secret_id: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, MlsClientError> {
        catch(move || {
            let id = secret_id_arg(&secret_id)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            match session.emit_secret_consumption(&id).map_err(map_durable)? {
                Some(local_id) => {
                    let payload = session.encrypt(local_id).map_err(map_durable)?;
                    Ok(Some(mls_core::envelope::wrap(&payload)))
                }
                None => Ok(None),
            }
        })
    }

    /// The current reveal phase of a secret at `now_ms` (advancing + persisting a state change).
    pub fn secret_phase(
        &self,
        secret_id: Vec<u8>,
        now_ms: u64,
    ) -> Result<SecretPhase, MlsClientError> {
        catch(move || {
            let id = secret_id_arg(&secret_id)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            let state = session.secret_state(&id, now_ms).map_err(map_durable)?;
            Ok(to_phase(state))
        })
    }

    /// The plaintext gate: `None` while sealed/counting down and forever after expiry (which also
    /// scrubs + persists).
    pub fn secret_visible_body(
        &self,
        secret_id: Vec<u8>,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, MlsClientError> {
        catch(move || {
            let id = secret_id_arg(&secret_id)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session
                .secret_visible_body(&id, now_ms)
                .map_err(map_durable)
        })
    }

    /// Both 0 outside that phase. Drives the UI timer + fade.
    pub fn secret_remaining(
        &self,
        secret_id: Vec<u8>,
        now_ms: u64,
    ) -> Result<SecretRemaining, MlsClientError> {
        catch(move || {
            let id = secret_id_arg(&secret_id)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            let (countdown_ms, view_ms) = session
                .secret_remaining_ms(&id, now_ms)
                .map_err(map_durable)?;
            Ok(SecretRemaining {
                countdown_ms,
                view_ms,
            })
        })
    }

    /// Used on a detected screenshot/capture or overlay close. Idempotent; scrubs the body.
    pub fn consume_secret(&self, secret_id: Vec<u8>) -> Result<(), MlsClientError> {
        catch(move || {
            let id = secret_id_arg(&secret_id)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.consume_secret(&id).map_err(map_durable)
        })
    }

    /// All effects — advanced ratchet, stored message, dedup marker, ack-eligibility — are durable
    /// together before returning.
    pub fn process_inbound(
        &self,
        envelope_id: u64,
        ciphertext: Vec<u8>,
    ) -> Result<InboundResult, MlsClientError> {
        catch(move || {
            bound(ciphertext.len(), MAX_ENVELOPE_LEN)?;
            // An unknown app-envelope version is rejected, never fed to MLS as-is.
            let payload = mls_core::envelope::unwrap(&ciphertext)
                .map_err(|_| MlsClientError::InvalidMessage)?
                .to_vec();
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            let outcome = session
                .process_inbound(envelope_id, &payload)
                .map_err(map_durable_input)?;
            Ok(match outcome {
                InboundOutcome::Application(pt) => InboundResult::Application { plaintext: pt },
                InboundOutcome::StateAdvanced => InboundResult::StateAdvanced,
                InboundOutcome::Duplicate => InboundResult::Duplicate,
                InboundOutcome::SecretSealed { secret_id } => InboundResult::SecretSealed {
                    secret_id: secret_id.to_vec(),
                },
                InboundOutcome::SecretConsumedRemotely { secret_id } => {
                    InboundResult::SecretConsumedRemotely {
                        secret_id: secret_id.to_vec(),
                    }
                }
                InboundOutcome::DeliveryKeyGranted { key_r } => InboundResult::DeliveryKeyGranted {
                    key_r: key_r.to_vec(),
                },
                InboundOutcome::HistorySynced { count } => InboundResult::HistorySynced { count },
                InboundOutcome::GroupRenamed { name } => InboundResult::GroupRenamed { name },
                InboundOutcome::AttachmentReceived { attachment } => {
                    InboundResult::AttachmentReceived {
                        attachment: to_attachment_info(&attachment),
                    }
                }
                InboundOutcome::ReactionChanged { target } => InboundResult::ReactionChanged {
                    target: target.to_vec(),
                },
                InboundOutcome::ReceiptsReceived { kind, count } => {
                    InboundResult::ReceiptsReceived {
                        kind: to_receipt_kind(kind),
                        count,
                    }
                }
                InboundOutcome::Typing { sender, active } => {
                    InboundResult::Typing { sender, active }
                }
                InboundOutcome::TimerChanged { seconds } => InboundResult::TimerChanged { seconds },
                InboundOutcome::MessageDeleted { target } => InboundResult::MessageDeleted {
                    target: target.to_vec(),
                },
                InboundOutcome::MessageEdited { target } => InboundResult::MessageEdited {
                    target: target.to_vec(),
                },
                InboundOutcome::GroupAvatarChanged { removed } => {
                    InboundResult::GroupAvatarChanged { removed }
                }
                InboundOutcome::Cover => InboundResult::Cover,
            })
        })
    }

    /// Self-group channel (ADR-0015 option 3): a `SecretConsumed` from another of this account's
    /// devices, or a self-group membership commit. Decrypting with the self-group keeps the read
    /// signal private to the account. Same dedup + ack contract as [`Self::process_inbound`].
    pub fn process_self_inbound(
        &self,
        envelope_id: u64,
        ciphertext: Vec<u8>,
    ) -> Result<InboundResult, MlsClientError> {
        catch(move || {
            bound(ciphertext.len(), MAX_ENVELOPE_LEN)?;
            let payload = mls_core::envelope::unwrap(&ciphertext)
                .map_err(|_| MlsClientError::InvalidMessage)?
                .to_vec();
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            let outcome = session
                .process_self_inbound(envelope_id, &payload)
                .map_err(map_durable_input)?;
            Ok(match outcome {
                InboundOutcome::Application(pt) => InboundResult::Application { plaintext: pt },
                InboundOutcome::StateAdvanced => InboundResult::StateAdvanced,
                InboundOutcome::Duplicate => InboundResult::Duplicate,
                InboundOutcome::SecretSealed { secret_id } => InboundResult::SecretSealed {
                    secret_id: secret_id.to_vec(),
                },
                InboundOutcome::SecretConsumedRemotely { secret_id } => {
                    InboundResult::SecretConsumedRemotely {
                        secret_id: secret_id.to_vec(),
                    }
                }
                InboundOutcome::DeliveryKeyGranted { key_r } => InboundResult::DeliveryKeyGranted {
                    key_r: key_r.to_vec(),
                },
                InboundOutcome::HistorySynced { count } => InboundResult::HistorySynced { count },
                InboundOutcome::GroupRenamed { name } => InboundResult::GroupRenamed { name },
                InboundOutcome::AttachmentReceived { attachment } => {
                    InboundResult::AttachmentReceived {
                        attachment: to_attachment_info(&attachment),
                    }
                }
                InboundOutcome::ReactionChanged { target } => InboundResult::ReactionChanged {
                    target: target.to_vec(),
                },
                InboundOutcome::ReceiptsReceived { kind, count } => {
                    InboundResult::ReceiptsReceived {
                        kind: to_receipt_kind(kind),
                        count,
                    }
                }
                InboundOutcome::Typing { sender, active } => {
                    InboundResult::Typing { sender, active }
                }
                InboundOutcome::TimerChanged { seconds } => InboundResult::TimerChanged { seconds },
                InboundOutcome::MessageDeleted { target } => InboundResult::MessageDeleted {
                    target: target.to_vec(),
                },
                InboundOutcome::MessageEdited { target } => InboundResult::MessageEdited {
                    target: target.to_vec(),
                },
                InboundOutcome::GroupAvatarChanged { removed } => {
                    InboundResult::GroupAvatarChanged { removed }
                }
                InboundOutcome::Cover => InboundResult::Cover,
            })
        })
    }

    /// Durably processed, so safe to acknowledge to the server.
    pub fn ack_eligible(&self) -> Result<Vec<u64>, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Active { session } => Ok(session.ack_eligible()),
                ClientState::Pending { .. } => Err(MlsClientError::WrongState),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    pub fn confirm_acked(&self, ids: Vec<u64>) -> Result<(), MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.confirm_acked(&ids).map_err(map_durable)
        })
    }

    /// Marshals the ENTIRE history across the boundary — fine for tests; a UI should use
    /// [`Self::messages_page`] + [`Self::message_count`] instead.
    pub fn messages(&self) -> Result<Vec<StoredMessage>, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Active { session } => {
                    Ok(session.message_views().iter().map(to_stored).collect())
                }
                ClientState::Pending { .. } => Err(MlsClientError::WrongState),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    // --- Group name, read state (arc: "feels like a messenger") ---------------------------------

    /// The group's name, or `None` if it has never been named. Set by a member over the E2EE
    /// channel: the relay stores no name and cannot learn one.
    pub fn group_name(&self) -> Result<Option<String>, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Active { session } => Ok(session.group_name().map(str::to_string)),
                ClientState::Pending { .. } => Err(MlsClientError::WrongState),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// The group's photo thumbnail (E2EE, like the name), or `None`.
    pub fn group_avatar(&self) -> Result<Option<Vec<u8>>, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Active { session } => Ok(session.group_avatar().map(|b| b.to_vec())),
                ClientState::Pending { .. } => Err(MlsClientError::WrongState),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// Queue a group-photo change for everyone (empty bytes = remove); `encrypt`/`mark_sent` it
    /// like any other message. The image is a pre-scaled THUMBNAIL bounded by the content cap.
    pub fn set_group_avatar(&self, image: Vec<u8>) -> Result<u64, MlsClientError> {
        catch(move || {
            bound(image.len(), MAX_PLAINTEXT_LEN)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session
                .enqueue_group_avatar(&image)
                .map_err(map_durable_input)
        })
    }

    /// Queue a rename for the whole group, returning its local id — `encrypt`/`mark_sent` it like
    /// any other message. The local name changes on encrypt, never before the group is told.
    /// Refuses a name a recipient's decoder would reject (empty, over-long, unsafe to render).
    pub fn set_group_name(&self, name: String) -> Result<u64, MlsClientError> {
        catch(move || {
            bound(name.len(), MAX_PLAINTEXT_LEN)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.enqueue_group_name(&name).map_err(map_durable_input)
        })
    }

    // --- Attachments -----------------------------------------------------------------------------

    /// Queue a message referring to an already-uploaded blob; `encrypt`/`mark_sent` it like any
    /// other message. The key goes to the group over MLS and never to the relay.
    #[allow(clippy::too_many_arguments)]
    pub fn send_attachment(
        &self,
        blob_id: Vec<u8>,
        key: Vec<u8>,
        digest: Vec<u8>,
        size: u64,
        mime: String,
        filename: String,
        caption: String,
    ) -> Result<u64, MlsClientError> {
        catch(move || {
            bound(
                mime.len() + filename.len() + caption.len(),
                MAX_PLAINTEXT_LEN,
            )?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session
                .enqueue_attachment(
                    fixed(&blob_id)?,
                    fixed(&key)?,
                    fixed(&digest)?,
                    size,
                    &mime,
                    &filename,
                    &caption,
                )
                .map_err(map_durable_input)
        })
    }

    // --- Replies, reactions, receipts, typing -----------------------------------------------------

    /// Send a message that answers another. The reply carries only the target's id — never a copy
    /// of its text, so a client cannot display words the quoted person never wrote.
    pub fn send_reply(&self, body: Vec<u8>, reply_to: Vec<u8>) -> Result<u64, MlsClientError> {
        catch(move || {
            bound(body.len(), MAX_PLAINTEXT_LEN)?;
            let target = fixed(&reply_to)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session
                .enqueue_reply(&body, Some(target))
                .map_err(map_durable_input)
        })
    }

    /// React to a message, or with `remove` take the reaction back. Idempotent on both sides.
    pub fn react(
        &self,
        target: Vec<u8>,
        emoji: String,
        remove: bool,
    ) -> Result<u64, MlsClientError> {
        catch(move || {
            let target = fixed(&target)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session
                .enqueue_reaction(target, &emoji, remove)
                .map_err(map_durable_input)
        })
    }

    /// Message ids that still owe a receipt of this kind, oldest first. `Read` only ever names
    /// messages the user has actually seen (`mark_read`).
    pub fn unacknowledged(&self, kind: ReceiptKindFfi) -> Result<Vec<Vec<u8>>, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Active { session } => Ok(session
                    .unacknowledged_inbound(from_receipt_kind(kind))
                    .iter()
                    .map(|id| id.to_vec())
                    .collect()),
                ClientState::Pending { .. } => Err(MlsClientError::WrongState),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// Queue one batched receipt for these ids, and remember they were acknowledged so the same
    /// message is never acknowledged twice.
    pub fn send_receipt(
        &self,
        kind: ReceiptKindFfi,
        message_ids: Vec<Vec<u8>>,
    ) -> Result<u64, MlsClientError> {
        catch(move || {
            let ids = message_ids
                .iter()
                .map(|id| fixed(id))
                .collect::<Result<Vec<[u8; 16]>, _>>()?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            let local_id = session
                .enqueue_receipt(from_receipt_kind(kind), ids.clone())
                .map_err(map_durable_input)?;
            session
                .record_receipts_sent(from_receipt_kind(kind), &ids)
                .map_err(map_durable)?;
            Ok(local_id)
        })
    }

    /// Start or stop a typing indicator. Ephemeral: nothing is logged, and a dropped one costs
    /// nothing, so callers should throttle rather than send per keystroke.
    pub fn send_typing(&self, active: bool) -> Result<u64, MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.enqueue_typing(active).map_err(map_durable_input)
        })
    }

    /// Queue a cover-traffic decoy (R-204) with the given random `padding`. It encrypts and uploads
    /// on the ordinary send path, so the relay sees an envelope indistinguishable from a real one;
    /// the recipient recognises the kind and discards it. Returns the outbound local id to encrypt.
    pub fn send_cover(&self, padding: Vec<u8>) -> Result<u64, MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.enqueue_cover(padding).map_err(map_durable_input)
        })
    }

    // --- Disappearing messages & delete-for-everyone ----------------------------------------------

    /// The conversation's disappearing-message timer in seconds (0 = off).
    pub fn disappear_timer(&self) -> Result<u32, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Active { session } => Ok(session.disappear_after_secs()),
                ClientState::Pending { .. } => Err(MlsClientError::WrongState),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// Queue a timer change for the whole conversation (0 = off), returning its local id —
    /// `encrypt`/`mark_sent` it like any other message. The local timer changes on encrypt, when
    /// the group is actually told. Refuses a timer past the wire cap (90 days).
    pub fn set_disappear_timer(&self, seconds: u32) -> Result<u64, MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session
                .enqueue_timer_change(seconds)
                .map_err(map_durable_input)
        })
    }

    /// Retract one of THIS DEVICE's own messages everywhere (delete-for-everyone), returning the
    /// local id of the queued retraction. Refused for anyone else's message — recipients only
    /// honor the author's delete. Honest limit (R-901): recipients' clients tombstone their
    /// copies; nothing can force a modified client to.
    pub fn delete_for_everyone(&self, target: Vec<u8>) -> Result<u64, MlsClientError> {
        catch(move || {
            let target = fixed(&target)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.enqueue_delete(target).map_err(map_durable_input)
        })
    }

    /// Replace the text of THIS DEVICE's own message (edit), returning the local id of the
    /// queued change. Author-only, text-only, and never on a deleted message — recipients
    /// enforce the same rules independently, and every applied edit is visibly marked.
    pub fn edit_message(&self, target: Vec<u8>, body: Vec<u8>) -> Result<u64, MlsClientError> {
        catch(move || {
            bound(body.len(), MAX_PLAINTEXT_LEN)?;
            let target = fixed(&target)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session
                .enqueue_edit(target, &body)
                .map_err(map_durable_input)
        })
    }

    /// Remove every message past its disappearing-message expiry, returning how many went. Call
    /// on open and periodically (the coordinator does, each sync).
    pub fn scrub_expired(&self) -> Result<u64, MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.scrub_expired().map_err(map_durable)
        })
    }

    /// Mark the whole conversation read (the user is looking at it).
    pub fn mark_read(&self) -> Result<(), MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.mark_read().map_err(map_durable)
        })
    }

    /// Inbound messages newer than the read mark. Your own messages are never unread.
    pub fn unread_count(&self) -> Result<u64, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Active { session } => Ok(session.unread_count()),
                ClientState::Pending { .. } => Err(MlsClientError::WrongState),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// Local ids of outbound messages the server has not accepted yet, oldest first — the upload
    /// retry set after a relaunch. `encrypt` on one of these returns the cached ciphertext.
    pub fn unsent_local_ids(&self) -> Result<Vec<u64>, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Active { session } => Ok(session.unsent_outbound()),
                ClientState::Pending { .. } => Err(MlsClientError::WrongState),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// Erase this device's visible message log when the user deletes the conversation. Protocol
    /// state (ratchet, replay watermark, outbox, secret records) is retained, so later messages
    /// still decrypt and a replayed secret still cannot be re-revealed. Local only — nothing is
    /// sent, and the peer's copy is untouched.
    pub fn clear_visible_history(&self) -> Result<(), MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.clear_visible_history().map_err(map_durable)
        })
    }

    /// TOTAL history: archive + hot window (R-105). Cheap — a stored counter, no archive read.
    pub fn message_count(&self) -> Result<u64, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Active { session } => Ok(session.total_message_count()),
                ClientState::Pending { .. } => Err(MlsClientError::WrongState),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// Bounded window over the FULL history (archive + hot), oldest first. `limit` is clamped to
    /// [`MAX_PAGE_MESSAGES`]; an offset past the end returns an empty page. Pages inside the hot
    /// window never touch the archive, so live rendering stays cheap; scrollback and search pay
    /// for the archive read only when they actually cross into it.
    pub fn messages_page(
        &self,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<StoredMessage>, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Active { session } => {
                    let capped = limit.min(MAX_PAGE_MESSAGES) as usize;
                    Ok(session
                        .message_views_page(offset as usize, capped)
                        .map_err(map_durable)?
                        .iter()
                        .map(to_stored)
                        .collect())
                }
                ClientState::Pending { .. } => Err(MlsClientError::WrongState),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    pub fn epoch(&self) -> Result<u64, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Active { session } => Ok(session.epoch()),
                ClientState::Pending { .. } => Err(MlsClientError::WrongState),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// 0 = pre-versioning; a Pending client also reports 0.
    pub fn storage_format_version(&self) -> Result<u32, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Active { session } => Ok(session.format_version()),
                ClientState::Pending { .. } => Ok(0),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// Idempotent. Durable state on disk is untouched — reopen with `open`.
    pub fn close(&self) {
        if let Ok(mut g) = self.inner.lock() {
            *g = ClientState::Closed;
        }
    }
}

// Non-exported helpers.
impl MlsClient {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ClientState>, MlsClientError> {
        // A poisoned lock fails safe rather than propagating the prior panic.
        self.inner.lock().map_err(|_| MlsClientError::Internal)
    }

    /// TEST-ONLY — never `#[uniffi::export]`ed, so not in the Swift surface. An in-memory journal
    /// lets crash/panic injection run without the filesystem.
    #[doc(hidden)]
    pub fn __test_active_in_memory(
        identity: &[u8],
        journal: InMemoryJournal,
    ) -> Result<Arc<Self>, MlsClientError> {
        let session =
            DurableSession::create(identity, JournalKind::Memory(journal)).map_err(map_durable)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(ClientState::Active {
                session: Box::new(session),
            }),
        }))
    }
}

/// Bundled system text — never an external resource that could fail at runtime.
/// Encrypt a file under a fresh one-time key, ready to upload. Deliberately NOT a method: it
/// touches no group state, so a caller can prepare a file before choosing where to send it — and
/// the upload can fail without ever having created a message that refers to missing bytes.
#[uniffi::export]
pub fn seal_attachment(plaintext: Vec<u8>) -> Result<SealedAttachment, MlsClientError> {
    catch(move || {
        let sealed = attachment::seal(&plaintext).map_err(map_attachment)?;
        Ok(SealedAttachment {
            ciphertext: sealed.ciphertext,
            key: sealed.key.to_vec(),
            digest: sealed.digest.to_vec(),
        })
    })
}

/// Verify a downloaded blob against the sender's digest and decrypt it. Fails closed on a
/// substituted blob distinctly from a bad key, so a client can tell "the relay served the wrong
/// bytes" from "this is not for me".
#[uniffi::export]
pub fn open_attachment(
    key: Vec<u8>,
    digest: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, MlsClientError> {
    catch(move || attachment::open(&key, &digest, &ciphertext).map_err(map_attachment))
}

#[uniffi::export]
pub fn secret_tombstone_text() -> String {
    DurableSession::<InMemoryJournal>::secret_tombstone_text().to_string()
}

/// For a quick human/log check.
#[uniffi::export]
pub fn binding_version() -> String {
    format!(
        "mls-ffi {} / mls-core {} / uniffi 0.29",
        env!("CARGO_PKG_VERSION"),
        CORE_VERSION
    )
}

/// Machine-checkable (ADR-0007 version compatibility).
#[uniffi::export]
pub fn capabilities() -> Capabilities {
    Capabilities {
        binding_version: env!("CARGO_PKG_VERSION").to_string(),
        core_version: CORE_VERSION.to_string(),
        protocol: "MLS 1.0 (RFC 9420)".to_string(),
        ciphersuite: CIPHERSUITE_NAME.to_string(),
        storage_format_version: BLOB_FORMAT_VERSION,
        max_identity: MAX_IDENTITY_LEN as u64,
        max_key_package: MAX_KEY_PACKAGE_LEN as u64,
        max_welcome: MAX_WELCOME_LEN as u64,
        max_envelope: MAX_ENVELOPE_LEN as u64,
        max_plaintext: MAX_PLAINTEXT_LEN as u64,
    }
}

// ---- helpers ------------------------------------------------------------------------------------

fn bound(len: usize, max: usize) -> Result<(), MlsClientError> {
    if len > max {
        Err(MlsClientError::InputTooLarge)
    } else {
        Ok(())
    }
}

fn file_journal(db_path: &str, at_rest_key: &[u8]) -> Result<JournalKind, MlsClientError> {
    if at_rest_key.len() != 32 {
        return Err(MlsClientError::BadKeyLength);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(at_rest_key);
    Ok(JournalKind::File(Box::new(FileJournal::new(db_path, &key))))
}

fn active_mut(g: &mut ClientState) -> Result<&mut DurableSession<JournalKind>, MlsClientError> {
    match g {
        ClientState::Active { session } => Ok(&mut **session),
        ClientState::Pending { .. } => Err(MlsClientError::WrongState),
        ClientState::Closed => Err(MlsClientError::Closed),
    }
}

fn to_stored(m: &CoreMessageView) -> StoredMessage {
    StoredMessage {
        local_id: m.local_id,
        direction: match m.direction {
            CoreDirection::Inbound => Direction::Inbound,
            CoreDirection::Outbound => Direction::Outbound,
        },
        plaintext: m.plaintext.clone(),
        envelope_id: m.envelope_id,
        secret_id: m.secret_id.map(|id| id.to_vec()),
        created_at_ms: m.created_at_ms,
        pending: m.pending,
        attachment: m.attachment.as_ref().map(to_attachment_info),
        message_id: m.message_id.to_vec(),
        reply_to: m.reply_to.map(|id| id.to_vec()),
        reactions: m
            .reactions
            .iter()
            .map(|r| ReactionInfo {
                emoji: r.emoji.clone(),
                sender: r.sender.clone(),
            })
            .collect(),
        delivered_count: m.delivered_count,
        read_count: m.read_count,
        expires_at_ms: m.expires_at_ms,
        deleted: m.deleted,
        edited: m.edited,
        sender: m.sender.clone(),
    }
}

fn to_receipt_kind(kind: CoreReceiptKind) -> ReceiptKindFfi {
    match kind {
        CoreReceiptKind::Delivered => ReceiptKindFfi::Delivered,
        CoreReceiptKind::Read => ReceiptKindFfi::Read,
    }
}

fn from_receipt_kind(kind: ReceiptKindFfi) -> CoreReceiptKind {
    match kind {
        ReceiptKindFfi::Delivered => CoreReceiptKind::Delivered,
        ReceiptKindFfi::Read => CoreReceiptKind::Read,
    }
}

fn to_attachment_info(a: &CoreAttachmentRef) -> AttachmentInfo {
    AttachmentInfo {
        blob_id: a.blob_id.to_vec(),
        key: a.key.to_vec(),
        digest: a.digest.to_vec(),
        size: a.size,
        mime: a.mime.clone(),
        filename: a.filename.clone(),
    }
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], MlsClientError> {
    bytes.try_into().map_err(|_| MlsClientError::InvalidMessage)
}

/// Fail-closed on any length other than 16.
fn secret_id_arg(bytes: &[u8]) -> Result<[u8; SECRET_ID_LEN], MlsClientError> {
    bytes.try_into().map_err(|_| MlsClientError::InvalidMessage)
}

fn to_phase(state: Option<mls_core::secret::SecretState>) -> SecretPhase {
    use mls_core::secret::SecretState::*;
    match state {
        Some(Sealed) => SecretPhase::Sealed,
        Some(Countdown) => SecretPhase::Countdown,
        Some(Visible) => SecretPhase::Visible,
        Some(Consumed) => SecretPhase::Consumed,
        None => SecretPhase::Unknown,
    }
}

/// Panics must never unwind across the C ABI (UB); defense in depth atop UniFFI's own catch.
fn catch<T>(
    f: impl FnOnce() -> Result<T, MlsClientError> + std::panic::UnwindSafe,
) -> Result<T, MlsClientError> {
    catch_unwind(f).unwrap_or(Err(MlsClientError::Internal))
}

/// Local paths: a fault here is ours.
/// Attachment failures are input problems, not internal ones: a bad key or a substituted blob is
/// something the caller must be told precisely so it can say what happened.
fn map_attachment(e: attachment::AttachmentError) -> MlsClientError {
    match e {
        attachment::AttachmentError::BadSize => MlsClientError::InputTooLarge,
        attachment::AttachmentError::BadKey => MlsClientError::BadKeyLength,
        attachment::AttachmentError::DigestMismatch
        | attachment::AttachmentError::Undecryptable => MlsClientError::InvalidMessage,
    }
}

fn map_durable(e: DurableError) -> MlsClientError {
    match e {
        DurableError::NoSession => MlsClientError::NoSession,
        DurableError::UnknownLocal => MlsClientError::NotFound,
        DurableError::Journal => MlsClientError::Journal,
        DurableError::SelfGroup => MlsClientError::WrongState,
        DurableError::Mls | DurableError::Codec => MlsClientError::Internal,
    }
}

/// Inbound paths: bad bytes are caller-supplied.
fn map_durable_input(e: DurableError) -> MlsClientError {
    match e {
        DurableError::NoSession => MlsClientError::NoSession,
        DurableError::UnknownLocal => MlsClientError::NotFound,
        DurableError::Journal => MlsClientError::Journal,
        DurableError::SelfGroup => MlsClientError::WrongState,
        DurableError::Mls | DurableError::Codec => MlsClientError::InvalidMessage,
    }
}

fn map_mls_input(e: MlsError) -> MlsClientError {
    match e {
        MlsError::MemberNotFound => MlsClientError::NotFound,
        MlsError::Codec | MlsError::Lib(_) | MlsError::ManifestMismatch => {
            MlsClientError::InvalidMessage
        }
    }
}
