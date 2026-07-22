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

use mls_core::client::{
    MAX_ENVELOPE_LEN, MAX_IDENTITY_LEN, MAX_KEY_PACKAGE_LEN, MAX_PLAINTEXT_LEN, MAX_WELCOME_LEN,
};
use mls_core::content::{HistoryEntry as CoreHistoryEntry, SECRET_ID_LEN};
use mls_core::durable::{
    Direction as CoreDirection, DurableError, DurableSession, FileJournal, InMemoryJournal,
    InboundOutcome, JournalKind, Message as CoreMessage, BLOB_FORMAT_VERSION,
};
use mls_core::{Member, MlsError, CIPHERSUITE_NAME, VERSION as CORE_VERSION};

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
        member: Box<Member>,
        journal: JournalKind,
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
    /// prekey, then `join_group(welcome)` once added. The pending identity is not yet durable — if
    /// the process dies before joining, request a fresh key package.
    #[uniffi::constructor]
    pub fn new_joiner(
        identity: Vec<u8>,
        db_path: String,
        at_rest_key: Vec<u8>,
    ) -> Result<Arc<Self>, MlsClientError> {
        catch(move || {
            bound(identity.len(), MAX_IDENTITY_LEN)?;
            let journal = file_journal(&db_path, &at_rest_key)?;
            let member = Member::new(&identity).map_err(map_mls_local)?;
            Ok(Arc::new(Self {
                inner: Mutex::new(ClientState::Pending {
                    member: Box::new(member),
                    journal,
                }),
            }))
        })
    }

    /// Reopen the last durably-committed session (relaunch / crash recovery).
    #[uniffi::constructor]
    pub fn open(db_path: String, at_rest_key: Vec<u8>) -> Result<Arc<Self>, MlsClientError> {
        catch(move || {
            let journal = file_journal(&db_path, &at_rest_key)?;
            let session = DurableSession::open(journal).map_err(map_durable)?;
            Ok(Arc::new(Self {
                inner: Mutex::new(ClientState::Active {
                    session: Box::new(session),
                }),
            }))
        })
    }

    /// A one-time prekey to publish so others can add this client.
    pub fn key_package(&self) -> Result<Vec<u8>, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Pending { member, .. } => {
                    member.key_package_bytes().map_err(map_mls_local)
                }
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
                ClientState::Pending { member, journal } => {
                    match member.join_from_welcome(&welcome) {
                        Ok(conversation) => {
                            match DurableSession::adopt(*member, conversation, journal) {
                                Ok(session) => {
                                    *g = ClientState::Active {
                                        session: Box::new(session),
                                    };
                                    Ok(())
                                }
                                // First commit failed: nothing durable to recover, client is dead → Closed.
                                Err(e) => Err(map_durable(e)),
                            }
                        }
                        Err(e) => {
                            // Restore so the caller can retry with a correct Welcome.
                            *g = ClientState::Pending { member, journal };
                            Err(map_mls_input(e))
                        }
                    }
                }
                ClientState::Active { session } => {
                    *g = ClientState::Active { session };
                    Err(MlsClientError::WrongState)
                }
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// The grown group is durable before returning.
    pub fn add_member(&self, key_package: Vec<u8>) -> Result<AddOutcome, MlsClientError> {
        catch(move || {
            bound(key_package.len(), MAX_KEY_PACKAGE_LEN)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            let (commit, welcome) = session
                .add_member(&key_package)
                .map_err(map_durable_input)?;
            Ok(AddOutcome { commit, welcome })
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
                    Ok(session.messages().iter().map(to_stored).collect())
                }
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

    /// Cheap: no payload crosses the boundary.
    pub fn message_count(&self) -> Result<u64, MlsClientError> {
        catch(move || {
            let g = self.lock()?;
            match &*g {
                ClientState::Active { session } => Ok(session.messages().len() as u64),
                ClientState::Pending { .. } => Err(MlsClientError::WrongState),
                ClientState::Closed => Err(MlsClientError::Closed),
            }
        })
    }

    /// Bounded window, oldest first. `limit` is clamped to [`MAX_PAGE_MESSAGES`] so one call can
    /// never marshal an unbounded payload; an offset past the end returns an empty page.
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
                    let all = session.messages();
                    let start = (offset as usize).min(all.len());
                    let end = start.saturating_add(capped).min(all.len());
                    Ok(all[start..end].iter().map(to_stored).collect())
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

fn to_stored(m: &CoreMessage) -> StoredMessage {
    StoredMessage {
        local_id: m.local_id,
        direction: match m.direction {
            CoreDirection::Inbound => Direction::Inbound,
            CoreDirection::Outbound => Direction::Outbound,
        },
        plaintext: m.plaintext.clone(),
        envelope_id: m.envelope_id,
        secret_id: m.secret_id.map(|id| id.to_vec()),
    }
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

fn map_mls_local(e: MlsError) -> MlsClientError {
    match e {
        MlsError::MemberNotFound => MlsClientError::NotFound,
        MlsError::Codec | MlsError::Lib(_) | MlsError::ManifestMismatch => MlsClientError::Internal,
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
