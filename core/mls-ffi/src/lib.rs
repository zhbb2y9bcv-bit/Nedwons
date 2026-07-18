//! `mls-ffi` — the UniFFI boundary exposing `mls-core`'s MLS client to Swift (ADR-0007).
//!
//! This crate is a **thin marshalling shim**. All MLS/crypto logic lives in `mls-core`
//! (`#![forbid(unsafe_code)]`); the unavoidable `unsafe extern "C"` scaffolding that any FFI needs
//! is generated here by UniFFI and confined to this small, fuzzable boundary.
//!
//! ## Contract (frozen in ADR-0007 v2)
//! - **Object per client, not a handle registry.** Swift holds an `Arc<MlsClient>`; its lifetime is
//!   ARC-managed. There is no shared `u64` registry, which removes stale-handle / ABA / cross-client
//!   / registry-exhaustion hazards by construction. `close()` gives explicit invalidation.
//! - **Single-writer per client.** All state is behind one `Mutex<ClientState>`; a given MLS group
//!   lives in exactly one client, so concurrent mutation of one group is impossible.
//! - **One persistence authority.** The only durable store is `mls_core::durable::DurableSession`
//!   over a `Journal` (an encrypted, atomically-committed blob = MLS store snapshot + message
//!   state). This crate never introduces a second store.
//! - **Bytes only across the boundary.** Key packages, welcomes, envelopes, ciphertext, and
//!   decrypted *application plaintext* cross; **no OpenMLS object, provider/store blob, ratchet
//!   secret, or signing key ever crosses.** There is deliberately no `export_store` on this surface.
//! - **Bounded, typed, redacted.** Every byte input is length-checked before parsing; errors are a
//!   coarse `MlsClientError` with variant-only messages; every entry point is `catch_unwind`-wrapped
//!   so no panic can unwind across the C ABI.

uniffi::setup_scaffolding!();

use std::panic::catch_unwind;
use std::sync::{Arc, Mutex};

use mls_core::client::{
    MAX_ENVELOPE_LEN, MAX_IDENTITY_LEN, MAX_KEY_PACKAGE_LEN, MAX_PLAINTEXT_LEN, MAX_WELCOME_LEN,
};
use mls_core::durable::{
    Direction as CoreDirection, DurableError, DurableSession, FileJournal, InMemoryJournal,
    InboundOutcome, JournalKind, Message as CoreMessage, BLOB_FORMAT_VERSION,
};
use mls_core::{Member, MlsError, CIPHERSUITE_NAME, VERSION as CORE_VERSION};

/// Maximum messages one `messages_page` call returns (bounds per-call FFI marshalling).
pub const MAX_PAGE_MESSAGES: u32 = 256;

/// Stable, coarse, **redacted** error surface. Messages are variant-only: no library internals, key
/// bytes, plaintext, or filesystem paths ever appear (asserted by a redaction test).
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

/// Commit (fan out to existing members) + welcome (deliver to the new member). Both opaque.
#[derive(uniffi::Record)]
pub struct AddOutcome {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

/// Direction of a stored message.
#[derive(uniffi::Enum)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// A durably-stored decrypted message (what the UI renders). Not a secret in the key-substitution
/// sense — application plaintext is exactly what the legitimate client is meant to hold.
#[derive(uniffi::Record)]
pub struct StoredMessage {
    pub local_id: u64,
    pub direction: Direction,
    pub plaintext: Vec<u8>,
    pub envelope_id: Option<u64>,
}

/// Result of processing an inbound envelope.
#[derive(Debug, uniffi::Enum)]
pub enum InboundResult {
    /// Decrypted application plaintext.
    Application { plaintext: Vec<u8> },
    /// A membership/commit advanced group state (no user-visible content).
    StateAdvanced,
    /// Already processed (at-least-once redelivery) — a durable no-op.
    Duplicate,
}

/// Capability/version record so the Swift side can assert it links a compatible core and refuse on
/// mismatch (ADR-0007 version compatibility).
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

/// Client lifecycle. `Pending` = identity exists but no group yet (a joiner that has published a
/// key package and awaits a Welcome). `Active` = a durable conversation. `Closed` = invalidated.
enum ClientState {
    // Both non-terminal states carry a heap-heavy MLS payload (provider store / group state); box
    // them so the enum stays small next to the zero-size `Closed` (clippy::large_enum_variant).
    Pending {
        member: Box<Member>,
        journal: JournalKind,
    },
    Active {
        session: Box<DurableSession<JournalKind>>,
    },
    Closed,
}

/// One MLS client (one identity + one conversation), owned by Swift as an `Arc<MlsClient>`.
#[derive(uniffi::Object)]
pub struct MlsClient {
    inner: Mutex<ClientState>,
}

#[uniffi::export]
impl MlsClient {
    /// Create a brand-new conversation with this client as the group creator/first member. Persists
    /// before returning.
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

    /// This client's key package bytes (a one-time prekey) to publish so others can add it.
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

    /// Join the group described by a Welcome (produced by another member's `add_member`). Transitions
    /// `Pending` → `Active` and persists. On a bad Welcome the client stays `Pending` (retryable).
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

    /// Add a member by their key-package bytes. Returns commit + welcome; the grown group is durable
    /// before returning.
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

    /// Queue an outbound message (durable draft). Does NOT advance the ratchet. Returns a local id.
    pub fn enqueue(&self, plaintext: Vec<u8>) -> Result<u64, MlsClientError> {
        catch(move || {
            bound(plaintext.len(), MAX_PLAINTEXT_LEN)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.enqueue(&plaintext).map_err(map_durable)
        })
    }

    /// Encrypt a queued message into an opaque envelope. **Idempotent:** a retry returns the cached
    /// ciphertext and never advances the ratchet again (no double-spend of a message key).
    pub fn encrypt(&self, local_id: u64) -> Result<Vec<u8>, MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.encrypt(local_id).map_err(map_durable)
        })
    }

    /// Mark a queued message accepted by the server. Persisted before returning.
    pub fn mark_sent(&self, local_id: u64) -> Result<(), MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.mark_sent(local_id).map_err(map_durable)
        })
    }

    /// Process an inbound envelope: application plaintext, a state advance, or a dedup no-op. All
    /// effects (advanced ratchet, stored message, dedup marker, ack-eligibility) are durable
    /// together before returning.
    pub fn process_inbound(
        &self,
        envelope_id: u64,
        ciphertext: Vec<u8>,
    ) -> Result<InboundResult, MlsClientError> {
        catch(move || {
            bound(ciphertext.len(), MAX_ENVELOPE_LEN)?;
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            let outcome = session
                .process_inbound(envelope_id, &ciphertext)
                .map_err(map_durable_input)?;
            Ok(match outcome {
                InboundOutcome::Application(pt) => InboundResult::Application { plaintext: pt },
                InboundOutcome::StateAdvanced => InboundResult::StateAdvanced,
                InboundOutcome::Duplicate => InboundResult::Duplicate,
            })
        })
    }

    /// Envelope ids durably processed and safe to acknowledge to the server.
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

    /// After the server confirms an ack, stop tracking those ids as ack-eligible.
    pub fn confirm_acked(&self, ids: Vec<u64>) -> Result<(), MlsClientError> {
        catch(move || {
            let mut g = self.lock()?;
            let session = active_mut(&mut g)?;
            session.confirm_acked(&ids).map_err(map_durable)
        })
    }

    /// Ordered log of ALL stored messages (inbound decrypted + outbound). Marshals the entire
    /// history across the boundary — fine for tests and small logs; a UI should render from
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

    /// Number of stored messages. Cheap: no payload crosses the boundary.
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

    /// A bounded window of the message log, oldest first: up to `limit` messages starting at
    /// `offset`. `limit` is clamped to [`MAX_PAGE_MESSAGES`] so a single call can never marshal
    /// an unbounded payload across the FFI; an offset past the end returns an empty page. This is
    /// what a chat UI should call (e.g. the newest window = `count - limit .. count`).
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

    /// Current MLS epoch (advances on every membership change).
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

    /// Storage schema version of the loaded blob (0 = pre-versioning; a Pending client reports 0).
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

    /// Explicitly invalidate the client and drop its MLS state. Idempotent; subsequent calls return
    /// `Closed`. Durable state on disk is untouched (reopen with `open`).
    pub fn close(&self) {
        if let Ok(mut g) = self.inner.lock() {
            *g = ClientState::Closed;
        }
    }
}

// Non-exported helpers.
impl MlsClient {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ClientState>, MlsClientError> {
        // A poisoned lock (a prior panic) fails safe rather than propagating.
        self.inner.lock().map_err(|_| MlsClientError::Internal)
    }

    /// TEST-ONLY (never `#[uniffi::export]`ed, so it is not in the Swift surface): build an Active
    /// client over an in-memory journal, so crash/panic injection can be exercised without the
    /// filesystem. Not part of the FFI contract.
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

/// Rust core version + UniFFI contract tag, for a quick human/log check.
#[uniffi::export]
pub fn binding_version() -> String {
    format!(
        "mls-ffi {} / mls-core {} / uniffi 0.29",
        env!("CARGO_PKG_VERSION"),
        CORE_VERSION
    )
}

/// Machine-checkable capability record (ADR-0007 version compatibility).
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
    }
}

/// Panic → typed `Internal`. Panics must never unwind across the C ABI (UB); every entry point is
/// wrapped (defense in depth atop UniFFI's own catch).
fn catch<T>(
    f: impl FnOnce() -> Result<T, MlsClientError> + std::panic::UnwindSafe,
) -> Result<T, MlsClientError> {
    catch_unwind(f).unwrap_or(Err(MlsClientError::Internal))
}

/// Durable errors on **local** paths (encrypt/enqueue/mark_sent/open/create): a fault here is ours.
fn map_durable(e: DurableError) -> MlsClientError {
    match e {
        DurableError::NoSession => MlsClientError::NoSession,
        DurableError::UnknownLocal => MlsClientError::NotFound,
        DurableError::Journal => MlsClientError::Journal,
        DurableError::Mls | DurableError::Codec => MlsClientError::Internal,
    }
}

/// Durable errors on **inbound** paths (process/add_member/join): bad bytes are caller-supplied.
fn map_durable_input(e: DurableError) -> MlsClientError {
    match e {
        DurableError::NoSession => MlsClientError::NoSession,
        DurableError::UnknownLocal => MlsClientError::NotFound,
        DurableError::Journal => MlsClientError::Journal,
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
