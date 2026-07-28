//! WebAssembly boundary exposing `mls-core`'s client to a browser (ADR-0017). A thin marshalling
//! shim, sibling to `core/mls-ffi`: all MLS/crypto logic stays in `mls-core`
//! (`#![forbid(unsafe_code)]`), and this crate only translates types.
//!
//! ## Contract (mirrors ADR-0007 v2 — deliberately NOT a second design)
//! - **Object per client, not a handle registry.** JS holds an `MlsClient`; `free()`/`close()`
//!   invalidates. No `u64` registry, so no stale-handle/ABA/cross-client hazards.
//! - **Single-writer per client.** One `RefCell<ClientState>`; a given MLS group lives in exactly
//!   one client. (`mls-ffi` uses a `Mutex` because Swift is multi-threaded; wasm is single-threaded
//!   and the JS host cannot re-enter us mid-call, so a `RefCell` is the honest equivalent — a
//!   `Mutex` here would imply a concurrency guarantee nothing needs.)
//! - **One persistence authority.** Only `DurableSession` over a `Journal`; never a second store.
//! - **Bytes only cross.** No OpenMLS object, store blob, ratchet secret, or signing key ever
//!   crosses; there is deliberately no `export_store` on this surface.
//! - **Bounded, typed, redacted.** Inputs length-checked before parsing; error messages are
//!   variant-only codes carrying no library internals, key bytes, plaintext, or paths.
//!
//! ## One contract that CANNOT be mirrored, stated plainly
//! `mls-ffi` wraps every entry point in `catch_unwind` because a panic unwinding across the C ABI is
//! undefined behaviour. There is no equivalent here: on `wasm32-unknown-unknown` a panic aborts the
//! **whole module instance**, leaving every live `MlsClient` unusable until the page reloads. It is
//! memory-safe (not UB) but it IS a denial of service, so the defence is the same bounded, typed,
//! fail-closed input handling — and `set_panic_hook()` so a panic is at least diagnosable instead of
//! a silent `unreachable`.

mod journal;

use std::cell::{RefCell, RefMut};

use mls_core::client::{
    MAX_ENVELOPE_LEN, MAX_IDENTITY_LEN, MAX_KEY_PACKAGE_LEN, MAX_PLAINTEXT_LEN, MAX_WELCOME_LEN,
};
use mls_core::content::{HistoryEntry as CoreHistoryEntry, SECRET_ID_LEN};
use mls_core::durable::{
    Direction as CoreDirection, DurableError, DurableSession, InMemoryJournal, InboundOutcome,
    Message as CoreMessage, BLOB_FORMAT_VERSION,
};
use mls_core::{Member, MlsError, CIPHERSUITE_NAME, VERSION as CORE_VERSION};
use wasm_bindgen::prelude::*;

pub use journal::{HostJournal, JournalHost, WasmJournal};

/// Bounds per-call marshalling, as on the UniFFI surface.
pub const MAX_PAGE_MESSAGES: u32 = 256;

/// Route Rust panics to `console.error` with a stack trace. Without this a panic surfaces in JS as
/// an opaque `unreachable executed`. Safe to call more than once; call it first from the host.
#[wasm_bindgen(js_name = setPanicHook)]
pub fn set_panic_hook() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            // Only the panic location/message — never client state.
            web_error(&format!("mls-wasm panic: {info}"));
        }));
    });
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn web_error(msg: &str);
}

// ---- errors -------------------------------------------------------------------------------------

/// Variant-only, exactly the `mls-ffi` taxonomy. These become the `message` of a thrown JS `Error`,
/// so they are **stable machine-readable codes** clients may switch on — never prose, and never
/// anything derived from attacker-controlled bytes.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WasmError {
    InputTooLarge,
    BadKeyLength,
    WrongState,
    NotFound,
    InvalidMessage,
    NoSession,
    Journal,
    Closed,
    Internal,
}

impl WasmError {
    fn code(self) -> &'static str {
        match self {
            WasmError::InputTooLarge => "input_too_large",
            WasmError::BadKeyLength => "bad_key_length",
            WasmError::WrongState => "wrong_state",
            WasmError::NotFound => "not_found",
            WasmError::InvalidMessage => "invalid_message",
            WasmError::NoSession => "no_session",
            WasmError::Journal => "journal",
            WasmError::Closed => "closed",
            WasmError::Internal => "internal",
        }
    }
}

impl From<WasmError> for JsValue {
    fn from(e: WasmError) -> Self {
        js_sys::Error::new(e.code()).into()
    }
}

type Result<T> = std::result::Result<T, WasmError>;

// ---- value types --------------------------------------------------------------------------------

/// Commit fans out to existing members; welcome goes to the new one. Both opaque.
#[wasm_bindgen]
pub struct AddOutcome {
    commit: Vec<u8>,
    welcome: Vec<u8>,
}

#[wasm_bindgen]
impl AddOutcome {
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Vec<u8> {
        self.commit.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Vec<u8> {
        self.welcome.clone()
    }
}

/// Mirrors `mls_core::secret::SecretState`.
#[wasm_bindgen]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SecretPhase {
    Sealed = "sealed",
    Countdown = "countdown",
    Visible = "visible",
    /// Terminal: plaintext gone, cannot reopen.
    Consumed = "consumed",
    /// No secret with this id is known here.
    Unknown = "unknown",
}

/// What the UI renders.
#[wasm_bindgen]
pub struct StoredMessage {
    local_id: u64,
    outbound: bool,
    plaintext: Vec<u8>,
    envelope_id: Option<u64>,
    secret_id: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl StoredMessage {
    #[wasm_bindgen(getter, js_name = localId)]
    pub fn local_id(&self) -> u64 {
        self.local_id
    }
    /// True if this account sent it. (The UniFFI surface uses a `Direction` enum; a boolean is the
    /// idiomatic JS equivalent of a two-variant enum and avoids a needless exported type.)
    #[wasm_bindgen(getter)]
    pub fn outbound(&self) -> bool {
        self.outbound
    }
    /// EMPTY when `secretId` is set — render the placeholder/tombstone from `secretPhase`, never
    /// this.
    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> Vec<u8> {
        self.plaintext.clone()
    }
    #[wasm_bindgen(getter, js_name = envelopeId)]
    pub fn envelope_id(&self) -> Option<u64> {
        self.envelope_id
    }
    /// `Some` (16 bytes) for a view-once secret.
    #[wasm_bindgen(getter, js_name = secretId)]
    pub fn secret_id(&self) -> Option<Vec<u8>> {
        self.secret_id.clone()
    }
}

/// Both 0 outside that phase. Drives the UI timer/fade.
#[wasm_bindgen]
pub struct SecretRemaining {
    countdown_ms: u64,
    view_ms: u64,
}

#[wasm_bindgen]
impl SecretRemaining {
    #[wasm_bindgen(getter, js_name = countdownMs)]
    pub fn countdown_ms(&self) -> u64 {
        self.countdown_ms
    }
    #[wasm_bindgen(getter, js_name = viewMs)]
    pub fn view_ms(&self) -> u64 {
        self.view_ms
    }
}

#[wasm_bindgen]
pub struct SecretHandle {
    local_id: u64,
    secret_id: Vec<u8>,
}

#[wasm_bindgen]
impl SecretHandle {
    #[wasm_bindgen(getter, js_name = localId)]
    pub fn local_id(&self) -> u64 {
        self.local_id
    }
    #[wasm_bindgen(getter, js_name = secretId)]
    pub fn secret_id(&self) -> Vec<u8> {
        self.secret_id.clone()
    }
}

/// The kind tag on [`InboundResult`]. A Rust enum with payloads cannot cross `wasm_bindgen`, so the
/// tagged union becomes a tag plus nullable payload getters — the standard JS shape.
#[wasm_bindgen]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum InboundKind {
    Application = "application",
    /// A commit advanced group state; no user-visible content.
    StateAdvanced = "state_advanced",
    /// At-least-once redelivery or a replayed secret id — a durable no-op.
    Duplicate = "duplicate",
    /// Stored sealed; the body is NOT delivered here.
    SecretSealed = "secret_sealed",
    /// Another of this account's devices revealed it; this copy is consumed.
    SecretConsumedRemotely = "secret_consumed_remotely",
    /// ADR-0014: store `K_r` keyed by sender for future sealed sends.
    DeliveryKeyGranted = "delivery_key_granted",
    /// Past messages were replicated to this device.
    HistorySynced = "history_synced",
}

#[wasm_bindgen]
pub struct InboundResult {
    kind: InboundKind,
    plaintext: Option<Vec<u8>>,
    secret_id: Option<Vec<u8>>,
    key_r: Option<Vec<u8>>,
    count: Option<u64>,
}

#[wasm_bindgen]
impl InboundResult {
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> InboundKind {
        self.kind
    }
    /// Set only for `application`.
    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> Option<Vec<u8>> {
        self.plaintext.clone()
    }
    /// Set for `secret_sealed` / `secret_consumed_remotely`.
    #[wasm_bindgen(getter, js_name = secretId)]
    pub fn secret_id(&self) -> Option<Vec<u8>> {
        self.secret_id.clone()
    }
    /// Set only for `delivery_key_granted`.
    #[wasm_bindgen(getter, js_name = keyR)]
    pub fn key_r(&self) -> Option<Vec<u8>> {
        self.key_r.clone()
    }
    /// Set only for `history_synced`.
    #[wasm_bindgen(getter)]
    pub fn count(&self) -> Option<u64> {
        self.count
    }
}

/// One past message in a history-sync batch. Secrets are never included.
#[wasm_bindgen]
pub struct HistoryEntry {
    outbound: bool,
    body: Vec<u8>,
}

#[wasm_bindgen]
impl HistoryEntry {
    #[wasm_bindgen(constructor)]
    pub fn new(outbound: bool, body: Vec<u8>) -> Self {
        Self { outbound, body }
    }
    #[wasm_bindgen(getter)]
    pub fn outbound(&self) -> bool {
        self.outbound
    }
    #[wasm_bindgen(getter)]
    pub fn body(&self) -> Vec<u8> {
        self.body.clone()
    }
}

/// Lets the host assert it links a compatible core and refuse on mismatch (ADR-0007).
#[wasm_bindgen]
pub struct Capabilities {
    binding_version: String,
    core_version: String,
    protocol: String,
    ciphersuite: String,
    storage_format_version: u32,
    max_identity: u32,
    max_key_package: u32,
    max_welcome: u32,
    max_envelope: u32,
    max_plaintext: u32,
}

#[wasm_bindgen]
impl Capabilities {
    #[wasm_bindgen(getter, js_name = bindingVersion)]
    pub fn binding_version(&self) -> String {
        self.binding_version.clone()
    }
    #[wasm_bindgen(getter, js_name = coreVersion)]
    pub fn core_version(&self) -> String {
        self.core_version.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn protocol(&self) -> String {
        self.protocol.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn ciphersuite(&self) -> String {
        self.ciphersuite.clone()
    }
    #[wasm_bindgen(getter, js_name = storageFormatVersion)]
    pub fn storage_format_version(&self) -> u32 {
        self.storage_format_version
    }
    #[wasm_bindgen(getter, js_name = maxIdentity)]
    pub fn max_identity(&self) -> u32 {
        self.max_identity
    }
    #[wasm_bindgen(getter, js_name = maxKeyPackage)]
    pub fn max_key_package(&self) -> u32 {
        self.max_key_package
    }
    #[wasm_bindgen(getter, js_name = maxWelcome)]
    pub fn max_welcome(&self) -> u32 {
        self.max_welcome
    }
    #[wasm_bindgen(getter, js_name = maxEnvelope)]
    pub fn max_envelope(&self) -> u32 {
        self.max_envelope
    }
    #[wasm_bindgen(getter, js_name = maxPlaintext)]
    pub fn max_plaintext(&self) -> u32 {
        self.max_plaintext
    }
}

/// Machine-checkable version compatibility.
#[wasm_bindgen]
pub fn capabilities() -> Capabilities {
    Capabilities {
        binding_version: env!("CARGO_PKG_VERSION").to_string(),
        core_version: CORE_VERSION.to_string(),
        protocol: "MLS 1.0 (RFC 9420)".to_string(),
        ciphersuite: CIPHERSUITE_NAME.to_string(),
        storage_format_version: BLOB_FORMAT_VERSION,
        max_identity: MAX_IDENTITY_LEN as u32,
        max_key_package: MAX_KEY_PACKAGE_LEN as u32,
        max_welcome: MAX_WELCOME_LEN as u32,
        max_envelope: MAX_ENVELOPE_LEN as u32,
        max_plaintext: MAX_PLAINTEXT_LEN as u32,
    }
}

/// Bundled system text — never an external resource that could fail at runtime.
#[wasm_bindgen(js_name = secretTombstoneText)]
pub fn secret_tombstone_text() -> String {
    DurableSession::<InMemoryJournal>::secret_tombstone_text().to_string()
}

#[wasm_bindgen(js_name = bindingVersion)]
pub fn binding_version() -> String {
    format!(
        "mls-wasm {} / mls-core {} / wasm-bindgen 0.2",
        env!("CARGO_PKG_VERSION"),
        CORE_VERSION
    )
}

// ---- the client ---------------------------------------------------------------------------------

/// `Pending` = identity but no group yet (a joiner awaiting a Welcome). `Active` = a durable
/// conversation. `Closed` = invalidated.
enum ClientState {
    Pending {
        member: Box<Member>,
        journal: WasmJournal,
    },
    Active {
        session: Box<DurableSession<WasmJournal>>,
    },
    Closed,
}

/// One identity + one conversation.
#[wasm_bindgen]
pub struct MlsClient {
    inner: RefCell<ClientState>,
}

#[wasm_bindgen]
impl MlsClient {
    /// This client becomes the group creator/first member. Persists before returning.
    ///
    /// `journal` is the embedder's synchronous storage host (see `journal.rs` for the atomicity
    /// contract it must honour); `atRestKey` is 32 bytes from the caller's key hierarchy.
    #[wasm_bindgen(js_name = createGroup)]
    pub fn create_group(
        identity: Vec<u8>,
        journal: JournalHost,
        at_rest_key: Vec<u8>,
    ) -> Result<MlsClient> {
        bound(identity.len(), MAX_IDENTITY_LEN)?;
        let journal = host_journal(journal, &at_rest_key)?;
        let session = DurableSession::create(&identity, journal).map_err(map_durable)?;
        Ok(Self::active(session))
    }

    /// Create a fresh identity that will JOIN an existing group: publish `keyPackage()`, then
    /// `joinGroup(welcome)` once added. The pending identity is not yet durable — if the page dies
    /// before joining, request a fresh key package.
    #[wasm_bindgen(js_name = newJoiner)]
    pub fn new_joiner(
        identity: Vec<u8>,
        journal: JournalHost,
        at_rest_key: Vec<u8>,
    ) -> Result<MlsClient> {
        bound(identity.len(), MAX_IDENTITY_LEN)?;
        let journal = host_journal(journal, &at_rest_key)?;
        let member = Member::new(&identity).map_err(map_mls_local)?;
        Ok(MlsClient {
            inner: RefCell::new(ClientState::Pending {
                member: Box::new(member),
                journal,
            }),
        })
    }

    /// Reopen the last durably-committed session (reload / crash recovery).
    pub fn open(journal: JournalHost, at_rest_key: Vec<u8>) -> Result<MlsClient> {
        let journal = host_journal(journal, &at_rest_key)?;
        let session = DurableSession::open(journal).map_err(map_durable)?;
        Ok(Self::active(session))
    }

    /// **Volatile**: state lives only for this page's lifetime. For tests and throwaway sessions —
    /// never a fallback when the storage host is unavailable, which must surface as an error rather
    /// than silently losing the ratchet.
    #[wasm_bindgen(js_name = createGroupInMemory)]
    pub fn create_group_in_memory(identity: Vec<u8>) -> Result<MlsClient> {
        bound(identity.len(), MAX_IDENTITY_LEN)?;
        let session =
            DurableSession::create(&identity, WasmJournal::Memory(InMemoryJournal::new()))
                .map_err(map_durable)?;
        Ok(Self::active(session))
    }

    /// Volatile joiner, the counterpart to [`Self::create_group_in_memory`]. Same warning: nothing
    /// survives a reload.
    #[wasm_bindgen(js_name = newJoinerInMemory)]
    pub fn new_joiner_in_memory(identity: Vec<u8>) -> Result<MlsClient> {
        bound(identity.len(), MAX_IDENTITY_LEN)?;
        let member = Member::new(&identity).map_err(map_mls_local)?;
        Ok(MlsClient {
            inner: RefCell::new(ClientState::Pending {
                member: Box::new(member),
                journal: WasmJournal::Memory(InMemoryJournal::new()),
            }),
        })
    }

    /// A one-time prekey to publish so others can add this client.
    #[wasm_bindgen(js_name = keyPackage)]
    pub fn key_package(&self) -> Result<Vec<u8>> {
        match &*self.state()? {
            ClientState::Pending { member, .. } => {
                member.key_package_bytes().map_err(map_mls_local)
            }
            ClientState::Active { session } => session.key_package().map_err(map_durable),
            ClientState::Closed => Err(WasmError::Closed),
        }
    }

    /// `Pending` → `Active`, persisted. On a bad Welcome the client stays `Pending` (retryable).
    #[wasm_bindgen(js_name = joinGroup)]
    pub fn join_group(&self, welcome: Vec<u8>) -> Result<()> {
        bound(welcome.len(), MAX_WELCOME_LEN)?;
        let mut g = self.state()?;
        match std::mem::replace(&mut *g, ClientState::Closed) {
            ClientState::Pending { member, journal } => match member.join_from_welcome(&welcome) {
                Ok(conversation) => match DurableSession::adopt(*member, conversation, journal) {
                    Ok(session) => {
                        *g = ClientState::Active {
                            session: Box::new(session),
                        };
                        Ok(())
                    }
                    // First commit failed: nothing durable to recover, the client is dead → Closed.
                    Err(e) => Err(map_durable(e)),
                },
                Err(e) => {
                    // Restore so the caller can retry with a correct Welcome.
                    *g = ClientState::Pending { member, journal };
                    Err(map_mls_input(e))
                }
            },
            ClientState::Active { session } => {
                *g = ClientState::Active { session };
                Err(WasmError::WrongState)
            }
            ClientState::Closed => Err(WasmError::Closed),
        }
    }

    /// The grown group is durable before returning.
    #[wasm_bindgen(js_name = addMember)]
    pub fn add_member(&self, key_package: Vec<u8>) -> Result<AddOutcome> {
        bound(key_package.len(), MAX_KEY_PACKAGE_LEN)?;
        let mut g = self.state()?;
        let session = active_mut(&mut g)?;
        let (commit, welcome) = session
            .add_member(&key_package)
            .map_err(map_durable_input)?;
        Ok(AddOutcome { commit, welcome })
    }

    // --- staged commits (ADR-0010) ---------------------------------------------------------------

    /// Builds commit + welcome WITHOUT advancing the epoch or persisting. Sign a manifest, POST
    /// `/commit`, then `mergeStaged()` on success or `clearStaged()` on rejection. Never merge
    /// before the server's epoch CAS confirms — that is how a race loser desyncs.
    #[wasm_bindgen(js_name = stageAdd)]
    pub fn stage_add(&self, key_package: Vec<u8>) -> Result<AddOutcome> {
        bound(key_package.len(), MAX_KEY_PACKAGE_LEN)?;
        let mut g = self.state()?;
        let session = active_mut(&mut g)?;
        let (commit, welcome) = session
            .stage_add_member(&key_package)
            .map_err(map_durable_input)?;
        Ok(AddOutcome { commit, welcome })
    }

    #[wasm_bindgen(js_name = stageRemove)]
    pub fn stage_remove(&self, identity: Vec<u8>) -> Result<Vec<u8>> {
        bound(identity.len(), MAX_IDENTITY_LEN)?;
        let mut g = self.state()?;
        let session = active_mut(&mut g)?;
        session.stage_remove_member(&identity).map_err(map_durable)
    }

    /// Server accepted: advance the epoch and persist.
    #[wasm_bindgen(js_name = mergeStaged)]
    pub fn merge_staged(&self) -> Result<()> {
        let mut g = self.state()?;
        active_mut(&mut g)?.merge_staged().map_err(map_durable)
    }

    /// Server rejected, or we're rebasing. State unchanged.
    #[wasm_bindgen(js_name = clearStaged)]
    pub fn clear_staged(&self) -> Result<()> {
        let mut g = self.state()?;
        active_mut(&mut g)?.clear_staged().map_err(map_durable)
    }

    /// ADR-0010 recipient path: merges ONLY if the commit's actual effect equals the sender's signed
    /// manifest. On mismatch: discarded unmerged, `invalid_message`, state unchanged.
    ///
    /// `added`/`removed` are arrays of identity byte-arrays taken from that manifest.
    #[wasm_bindgen(js_name = processCommit)]
    pub fn process_commit(
        &self,
        envelope: Vec<u8>,
        next_epoch: u64,
        added: js_sys::Array,
        removed: js_sys::Array,
    ) -> Result<()> {
        bound(envelope.len(), MAX_ENVELOPE_LEN)?;
        let added = byte_arrays(&added)?;
        let removed = byte_arrays(&removed)?;
        let mut g = self.state()?;
        let session = active_mut(&mut g)?;
        session
            .process_commit_checked(&envelope, next_epoch, &added, &removed)
            .map_err(map_durable_input)
    }

    // --- device self-group (ADR-0015 option 3) ---------------------------------------------------

    #[wasm_bindgen(js_name = hasSelfGroup)]
    pub fn has_self_group(&self) -> Result<bool> {
        match &*self.state()? {
            ClientState::Active { session } => Ok(session.has_self_group()),
            ClientState::Pending { .. } => Err(WasmError::WrongState),
            ClientState::Closed => Err(WasmError::Closed),
        }
    }

    /// `wrong_state` if one already exists.
    #[wasm_bindgen(js_name = createSelfGroup)]
    pub fn create_self_group(&self) -> Result<()> {
        let mut g = self.state()?;
        active_mut(&mut g)?.create_self_group().map_err(map_durable)
    }

    /// Returns a **wrapped** commit (for existing devices via `processSelfInbound`, which unwraps)
    /// plus the **raw** welcome (for the new device via `joinSelfGroup`, which does not).
    #[wasm_bindgen(js_name = addSelfDevice)]
    pub fn add_self_device(&self, key_package: Vec<u8>) -> Result<AddOutcome> {
        bound(key_package.len(), MAX_KEY_PACKAGE_LEN)?;
        let mut g = self.state()?;
        let session = active_mut(&mut g)?;
        let (commit, welcome) = session
            .add_self_device(&key_package)
            .map_err(map_durable_input)?;
        Ok(AddOutcome {
            commit: mls_core::envelope::wrap(&commit),
            welcome,
        })
    }

    #[wasm_bindgen(js_name = joinSelfGroup)]
    pub fn join_self_group(&self, welcome: Vec<u8>) -> Result<()> {
        bound(welcome.len(), MAX_WELCOME_LEN)?;
        let mut g = self.state()?;
        active_mut(&mut g)?
            .join_self_group(&welcome)
            .map_err(map_durable_input)
    }

    /// Used when that device is revoked. The returned remove-commit advances the epoch, so the
    /// removed device cannot decrypt later self-group traffic even if it kept old ratchet state.
    #[wasm_bindgen(js_name = removeSelfDevice)]
    pub fn remove_self_device(&self, identity: Vec<u8>) -> Result<Vec<u8>> {
        bound(identity.len(), MAX_IDENTITY_LEN)?;
        let mut g = self.state()?;
        let commit = active_mut(&mut g)?
            .remove_self_device(&identity)
            .map_err(map_durable_input)?;
        Ok(mls_core::envelope::wrap(&commit))
    }

    // --- sending ---------------------------------------------------------------------------------

    /// Durable draft; does NOT advance the ratchet.
    pub fn enqueue(&self, plaintext: Vec<u8>) -> Result<u64> {
        bound(plaintext.len(), MAX_PLAINTEXT_LEN)?;
        let mut g = self.state()?;
        active_mut(&mut g)?.enqueue(&plaintext).map_err(map_durable)
    }

    /// Produces the versioned opaque envelope (`app-envelope v1`). **Idempotent:** a retry returns
    /// the same bytes and never advances the ratchet again — no double-spend of a message key.
    pub fn encrypt(&self, local_id: u64) -> Result<Vec<u8>> {
        let mut g = self.state()?;
        let payload = active_mut(&mut g)?.encrypt(local_id).map_err(map_durable)?;
        Ok(mls_core::envelope::wrap(&payload))
    }

    #[wasm_bindgen(js_name = markSent)]
    pub fn mark_sent(&self, local_id: u64) -> Result<()> {
        let mut g = self.state()?;
        active_mut(&mut g)?.mark_sent(local_id).map_err(map_durable)
    }

    /// The classification + body are encrypted inside the content envelope, so the relay never
    /// learns a message is secret. `encrypt`/`markSent` then proceed exactly as for a normal one.
    #[wasm_bindgen(js_name = enqueueSecret)]
    pub fn enqueue_secret(&self, body: Vec<u8>) -> Result<SecretHandle> {
        bound(body.len(), MAX_PLAINTEXT_LEN)?;
        let mut g = self.state()?;
        let (local_id, secret_id) = active_mut(&mut g)?
            .enqueue_secret(&body)
            .map_err(map_durable)?;
        Ok(SecretHandle {
            local_id,
            secret_id: secret_id.to_vec(),
        })
    }

    /// ADR-0014: share `K_r` (exactly 32 bytes) over the E2EE channel — the relay never sees it.
    #[wasm_bindgen(js_name = enqueueDeliveryKeyGrant)]
    pub fn enqueue_delivery_key_grant(&self, key_r: Vec<u8>) -> Result<u64> {
        let key: [u8; 32] = key_r
            .as_slice()
            .try_into()
            .map_err(|_| WasmError::InvalidMessage)?;
        let mut g = self.state()?;
        active_mut(&mut g)?
            .enqueue_delivery_key_grant(&key)
            .map_err(map_durable)
    }

    // --- receiving -------------------------------------------------------------------------------

    /// All effects — advanced ratchet, stored message, dedup marker, ack-eligibility — are durable
    /// together before returning. Idempotent per `envelopeId`.
    #[wasm_bindgen(js_name = processInbound)]
    pub fn process_inbound(&self, envelope_id: u64, ciphertext: Vec<u8>) -> Result<InboundResult> {
        self.process(envelope_id, ciphertext, false)
    }

    /// Self-group channel (ADR-0015 option 3): a `SecretConsumed` from another of this account's
    /// devices, or a self-group membership commit. Same dedup + ack contract.
    #[wasm_bindgen(js_name = processSelfInbound)]
    pub fn process_self_inbound(
        &self,
        envelope_id: u64,
        ciphertext: Vec<u8>,
    ) -> Result<InboundResult> {
        self.process(envelope_id, ciphertext, true)
    }

    /// Durably processed, so safe to acknowledge to the server.
    #[wasm_bindgen(js_name = ackEligible)]
    pub fn ack_eligible(&self) -> Result<Vec<u64>> {
        match &*self.state()? {
            ClientState::Active { session } => Ok(session.ack_eligible()),
            ClientState::Pending { .. } => Err(WasmError::WrongState),
            ClientState::Closed => Err(WasmError::Closed),
        }
    }

    #[wasm_bindgen(js_name = confirmAcked)]
    pub fn confirm_acked(&self, ids: Vec<u64>) -> Result<()> {
        let mut g = self.state()?;
        active_mut(&mut g)?.confirm_acked(&ids).map_err(map_durable)
    }

    // --- secret reveal state machine -------------------------------------------------------------

    /// **Atomic + fail-closed:** the transition + deadlines are committed before this returns; an
    /// invalid transition (double tap, replay) or failed write throws and reveals nothing. `nowMs`
    /// is the caller's monotonic clock (`performance.now()`, NOT `Date.now()`).
    #[wasm_bindgen(js_name = beginSecretReveal)]
    pub fn begin_secret_reveal(&self, secret_id: Vec<u8>, now_ms: u64) -> Result<()> {
        let id = secret_id_arg(&secret_id)?;
        let mut g = self.state()?;
        active_mut(&mut g)?
            .begin_secret_reveal(&id, now_ms)
            .map_err(map_durable_input)
    }

    /// The consumption control message for a secret this device revealed (ADR-0015). `null` if the
    /// secret is unknown, the sender's own, or unrevealed here. Idempotent: repeated calls return
    /// the same envelope and never double-advance the ratchet.
    #[wasm_bindgen(js_name = secretConsumptionEnvelope)]
    pub fn secret_consumption_envelope(&self, secret_id: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let id = secret_id_arg(&secret_id)?;
        let mut g = self.state()?;
        let session = active_mut(&mut g)?;
        match session.emit_secret_consumption(&id).map_err(map_durable)? {
            Some(local_id) => {
                let payload = session.encrypt(local_id).map_err(map_durable)?;
                Ok(Some(mls_core::envelope::wrap(&payload)))
            }
            None => Ok(None),
        }
    }

    #[wasm_bindgen(js_name = secretPhase)]
    pub fn secret_phase(&self, secret_id: Vec<u8>, now_ms: u64) -> Result<SecretPhase> {
        let id = secret_id_arg(&secret_id)?;
        let mut g = self.state()?;
        let state = active_mut(&mut g)?
            .secret_state(&id, now_ms)
            .map_err(map_durable)?;
        Ok(to_phase(state))
    }

    /// The plaintext gate: `null` while sealed/counting down and forever after expiry (which also
    /// scrubs + persists).
    #[wasm_bindgen(js_name = secretVisibleBody)]
    pub fn secret_visible_body(&self, secret_id: Vec<u8>, now_ms: u64) -> Result<Option<Vec<u8>>> {
        let id = secret_id_arg(&secret_id)?;
        let mut g = self.state()?;
        active_mut(&mut g)?
            .secret_visible_body(&id, now_ms)
            .map_err(map_durable)
    }

    #[wasm_bindgen(js_name = secretRemaining)]
    pub fn secret_remaining(&self, secret_id: Vec<u8>, now_ms: u64) -> Result<SecretRemaining> {
        let id = secret_id_arg(&secret_id)?;
        let mut g = self.state()?;
        let (countdown_ms, view_ms) = active_mut(&mut g)?
            .secret_remaining_ms(&id, now_ms)
            .map_err(map_durable)?;
        Ok(SecretRemaining {
            countdown_ms,
            view_ms,
        })
    }

    /// Used on an explicit close (or a detected capture, where the platform allows). Idempotent;
    /// scrubs the body.
    #[wasm_bindgen(js_name = consumeSecret)]
    pub fn consume_secret(&self, secret_id: Vec<u8>) -> Result<()> {
        let id = secret_id_arg(&secret_id)?;
        let mut g = self.state()?;
        active_mut(&mut g)?.consume_secret(&id).map_err(map_durable)
    }

    // --- history ---------------------------------------------------------------------------------

    /// Up to `max` recent non-secret messages, for replication to a newly-linked device.
    #[wasm_bindgen(js_name = historyEntries)]
    pub fn history_entries(&self, max: u32) -> Result<Vec<HistoryEntry>> {
        match &*self.state()? {
            ClientState::Active { session } => Ok(session
                .history_entries(max as usize)
                .into_iter()
                .map(|e| HistoryEntry {
                    outbound: e.outbound,
                    body: e.body,
                })
                .collect()),
            ClientState::Pending { .. } => Err(WasmError::WrongState),
            ClientState::Closed => Err(WasmError::Closed),
        }
    }

    /// Replicate `entries` over the self-group. `wrong_state` if none is established.
    #[wasm_bindgen(js_name = enqueueHistorySync)]
    pub fn enqueue_history_sync(&self, entries: Vec<HistoryEntry>) -> Result<u64> {
        let core: Vec<CoreHistoryEntry> = entries
            .into_iter()
            .map(|e| CoreHistoryEntry {
                outbound: e.outbound,
                body: e.body,
            })
            .collect();
        let mut g = self.state()?;
        active_mut(&mut g)?
            .enqueue_history_sync(core)
            .map_err(map_durable)
    }

    // --- reading ---------------------------------------------------------------------------------

    /// Cheap: no payload crosses the boundary.
    #[wasm_bindgen(js_name = messageCount)]
    pub fn message_count(&self) -> Result<u64> {
        match &*self.state()? {
            ClientState::Active { session } => Ok(session.messages().len() as u64),
            ClientState::Pending { .. } => Err(WasmError::WrongState),
            ClientState::Closed => Err(WasmError::Closed),
        }
    }

    /// Bounded window, oldest first. `limit` is clamped to `MAX_PAGE_MESSAGES` so one call can never
    /// marshal an unbounded payload; an offset past the end returns an empty page.
    ///
    /// There is deliberately no "all messages" call here: the UniFFI surface has one only for tests,
    /// and R-105 (whole-history rewrite per commit) bites harder in a browser.
    #[wasm_bindgen(js_name = messagesPage)]
    pub fn messages_page(&self, offset: u64, limit: u32) -> Result<Vec<StoredMessage>> {
        match &*self.state()? {
            ClientState::Active { session } => {
                let capped = limit.min(MAX_PAGE_MESSAGES) as usize;
                let all = session.messages();
                let start = (offset as usize).min(all.len());
                let end = start.saturating_add(capped).min(all.len());
                Ok(all[start..end].iter().map(to_stored).collect())
            }
            ClientState::Pending { .. } => Err(WasmError::WrongState),
            ClientState::Closed => Err(WasmError::Closed),
        }
    }

    /// Erase this device's visible message log when the user deletes the conversation. Protocol
    /// state (ratchet, replay watermark, outbox, secret records) is retained, so later messages
    /// still decrypt and a replayed secret still cannot be re-revealed. Local only — nothing is
    /// sent, and the peer's copy is untouched.
    #[wasm_bindgen(js_name = clearVisibleHistory)]
    pub fn clear_visible_history(&self) -> Result<()> {
        let mut g = self.state()?;
        active_mut(&mut g)?
            .clear_visible_history()
            .map_err(map_durable)
    }

    pub fn epoch(&self) -> Result<u64> {
        match &*self.state()? {
            ClientState::Active { session } => Ok(session.epoch()),
            ClientState::Pending { .. } => Err(WasmError::WrongState),
            ClientState::Closed => Err(WasmError::Closed),
        }
    }

    /// 0 = pre-versioning; a pending client also reports 0.
    #[wasm_bindgen(js_name = storageFormatVersion)]
    pub fn storage_format_version(&self) -> Result<u32> {
        match &*self.state()? {
            ClientState::Active { session } => Ok(session.format_version()),
            ClientState::Pending { .. } => Ok(0),
            ClientState::Closed => Err(WasmError::Closed),
        }
    }

    /// Idempotent. Durable state is untouched — reopen with `open`.
    pub fn close(&self) {
        if let Ok(mut g) = self.inner.try_borrow_mut() {
            *g = ClientState::Closed;
        }
    }
}

// Non-exported helpers.
impl MlsClient {
    fn active(session: DurableSession<WasmJournal>) -> Self {
        MlsClient {
            inner: RefCell::new(ClientState::Active {
                session: Box::new(session),
            }),
        }
    }

    /// A failed borrow means JS re-entered a client that is mid-call (e.g. a storage host that
    /// synchronously calls back in). Fail closed rather than panic on `borrow_mut`, which would
    /// abort the whole wasm instance.
    fn state(&self) -> Result<RefMut<'_, ClientState>> {
        self.inner.try_borrow_mut().map_err(|_| WasmError::Internal)
    }

    fn process(
        &self,
        envelope_id: u64,
        ciphertext: Vec<u8>,
        self_group: bool,
    ) -> Result<InboundResult> {
        bound(ciphertext.len(), MAX_ENVELOPE_LEN)?;
        // An unknown app-envelope version is rejected, never fed to MLS as-is.
        let payload = mls_core::envelope::unwrap(&ciphertext)
            .map_err(|_| WasmError::InvalidMessage)?
            .to_vec();
        let mut g = self.state()?;
        let session = active_mut(&mut g)?;
        let outcome = if self_group {
            session.process_self_inbound(envelope_id, &payload)
        } else {
            session.process_inbound(envelope_id, &payload)
        }
        .map_err(map_durable_input)?;
        Ok(to_inbound(outcome))
    }
}

// ---- helpers ------------------------------------------------------------------------------------

fn bound(len: usize, max: usize) -> Result<()> {
    if len > max {
        Err(WasmError::InputTooLarge)
    } else {
        Ok(())
    }
}

fn host_journal(host: JournalHost, at_rest_key: &[u8]) -> Result<WasmJournal> {
    let key: [u8; 32] = at_rest_key
        .try_into()
        .map_err(|_| WasmError::BadKeyLength)?;
    Ok(WasmJournal::Host(Box::new(HostJournal::new(host, &key))))
}

fn active_mut(g: &mut ClientState) -> Result<&mut DurableSession<WasmJournal>> {
    match g {
        ClientState::Active { session } => Ok(&mut **session),
        ClientState::Pending { .. } => Err(WasmError::WrongState),
        ClientState::Closed => Err(WasmError::Closed),
    }
}

/// Convert a JS array of `Uint8Array` into owned byte vectors, rejecting anything else rather than
/// coercing — a silently-coerced element would change which members a manifest check compares.
fn byte_arrays(array: &js_sys::Array) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(array.length() as usize);
    for value in array.iter() {
        if !value.is_instance_of::<js_sys::Uint8Array>() {
            return Err(WasmError::InvalidMessage);
        }
        out.push(js_sys::Uint8Array::unchecked_from_js(value).to_vec());
    }
    Ok(out)
}

fn to_stored(m: &CoreMessage) -> StoredMessage {
    StoredMessage {
        local_id: m.local_id,
        outbound: m.direction == CoreDirection::Outbound,
        plaintext: m.plaintext.clone(),
        envelope_id: m.envelope_id,
        secret_id: m.secret_id.map(|id| id.to_vec()),
    }
}

fn to_inbound(outcome: InboundOutcome) -> InboundResult {
    let mut r = InboundResult {
        kind: InboundKind::StateAdvanced,
        plaintext: None,
        secret_id: None,
        key_r: None,
        count: None,
    };
    match outcome {
        InboundOutcome::Application(pt) => {
            r.kind = InboundKind::Application;
            r.plaintext = Some(pt);
        }
        InboundOutcome::StateAdvanced => r.kind = InboundKind::StateAdvanced,
        InboundOutcome::Duplicate => r.kind = InboundKind::Duplicate,
        InboundOutcome::SecretSealed { secret_id } => {
            r.kind = InboundKind::SecretSealed;
            r.secret_id = Some(secret_id.to_vec());
        }
        InboundOutcome::SecretConsumedRemotely { secret_id } => {
            r.kind = InboundKind::SecretConsumedRemotely;
            r.secret_id = Some(secret_id.to_vec());
        }
        InboundOutcome::DeliveryKeyGranted { key_r } => {
            r.kind = InboundKind::DeliveryKeyGranted;
            r.key_r = Some(key_r.to_vec());
        }
        InboundOutcome::HistorySynced { count } => {
            r.kind = InboundKind::HistorySynced;
            r.count = Some(count);
        }
    }
    r
}

/// Fail-closed on any length other than 16.
fn secret_id_arg(bytes: &[u8]) -> Result<[u8; SECRET_ID_LEN]> {
    bytes.try_into().map_err(|_| WasmError::InvalidMessage)
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

/// Local paths: a fault here is ours.
fn map_durable(e: DurableError) -> WasmError {
    match e {
        DurableError::NoSession => WasmError::NoSession,
        DurableError::UnknownLocal => WasmError::NotFound,
        DurableError::Journal => WasmError::Journal,
        DurableError::SelfGroup => WasmError::WrongState,
        DurableError::Mls | DurableError::Codec => WasmError::Internal,
    }
}

/// Inbound paths: bad bytes are caller-supplied.
fn map_durable_input(e: DurableError) -> WasmError {
    match e {
        DurableError::NoSession => WasmError::NoSession,
        DurableError::UnknownLocal => WasmError::NotFound,
        DurableError::Journal => WasmError::Journal,
        DurableError::SelfGroup => WasmError::WrongState,
        DurableError::Mls | DurableError::Codec => WasmError::InvalidMessage,
    }
}

fn map_mls_local(e: MlsError) -> WasmError {
    match e {
        MlsError::MemberNotFound => WasmError::NotFound,
        MlsError::Codec | MlsError::Lib(_) | MlsError::ManifestMismatch => WasmError::Internal,
    }
}

fn map_mls_input(e: MlsError) -> WasmError {
    match e {
        MlsError::MemberNotFound => WasmError::NotFound,
        MlsError::Codec | MlsError::Lib(_) | MlsError::ManifestMismatch => {
            WasmError::InvalidMessage
        }
    }
}
