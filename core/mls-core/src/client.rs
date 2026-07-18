//! Narrow, FFI-ready client façade over the MLS primitives (Gate 2, ADR-0007).
//!
//! The iOS/Android client never holds MLS objects or secrets: it holds **opaque `u64` handles**
//! and passes/receives only `Vec<u8>` and small typed values. This is the surface a UniFFI (or C
//! ABI) layer wraps — kept deliberately small so it is easy to fuzz.
//!
//! Boundary guarantees:
//! - **`&self` methods** over interior mutability (a `Mutex`), so the generated FFI object exposes
//!   `&self` calls (ADR-0007 item 1) — Swift/Kotlin need no `&mut`.
//! - **Bounded inputs:** every byte input is length-checked against an explicit maximum *before*
//!   any parsing/allocation, so an oversized buffer is rejected, not processed.
//! - **Typed, stable, redacted errors:** hostile or malformed input yields [`ClientError`], never
//!   a panic and never leaked library internals. Every public entry point is wrapped in
//!   `catch_unwind`, so even an unexpected panic deep in a dependency becomes `Internal` instead
//!   of unwinding across the FFI boundary (which would be undefined behavior).
//! - **No secrets cross:** only ciphertext/opaque bytes and handles leave this type.

use std::collections::HashMap;
use std::panic::catch_unwind;
use std::sync::Mutex;

use crate::{Incoming, Member, MlsError};

/// Explicit input bounds. Defense-in-depth at the trust boundary: reject before parsing. Envelope
/// and welcome bounds match the relay's 256 KiB body cap (contracts/API.md).
pub const MAX_IDENTITY_LEN: usize = 256;
pub const MAX_KEY_PACKAGE_LEN: usize = 64 * 1024;
pub const MAX_WELCOME_LEN: usize = 256 * 1024;
pub const MAX_ENVELOPE_LEN: usize = 256 * 1024;
pub const MAX_PLAINTEXT_LEN: usize = 64 * 1024;

/// Stable, redacted error surface for the FFI boundary. Intentionally coarse: it must not leak
/// which internal step failed to a potentially hostile caller.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ClientError {
    /// A byte input exceeded its documented maximum length.
    #[error("input too large")]
    InputTooLarge,
    /// No identity/conversation exists for the supplied handle.
    #[error("unknown handle")]
    NotFound,
    /// The supplied bytes were not a valid/processable MLS message for this state.
    #[error("invalid message")]
    InvalidMessage,
    /// An unexpected internal fault (also the fail-safe result of a caught panic or poisoned lock).
    #[error("internal error")]
    Internal,
}

/// Result of adding a member: opaque bytes for the caller to route. `commit` fans out to existing
/// members; `welcome` goes to the joining device.
pub struct AddOutcome {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

struct State {
    next_handle: u64,
    members: HashMap<u64, Member>,
    conversations: HashMap<u64, crate::Conversation>,
}

/// The handle registry. One instance per app process.
pub struct ClientApi {
    inner: Mutex<State>,
}

impl Default for ClientApi {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientApi {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(State {
                next_handle: 1,
                members: HashMap::new(),
                conversations: HashMap::new(),
            }),
        }
    }

    /// Create a fresh local identity (its signature key + credential + key store live in Rust).
    /// Returns an opaque identity handle.
    pub fn create_identity(&self, identity: &[u8]) -> Result<u64, ClientError> {
        catch(|| {
            check(identity.len(), MAX_IDENTITY_LEN)?;
            let member = Member::new(identity).map_err(map_local)?;
            let mut st = self.lock()?;
            let handle = st.take_handle();
            st.members.insert(handle, member);
            Ok(handle)
        })
    }

    /// Serialize a fresh key package ("prekey") for `identity` to publish to the directory.
    pub fn key_package(&self, identity: u64) -> Result<Vec<u8>, ClientError> {
        catch(|| {
            let st = self.lock()?;
            let member = st.members.get(&identity).ok_or(ClientError::NotFound)?;
            member.key_package_bytes().map_err(map_local)
        })
    }

    /// Create a new conversation (MLS group) owned by `identity`. Returns a conversation handle.
    pub fn create_group(&self, identity: u64) -> Result<u64, ClientError> {
        catch(|| {
            let mut st = self.lock()?;
            let conversation = {
                let member = st.members.get(&identity).ok_or(ClientError::NotFound)?;
                member.create_group().map_err(map_local)?
            };
            let handle = st.take_handle();
            st.conversations.insert(handle, conversation);
            Ok(handle)
        })
    }

    /// Join a conversation from a serialized Welcome. Returns a conversation handle.
    pub fn join_from_welcome(&self, identity: u64, welcome: &[u8]) -> Result<u64, ClientError> {
        catch(|| {
            check(welcome.len(), MAX_WELCOME_LEN)?;
            let mut st = self.lock()?;
            let conversation = {
                let member = st.members.get(&identity).ok_or(ClientError::NotFound)?;
                member.join_from_welcome(welcome).map_err(map_input)?
            };
            let handle = st.take_handle();
            st.conversations.insert(handle, conversation);
            Ok(handle)
        })
    }

    /// Add a member (by their key-package bytes) to a conversation. Returns commit + welcome.
    pub fn add_member(
        &self,
        conversation: u64,
        identity: u64,
        key_package: &[u8],
    ) -> Result<AddOutcome, ClientError> {
        catch(|| {
            check(key_package.len(), MAX_KEY_PACKAGE_LEN)?;
            let mut st = self.lock()?;
            let st = &mut *st;
            let conv = st
                .conversations
                .get_mut(&conversation)
                .ok_or(ClientError::NotFound)?;
            let member = st.members.get(&identity).ok_or(ClientError::NotFound)?;
            let result = conv.add_member(member, key_package).map_err(map_input)?;
            Ok(AddOutcome {
                commit: result.commit,
                welcome: result.welcome,
            })
        })
    }

    /// Encrypt an application message. Returns an opaque envelope.
    pub fn encrypt(
        &self,
        conversation: u64,
        identity: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        catch(|| {
            check(plaintext.len(), MAX_PLAINTEXT_LEN)?;
            let mut st = self.lock()?;
            let st = &mut *st;
            let conv = st
                .conversations
                .get_mut(&conversation)
                .ok_or(ClientError::NotFound)?;
            let member = st.members.get(&identity).ok_or(ClientError::NotFound)?;
            conv.encrypt(member, plaintext).map_err(map_local)
        })
    }

    /// Process an inbound envelope: application plaintext, or a state-advancing control message.
    pub fn process(
        &self,
        conversation: u64,
        identity: u64,
        envelope: &[u8],
    ) -> Result<Received, ClientError> {
        catch(|| {
            check(envelope.len(), MAX_ENVELOPE_LEN)?;
            let mut st = self.lock()?;
            let st = &mut *st;
            let conv = st
                .conversations
                .get_mut(&conversation)
                .ok_or(ClientError::NotFound)?;
            let member = st.members.get(&identity).ok_or(ClientError::NotFound)?;
            match conv.process(member, envelope).map_err(map_input)? {
                Incoming::Application(bytes) => Ok(Received::Application(bytes)),
                Incoming::StateAdvanced => Ok(Received::StateAdvanced),
            }
        })
    }

    /// Current epoch of a conversation (advances on every membership change).
    pub fn epoch(&self, conversation: u64) -> Result<u64, ClientError> {
        catch(|| {
            let st = self.lock()?;
            let conv = st
                .conversations
                .get(&conversation)
                .ok_or(ClientError::NotFound)?;
            Ok(conv.epoch())
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>, ClientError> {
        // A poisoned lock (a prior panic) fails safe rather than propagating the panic.
        self.inner.lock().map_err(|_| ClientError::Internal)
    }
}

impl State {
    fn take_handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }
}

/// FFI-friendly result of [`ClientApi::process`].
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    /// Decrypted application plaintext.
    Application(Vec<u8>),
    /// A membership/commit message advanced group state (no user-visible content).
    StateAdvanced,
}

fn check(len: usize, max: usize) -> Result<(), ClientError> {
    if len > max {
        Err(ClientError::InputTooLarge)
    } else {
        Ok(())
    }
}

/// Convert a panic (unwound as `Box<dyn Any>`) into a typed `Internal` error. Panics must never
/// cross the FFI boundary — that is undefined behavior — so every entry point is wrapped.
fn catch<T>(
    f: impl FnOnce() -> Result<T, ClientError> + std::panic::UnwindSafe,
) -> Result<T, ClientError> {
    catch_unwind(f).unwrap_or(Err(ClientError::Internal))
}

/// Map errors from **inbound-processing** paths: malformed/unverifiable input is caller-supplied,
/// so it is reported as `InvalidMessage` (redacted — no library detail). A manifest mismatch is
/// also hostile input at this boundary.
fn map_input(e: MlsError) -> ClientError {
    match e {
        MlsError::MemberNotFound => ClientError::NotFound,
        MlsError::Codec | MlsError::Lib(_) | MlsError::ManifestMismatch => {
            ClientError::InvalidMessage
        }
    }
}

/// Map errors from **local-generation** paths (create key package, encrypt): a failure here is our
/// own fault, not bad input, so it is `Internal`.
fn map_local(e: MlsError) -> ClientError {
    match e {
        MlsError::MemberNotFound => ClientError::NotFound,
        MlsError::Codec | MlsError::Lib(_) | MlsError::ManifestMismatch => ClientError::Internal,
    }
}
