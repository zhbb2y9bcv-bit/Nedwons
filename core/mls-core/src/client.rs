//! Narrow, FFI-ready client façade over the MLS primitives (Gate 2, ADR-0007). Kept small so it is
//! easy to fuzz; the client holds only opaque `u64` handles, never MLS objects or secrets.
//!
//! Boundary guarantees:
//! - **`&self` methods** over a `Mutex`, so the generated FFI object needs no `&mut` (ADR-0007).
//! - **Bounded inputs:** length-checked *before* any parsing or allocation.
//! - **Typed, redacted errors:** never a panic, never leaked library internals. Every entry point
//!   is `catch_unwind`-wrapped, since unwinding across the FFI boundary is undefined behavior.
//! - **No secrets cross:** only opaque bytes and handles leave this type.

use std::collections::HashMap;
use std::panic::catch_unwind;
use std::sync::Mutex;

use crate::{Incoming, Member, MlsError};

/// Reject before parsing. Envelope/welcome bounds match the relay's 256 KiB body cap
/// (contracts/API.md).
pub const MAX_IDENTITY_LEN: usize = 256;
pub const MAX_KEY_PACKAGE_LEN: usize = 64 * 1024;
pub const MAX_WELCOME_LEN: usize = 256 * 1024;
pub const MAX_ENVELOPE_LEN: usize = 256 * 1024;
pub const MAX_PLAINTEXT_LEN: usize = 64 * 1024;

/// Intentionally coarse: must not leak which internal step failed to a hostile caller.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ClientError {
    #[error("input too large")]
    InputTooLarge,
    #[error("unknown handle")]
    NotFound,
    #[error("invalid message")]
    InvalidMessage,
    /// Also the fail-safe result of a caught panic or poisoned lock.
    #[error("internal error")]
    Internal,
}

/// Opaque bytes for the caller to route: `commit` to existing members, `welcome` to the joiner.
pub struct AddOutcome {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

struct State {
    next_handle: u64,
    members: HashMap<u64, Member>,
    conversations: HashMap<u64, crate::Conversation>,
}

/// One instance per app process.
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

    /// Signature key, credential and key store stay in Rust; returns an opaque handle.
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

    /// A fresh prekey for `identity` to publish to the directory.
    pub fn key_package(&self, identity: u64) -> Result<Vec<u8>, ClientError> {
        catch(|| {
            let st = self.lock()?;
            let member = st.members.get(&identity).ok_or(ClientError::NotFound)?;
            member.key_package_bytes().map_err(map_local)
        })
    }

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

    /// Returns an opaque envelope.
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
        // A poisoned lock fails safe rather than propagating the prior panic.
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

#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    Application(Vec<u8>),
    /// A commit advanced group state; no user-visible content.
    StateAdvanced,
}

fn check(len: usize, max: usize) -> Result<(), ClientError> {
    if len > max {
        Err(ClientError::InputTooLarge)
    } else {
        Ok(())
    }
}

/// Panics must never cross the FFI boundary (undefined behavior), so every entry point is wrapped.
fn catch<T>(
    f: impl FnOnce() -> Result<T, ClientError> + std::panic::UnwindSafe,
) -> Result<T, ClientError> {
    catch_unwind(f).unwrap_or(Err(ClientError::Internal))
}

/// Inbound paths: the bytes are caller-supplied, so failures (including a manifest mismatch) are
/// hostile input, reported redacted as `InvalidMessage`.
fn map_input(e: MlsError) -> ClientError {
    match e {
        MlsError::MemberNotFound => ClientError::NotFound,
        MlsError::Codec | MlsError::Lib(_) | MlsError::ManifestMismatch => {
            ClientError::InvalidMessage
        }
    }
}

/// Local-generation paths: a failure is our own fault, not bad input, so it is `Internal`.
fn map_local(e: MlsError) -> ClientError {
    match e {
        MlsError::MemberNotFound => ClientError::NotFound,
        MlsError::Codec | MlsError::Lib(_) | MlsError::ManifestMismatch => ClientError::Internal,
    }
}
