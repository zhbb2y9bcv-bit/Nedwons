//! Browser persistence for the durable session (ADR-0017).
//!
//! ## Why the storage itself lives in JavaScript
//!
//! `mls_core::durable::Journal` is a **synchronous** trait — `commit` must not return until the blob
//! is durable, because the whole module exists to guarantee the MLS ratchet and the message log
//! advance as one untearable unit. **IndexedDB has no synchronous API**, so it cannot back this
//! trait: buffering in memory and flushing asynchronously would make `commit` return `Ok` before the
//! write landed, which is precisely the invariant violation the design forbids.
//!
//! The browser primitive that *is* synchronous is OPFS
//! `FileSystemSyncAccessHandle` (`read`/`write`/`flush`/`truncate`), available only inside a Web
//! Worker. Rather than bind OPFS here, this module defines a narrow **host seam**: the embedder
//! passes a JS object with synchronous `commit(bytes)` / `load()` methods, and the worker implements
//! those over OPFS. That mirrors ADR-0006's storage-seam philosophy — the protocol core stays
//! storage-agnostic, and the platform specifics live where their APIs are natural.
//!
//! ## What stays in Rust regardless of host
//!
//! **At-rest sealing.** The host only ever sees ciphertext. The layout is byte-identical to
//! `mls_core::durable::FileJournal` — `nonce (12 bytes) ‖ AES-256-GCM ciphertext`, fresh random
//! nonce per write — so a blob written by the web client and one written on iOS are the same format.
//! A malicious or buggy host can lose or corrupt bytes, but cannot read the ratchet state or forge a
//! blob: GCM authentication fails closed.
//!
//! ## What the host MUST provide (the atomicity contract)
//!
//! `commit` has to be all-or-nothing. OPFS has no atomic `rename`, so the temp-file+rename trick
//! `FileJournal` uses does not transfer. The documented host strategy is **two slots plus a
//! generation counter**: write the blob to the *inactive* slot, `flush()`, then write the small
//! generation header, `flush()`; on load, take the slot with the highest generation that
//! authenticates. Because the blob is already sealed, **the GCM tag is the torn-write detector** — a
//! partially written slot simply fails to decrypt and the reader falls back to the previous one.
//!
//! A useful side effect: `createSyncAccessHandle()` is **exclusive**, so a second tab cannot acquire
//! the journal. The single-writer invariant is enforced by the platform rather than by convention.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use mls_core::durable::{DurableError, InMemoryJournal, Journal};
use rand_core::{OsRng, RngCore};
use wasm_bindgen::prelude::*;

/// Must match `FileJournal`'s nonce width, or blobs stop being cross-platform.
const NONCE_LEN: usize = 12;

#[wasm_bindgen]
extern "C" {
    /// The embedder-supplied storage host. Both methods MUST be synchronous — returning a Promise
    /// silently breaks the durability contract, because this side cannot await it.
    ///
    /// `commit(bytes)` must not resolve until the bytes are durable and must be all-or-nothing.
    /// `load()` returns the last committed `Uint8Array`, or `null`/`undefined` if none.
    #[wasm_bindgen(js_name = JournalHost, typescript_type = "JournalHost")]
    pub type JournalHost;

    #[wasm_bindgen(method, catch, js_name = commit)]
    fn commit(this: &JournalHost, blob: &[u8]) -> Result<(), JsValue>;

    #[wasm_bindgen(method, catch, js_name = load)]
    fn load(this: &JournalHost) -> Result<JsValue, JsValue>;
}

/// Seals blobs and delegates raw byte storage to a JS host.
pub struct HostJournal {
    host: JournalHost,
    cipher: Aes256Gcm,
}

impl HostJournal {
    /// `at_rest_key` comes from the caller's key hierarchy — never hard-coded, never sent to the
    /// host.
    pub fn new(host: JournalHost, key: &[u8; 32]) -> Self {
        // 32 bytes is always a valid AES-256 key length.
        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 key is 32 bytes");
        Self { host, cipher }
    }
}

impl Journal for HostJournal {
    fn commit(&mut self, blob: &[u8]) -> Result<(), DurableError> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(&nonce.into(), blob)
            .map_err(|_| DurableError::Journal)?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        // A host exception (quota exceeded, evicted handle, closed worker) becomes a typed journal
        // error, never a panic — a panic would abort the whole wasm instance (see lib.rs).
        self.host.commit(&out).map_err(|_| DurableError::Journal)
    }

    fn load(&self) -> Result<Option<Vec<u8>>, DurableError> {
        let value = self.host.load().map_err(|_| DurableError::Journal)?;
        if value.is_null() || value.is_undefined() {
            return Ok(None); // no session yet — a first run, not a failure
        }
        let data = js_sys::Uint8Array::new(&value).to_vec();
        if data.len() < NONCE_LEN {
            return Err(DurableError::Journal);
        }
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().map_err(|_| DurableError::Journal)?;
        let plaintext = self
            .cipher
            .decrypt(&nonce.into(), ciphertext)
            .map_err(|_| DurableError::Journal)?; // fails closed on tamper / wrong key / torn write
        Ok(Some(plaintext))
    }
}

/// `DurableSession<J>` is generic but a `#[wasm_bindgen]` type cannot be, so — exactly as `mls-ffi`
/// does with `JournalKind` — the backend is picked once at construction behind one concrete type.
/// There is deliberately no file variant: `mls-core`'s `FileJournal` compiles for wasm32 and then
/// fails at runtime on every call, so exposing it would only offer a trap.
pub enum WasmJournal {
    // Boxed: `HostJournal` carries the AES key schedule, far larger than the `Memory` variant.
    Host(Box<HostJournal>),
    /// Volatile, for tests and ephemeral sessions. **Nothing survives a reload** — never a default.
    Memory(InMemoryJournal),
}

impl Journal for WasmJournal {
    fn commit(&mut self, blob: &[u8]) -> Result<(), DurableError> {
        match self {
            WasmJournal::Host(j) => j.commit(blob),
            WasmJournal::Memory(j) => j.commit(blob),
        }
    }

    fn load(&self) -> Result<Option<Vec<u8>>, DurableError> {
        match self {
            WasmJournal::Host(j) => j.load(),
            WasmJournal::Memory(j) => j.load(),
        }
    }
}
