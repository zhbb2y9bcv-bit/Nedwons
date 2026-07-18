# ADR-0007: On-device MLS via a UniFFI binding of `mls-core`

- **Status:** Accepted (plan) — not yet implemented
- **Date:** 2026-07-17
- **Deciders:** crypto integrator, iOS lead

## Context

`core/mls-core` (ADR-0001) is the Rust MLS integration and is fully tested on the host
(`cargo test`). The iOS app needs to call it on device to encrypt/decrypt messages. The
canonical transcript layer already crosses to Swift byte-identically (SentinelKit), but MLS
group state is complex and must not be reimplemented in Swift — that would be a second
crypto implementation, which the mission forbids.

## Decision

Expose `mls-core` to Swift through **UniFFI**, producing a Swift package + an `xcframework`
the app links. The Rust core remains the single source of MLS logic; Swift is a thin caller.

Required adaptations (small, tracked as work items):

1. **Interior mutability.** UniFFI objects expose `&self` methods. `Conversation`'s current
   `&mut self` methods become `&self` over a `Mutex<MlsGroup>` (or the object is wrapped in
   `Arc<Mutex<…>>`). The public method set stays the same.
2. **Error type.** `MlsError` maps to a UniFFI `[Error] enum` so Swift sees typed throws.
3. **Byte-oriented API.** The FFI surface passes `Vec<u8>` / `Data` (key packages, welcomes,
   envelopes, plaintext) — no complex types cross the boundary, keeping it easy to fuzz.
4. **Provider persistence.** The in-memory `OpenMlsRustCrypto` store used in tests is
   replaced on device by a persistent `StorageProvider` whose secrets live under the local
   at-rest key hierarchy (Keychain-wrapped, CRYPTOGRAPHY.md §5). This is the main non-trivial
   piece and gets its own tests.

## Build/packaging

- Add `uniffi` with the `build`/`bindgen` features; a `uniffi::setup_scaffolding!()` or UDL.
- Cross-compile the staticlib for `aarch64-apple-ios`, `aarch64-apple-ios-sim`, and (for
  host tests) the Mac arch; assemble an `xcframework` via `xcodebuild -create-xcframework`.
- Generate Swift bindings with `uniffi-bindgen`; ship as a local SwiftPM target the app links
  alongside `SentinelKit`.

## Consequences

**Positive:** one audited MLS implementation across host tests and device; a small, fuzzable
FFI boundary (ADR-0004 consequence); no Swift crypto to review.

**Negative / risks:**
- The FFI boundary must be **memory-safe at the API and fuzzed** (mission requirement). Add
  `cargo fuzz` targets for the deserialize/process entry points before shipping.
- Cross-compilation toolchain (`rustup target add aarch64-apple-ios …`) and the xcframework
  assembly are not exercised in the current environment (no iOS build here, R-101).
- The persistent storage provider is security-sensitive (holds ratchet secrets) and is a
  launch-blocking implementation item.

## Status

Planned. The host-side MLS (`mls-core`) and the auth client transport (SentinelKit's
`SentinelClient`, verified against the live backend) are done; this binding is the remaining
bridge to run E2EE on the device, landed together with the Xcode app target (Section 3 / R-101).

### Update 2026-07-17 — the narrow Rust-owned API layer now exists (`mls_core::client`)

The FFI-shaped surface the binding will wrap is implemented and tested headlessly, so the
UniFFI step becomes packaging rather than design:

- **`ClientApi`** exposes **`&self`** methods over a `Mutex` (satisfies item 1 — no `&mut` at the
  boundary), keyed by **opaque `u64` handles**; no MLS objects or secrets cross to the caller.
- **Byte-oriented + bounded:** every input is length-checked (`MAX_*` constants) before parsing.
- **Typed, stable, redacted errors** (`ClientError`), and **every entry point is wrapped in
  `catch_unwind`** so a panic can never unwind across the FFI boundary (UB) — it becomes `Internal`.
- Tests (`tests/client_api.rs`): deterministic two-party round trip through handles, oversized-input
  rejection, unknown-handle handling, and a malformed/near-miss **corpus that must never panic**.

**Still required before shipping on device (blocked on the iOS toolchain — R-101):** the `uniffi`
scaffolding/UDL and generated Swift bindings; cross-compiled `aarch64-apple-ios(-sim)` staticlib +
`xcframework`; the **persistent `StorageProvider`** (ratchet secrets under the at-rest key
hierarchy — the security-sensitive piece); and a **`cargo fuzz`** target on `process`/`join`/
`add_member` to harden the corpus test into continuous fuzzing.

---

## Update 2026-07-17 (v2) — concrete FFI contract (the design this arc implements)

- **Status:** Accepted — **implemented** for the host + simulator/device *packaging*; **on-device
  execution** (running the slices on a physical iPhone, App Attest, Enclave-wrapped at-rest key)
  remains `BLOCKED` (R-101), not waived.

This section supersedes the *shape* sketched above with the exact, frozen contract. It was written
**after** a throwaway toolchain spike proved the mechanism end to end on this machine (a UniFFI
`Object` with an interior-`Mutex`, a bounded byte-in/byte-out method, and a typed error was called
from Swift 6.3.3 against the Rust dylib), so the versions and commands below are ones that actually
ran here — not aspirations.

### Toolchain (pinned)

| Item | Decision | Rationale |
|------|----------|-----------|
| UniFFI version | **`0.29`** (resolved `0.29.5`) | Latest 0.29 line; compiles under Rust 1.97.1; its generated Swift compiles clean under Swift 6.3.3 with `-swift-version 6`. Pin the minor; re-review on bump. |
| Binding mode | **proc-macro** (`uniffi::setup_scaffolding!()` + `#[uniffi::export]`, `#[derive(uniffi::Object/Record/Enum/Error)]`) | One source of truth in Rust; **no UDL file to drift** out of sync with the code. UDL is rejected precisely because it duplicates the surface. |
| Bindgen | **library mode** via an in-crate `uniffi-bindgen` bin (`cargo run --bin uniffi-bindgen generate --library <dylib> --language swift`) | The generator introspects the built library, so bindings cannot describe a surface the library does not export. Avoids a separately-versioned external `uniffi-bindgen`. |
| Min deployment target | **iOS 17 / macOS 14** | Matches `SentinelKit/Package.swift`. |
| Architectures | host `arm64-apple-macos` (host tests) · `aarch64-apple-ios` (device) · `aarch64-apple-ios-sim` (simulator, Apple Silicon). `x86_64-apple-ios` (Intel sim) is **optional** and off by default. | Apple-Silicon-first; the host slice is what the fast `swift test` integration loop links. |
| Swift language mode | generated bindings compile under **`-swift-version 6`** | Proven in the spike. UniFFI's own docs call Swift-6 support partial, so this is asserted by a real compile, and warnings are **not** broadly suppressed to hide it. |

### The exported surface — an **object per client**, not a handle registry

The prior `mls_core::client::ClientApi` used opaque `u64` handles in a process-wide `HashMap`. The
FFI object model is **strictly safer**, so the binding uses it and `ClientApi` stays an internal
host-test helper (not exported):

- The exported type is **`MlsClient`** — a `uniffi::Object`. Swift holds an **`Arc<MlsClient>`**;
  its lifetime is ARC-managed. **There is no shared `u64` registry**, which *eliminates* the entire
  class of stale-handle, ABA-reuse, cross-client-handle, and registry-exhaustion bugs by
  construction — you cannot forge or collide a reference that doesn't exist.
- **Explicit invalidation:** `close()` transitions the object to a `Closed` state and drops the MLS
  session; every subsequent call returns `MlsClientError::Closed`. `close()` is **idempotent**
  (double-close is a typed no-op, never a panic).
- **Single-writer serialization:** all state is behind **one `Mutex<ClientState>` per object**;
  every method takes `&self` and locks. Because a given MLS group lives inside exactly one
  `MlsClient`, **concurrent mutation of one group is impossible**; independent clients run fully in
  parallel. A poisoned lock (prior panic) fails closed to `Internal`.
- **Scope of the slice:** one `MlsClient` owns **one identity and one conversation**. Multiple
  conversations per identity (sharing one signature key / provider) is deliberately out of scope
  here and noted as future work — it must *not* be bolted on by creating a second persistence path.

`ClientState` is a small state machine: `Pending { member }` (identity created, no group yet — can
publish a key package and then create/join) → `Active { session: DurableSession<…> }` → `Closed`.

### One persistence authority

The **only** durable store is the existing crash-safe `durable::DurableSession` + `Journal`
(`FileJournal` on device: one AES-256-GCM blob = MLS-store snapshot **+** message/queue metadata,
written temp-file→fsync→rename). The FFI object **wraps** a `DurableSession`; it introduces **no**
second store and does **not** persist through the OpenMLS `StorageProvider` independently — that
would be the "conflicting durable-blob and StorageProvider state" the mission forbids. To keep the
`uniffi::Object` non-generic while still allowing an in-memory journal for crash-injection tests, a
concrete `enum JournalKind { File(FileJournal), Memory(InMemoryJournal) }` implements `Journal`; the
FFI constructors build the `File` variant from a caller-supplied path + 32-byte at-rest key.

- **Transaction boundary:** each mutating method commits the blob **before returning**. Per the
  inherited recovery contract, any method that returns `Err` may have advanced in-memory MLS state
  without committing; the caller **must** drop the object and `open()` again (which reloads the last
  durable state). This is stated in the Swift docs and tested.
- **Storage schema version:** the persisted `Meta` gains a `#[serde(default)] version` field so
  older blobs load and future changes are detectable; `capabilities()` reports it.

### Byte-oriented, bounded, typed

- Every input is length-checked against an explicit maximum **before** parsing (reused from
  `client`): identity ≤ 256 B, key package ≤ 64 KiB, welcome ≤ 256 KiB, envelope ≤ 256 KiB,
  plaintext ≤ 64 KiB; the at-rest key must be **exactly 32 bytes**.
- Only bytes and small typed values cross: `Vec<u8>` (key packages, welcomes, envelopes,
  ciphertext, decrypted plaintext), `u64` (epoch, local ids), records (`AddOutcome`,
  `StoredMessage`, `Capabilities`), enums (`InboundResult`, `Direction`). **No OpenMLS object, no
  provider/store bytes, no ratchet secret, and no signature private key is ever a parameter or a
  return value.** There is deliberately no `export_store`-style call on the FFI surface. Decrypted
  *application plaintext* does cross (that is the whole point — Swift renders it); that is not a
  secret in the key-substitution sense.
- **Errors** are a coarse, stable `MlsClientError` (`InputTooLarge`, `WrongState`, `NotFound`,
  `InvalidMessage`, `Journal`, `Closed`, `Internal`). Messages are variant-only and **redacted** —
  no library internals, key bytes, plaintext, or path leak. A test asserts redaction.
- **No panic crosses the ABI:** every entry point is wrapped in `catch_unwind` mapping to
  `Internal` (defense in depth on top of UniFFI's own catch), so a panic deep in a dependency can
  never unwind across the C ABI (UB).
- **Concurrency/cancellation:** the surface is **synchronous and non-blocking** — CPU-bound MLS work
  plus a bounded local-file commit; no network, no async, no unbounded wait crosses FFI in this
  slice. (Network I/O stays in Swift's `SentinelClient`.)

### Version compatibility

`binding_version()` (the Rust `mls-core` version + UniFFI contract tag) and `capabilities()`
(protocol = MLS 1.0 / RFC 9420, the single ciphersuite, the input maxima, the storage schema
version) let Swift assert it is linked against a compatible core and refuse on mismatch. A test
drives this.

### Test matrix (what runs where)

| Tier | Runs here? | What it proves |
|------|-----------|----------------|
| **Rust unit/integration** (`cargo test`) | ✅ host | MLS correctness, durable crash-safety, FFI-object semantics, adversarial corpus. |
| **Swift ↔ Rust host integration** (SwiftPM test linking the host static lib) | ✅ host (macOS) | The generated bindings drive the real core: two `MlsClient`s exchange real MLS messages, persist, relaunch, retry-without-re-encrypt, and reject hostile input — **no simulator needed**. This is the primary bridge proof. |
| **Simulator slice** (`aarch64-apple-ios-sim`) | ✅ compile + link into xcframework | The device-family library builds and packages. Running it in a simulator needs a test-host app (Xcode project, R-101). |
| **Device slice** (`aarch64-apple-ios`) | ⚙️ **compile-only** | Cross-compiles + packages. **Cannot run** — no physical device (R-101); App Attest and the Enclave-wrapped at-rest key are device-only. |

### Consequences

Positive: one audited MLS implementation from host tests to device; a small, fuzzable, ARC-safe FFI
boundary with no handle registry to exploit; a single persistence authority. Negative/residual:
UniFFI 0.29 pin must be re-reviewed on upgrade; the persistent `StorageProvider`-vs-blob decision is
settled in favor of the blob for now (a native `StorageProvider` remains possible later but must not
create a second authority); on-device execution stays blocked (R-101).
