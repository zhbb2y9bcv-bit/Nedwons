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
