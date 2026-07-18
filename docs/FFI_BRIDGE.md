# The MLS FFI bridge (Rust ↔ Swift)

How the iOS client runs MLS on-device without a second crypto implementation. Design rationale and
the full contract are in [ADR-0007](adr/0007-uniffi-mls-binding.md); this is the data-flow map.

## Crate / package layout

```
core/mls-core     Rust  #![forbid(unsafe_code)]   OpenMLS integration + crash-safe DurableSession.
                        The audited crypto core. Never links UniFFI.
core/mls-ffi      Rust  UniFFI boundary. Thin marshalling shim: MlsClient object + records/enums +
                        redacted errors. The ONLY place the unavoidable FFI `unsafe` lives.
                        `cargo run --bin uniffi-bindgen` generates the Swift.
apps/ios/SentinelMLS   Swift package: generated bindings (Sources/MlsFfi/mls_ffi.swift, committed)
                        + MlsFfi.xcframework (built, not committed) + the integration test.
services/api      Rust  The relay. Depends on NEITHER mls-core NOR mls-ffi — it only ever sees
                        opaque ciphertext (INV-1 / ADR-0001). Verified by `grep`, not just intent.
```

## What crosses the boundary (and what must not)

```
Swift  ──▶  Rust      identity bytes, at-rest key (32B), key package, welcome, envelope,
                      plaintext to send, local ids, envelope ids
Rust   ──▶  Swift     key package, commit, welcome, opaque envelope (ciphertext),
                      decrypted application plaintext, epoch, StoredMessage, Capabilities, typed errors

NEVER crosses         OpenMLS objects · the provider/store blob · ratchet secrets · the signing
                      private key. There is deliberately no `export_store` on the FFI surface.
```

Decrypted *application plaintext* does cross — that is the whole point (Swift renders it). It is not
a secret in the key-substitution sense; key material is.

## Message send/receive flow

```
send:     Swift enqueue(pt) ─▶ Rust: durable draft (ratchet NOT advanced) ─▶ local_id
          Swift encrypt(local_id) ─▶ Rust: MLS create_message (ratchet advances ONCE, cached)
                                        ─▶ opaque envelope ─▶ Swift hands to the relay
          retry encrypt(local_id) ─▶ Rust returns the CACHED ciphertext (no re-encrypt, INV)
receive:  relay ─▶ Swift process_inbound(env_id, ct) ─▶ Rust: MLS decrypt / merge commit,
                    dedup on env_id, persist message+ratchet+ack atomically ─▶ InboundResult
```

Every mutating call commits one encrypted blob (MLS store snapshot + message/queue state) through
the single `DurableSession`/`Journal` authority **before returning**. On `Err`, the caller discards
the object and `open()`s again (reloads the last durable state).

## Lifetime & safety model

- Swift owns an `Arc<MlsClient>` (UniFFI object) — **no shared `u64` handle registry**, so stale /
  ABA / cross-client / registry-exhaustion bugs don't exist by construction. `close()` invalidates.
- One `Mutex<ClientState>` per client ⇒ single-writer; a group lives in exactly one client, so it
  can't be mutated concurrently.
- Every entry point is `catch_unwind`-wrapped: a panic becomes `MlsClientError::Internal`, never an
  unwind across the C ABI. Fuzzed at the envelope-decode boundary (`core/mls-ffi/fuzz`).

## Build

`scripts/build_mls_ffi.sh` builds the three static-lib slices, generates the bindings in library
mode, assembles `MlsFfi.xcframework`, and writes a provenance manifest. `--check` fails if the
committed bindings are stale. CI (`mls-bridge` job) runs it, `swift test`s the host slice, and
compiles the simulator + device slices.

## Blocked (R-101): on-device *execution*

Building/packaging/compiling for device is done and verified headlessly. Running the slices on a
physical iPhone, the Enclave-wrapped at-rest key, and App Attest remain device-only.
