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
apps/ios/NedwonsMLS   Swift package: generated bindings (Sources/MlsFfi/mls_ffi.swift, committed)
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

### What the app layer builds on top (2026-09-09)

Three additions made the shipped app's pipeline (`NedwonsAppKit/ConversationCoordinator`) real:

- **`unsent_local_ids()`** — the outbox status (`Queued`/`Encrypted`/`Sent`) was durable but never
  exposed, so a relaunch could not find an interrupted upload. Now it replays them: `encrypt`
  returns the cached ciphertext, the upload uses an idempotency key derived from
  (conversation, local id), `mark_sent` closes it — delivered exactly once.
- **Durable pending identities** (`mls_core::durable::PendingIdentity`) — a joiner used to live only
  in memory ("if the process dies before joining, request a fresh key package"), which meant a
  group created for you while the app was closed was unjoinable. A joiner is now committed on
  creation and after every `key_package()`, `open()` returns it still Pending (`is_pending()`), and
  `join_group` overwrites the blob with the Active session. The app keeps a *lobby* of such
  identities, one per outstanding prekey, and tries a Welcome against each.
- **`add_member`'s commit is a versioned app envelope** (as `add_self_device`'s already was) so the
  members already in a group apply it through `process_inbound` → `StateAdvanced`. Before this the
  raw commit was refused by that path and no group beyond two people could decrypt for its earlier
  members. Proven in `core/mls-ffi/tests/client.rs::group_growth_commit_reaches_earlier_members…`.

Bootstrap shape the coordinator uses: Welcome → the newcomer (targeted); that add's commit →
every member already in (targeted, so the newcomer never sees a commit for the epoch it joined at).

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
