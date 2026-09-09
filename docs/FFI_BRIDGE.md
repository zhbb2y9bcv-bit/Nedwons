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
fanned out to the conversation (the relay already knows the routing set; the newcomer also receives
it, cannot process a commit for the epoch it joins at, and discards it like any out-of-epoch
envelope). The same path adds people to an existing group (`addMembers`), which previously touched
relay routing only — they were being sent ciphertext they held no key for.

### Attachments (E2EE files)

`mls_core::attachment` seals a file under a **fresh one-time key** (AES-256-GCM). The nonce is fixed
at zero and that is safe *only* because a key is used exactly once — re-encrypting the same file
draws a new key and produces different bytes, so identical files are not recognisable as such. The
sender uploads the ciphertext, gets a blob id, and sends `Content::Attachment` carrying the key,
a SHA-256 of the ciphertext, the size, media type, filename and caption — all inside the MLS
ciphertext. The relay therefore stores bytes it has no key for and cannot tell a photo from a PDF.

The digest is checked **before** decryption, which is what catches a relay that serves a different
(perfectly valid) object under the same id: GCM alone would just fail, and the client could not say
which thing went wrong. `seal_attachment`/`open_attachment` are free functions, not methods —
sealing touches no group state, so a file can be prepared before choosing where to send it, and a
failed upload never leaves a message pointing at bytes that do not exist.

References are stored in the message log **including the key**, so a file reopens after a relaunch
without asking the sender; the log lives in the durable blob, encrypted at rest under the same key
as the ratchet beside it. Bounded at 25 MB because both halves run in memory (plaintext, ciphertext,
and a copy of each across the FFI) — streaming is the honest next step, and until it exists a cap
beats an out-of-memory crash on a large video. Decrypted bytes are held in memory for the session
and never written to disk in the clear.

### Group name, read state, timestamps (arc: "feels like a messenger")

- **`Content::GroupName`** (kind 5) — the group's name is an ordinary E2EE message: the sender's
  local name changes when it is *encrypted* (the point of no return), recipients learn it by
  decrypting (`InboundResult::GroupRenamed`), and `group_name()` reads it from the durable blob.
  There is no server-side name field at all. The decoder refuses what must never reach a screen
  (empty, >128 bytes, invalid UTF-8, control characters, bidi overrides/isolates), and
  `set_group_name` refuses the same at the source. Any member *can* send one — MLS has no roles and
  the relay cannot police a message it cannot read — the app offers it to admins as a UI-level
  restriction and says so in the sheet.
- **`mark_read` / `unread_count`** — a per-conversation read mark stored in the blob; unread =
  inbound messages above it. The mark is an `Option` because local ids start at 0 (a `0` sentinel
  made the first message permanently read — caught by the test). The relay never sees a read
  receipt; it is counting what it cannot read.
- **`StoredMessage.created_at_ms` / `pending`** — every message is stamped by *this* device
  (queued, for outbound; decrypted, for inbound) and never on the wire, so a peer cannot forge when
  a message appeared here; the stated cost is that a long-offline delivery is timed at arrival.
  Wall-clock is used here deliberately and only here — the secret-reveal timer keeps its injected
  monotonic clock because that one is security-relevant. `pending` resolves an outbound message
  against its outbox entry (`Message.outbox_local_id`), which is what lets the thread show
  "Sending" for a message the relay has not accepted, instead of it vanishing until a retry.

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
