# ADR-0017: Web client — WASM core reuse, browser durability, and the `software` device-assurance class

- **Status:** **Proposed.** The WASM feasibility spike is done and green (see Verification); nothing
  else here is implemented. No UI work has started, deliberately — this ADR is the gate.
- **Date:** 2026-07-27
- **Deciders:** security architect, crypto integrator, backend lead
- **Supersedes nothing.** Pins down the `assurance ∈ {hardware, software}` distinction ADR-0008
  reserved but never implemented, and scopes the first non-Apple client under ADR-0005's
  "platform-neutral backend" clause.

## Context

ADR-0005 targets iOS only but deliberately kept the backend, `core/`, and the wire contracts
platform-neutral "so a second platform remains feasible later **without** redesign." This ADR is the
first test of that claim. A web client would reuse `core/mls-core` compiled to WebAssembly instead of
the Swift UniFFI bridge (ADR-0007), against the unchanged relay.

Three questions had to be answered before any UI work, because each could have killed the effort:

1. **Does the PQ crypto core even run in a browser?** `mls-core` pulls OpenMLS, a vendored X-Wing
   provider (ADR-0016), `ml-kem`, `libcrux-*` and `hpke-rs`. Any native-threading, OS-randomness or
   SIMD assumption in that stack would be fatal.
2. **Can the crash-safety invariant survive?** `durable.rs` commits the MLS ratchet state and the
   message log as **one atomic blob** so a crash can never tear them apart. Browsers have no
   `rename(2)`.
3. **What replaces hardware device binding?** There is no Secure Enclave and no App Attest on the
   web. Substituting silently would be a security-posture change disguised as a technical detail.

### What the spike established (facts, not projections)

`mls-core` compiles for `wasm32-unknown-unknown`, and its **full test suite executes green** under
`wasm32-wasip1` — 41 tests including the X-Wing PQ round trip, removed-member forward secrecy, the
durable-state crash-safety cases, and the secret-message state machine. Two `Cargo.toml` additions
were required, both `[target.'cfg(target_arch = "wasm32")']`-gated so the native and iOS dependency
graphs are provably untouched (`cargo tree --target aarch64-apple-ios` contains zero wasm crates):

- **`getrandom`** — **two majors coexist** in the graph and each has a *different* opt-in: 0.2 (via
  `rand_core` 0.6 → `OsRng` in `durable.rs`) needs `js`; 0.4 (via `rand` 0.10 → `hpke-rs`,
  `libcrux-sha3`, `uuid`) needs `wasm_js`. Note 0.4 does **not** need the `--cfg getrandom_backend`
  RUSTFLAG — that requirement was 0.3-only, and stale guidance on this is a known time sink.
- **`openmls`** needs its `js` feature or it hard-`compile_error!`s.

Notably **`rayon` is a non-issue**: it appears in the graph but OpenMLS gates it
`#[cfg(not(target_arch = "wasm32"))]` at its use sites (`treekem.rs`, `parent_node.rs`), so the
commit path has no threading assumption. No non-portable SIMD was found.

So the crypto is **not** the hard part. The hard parts are durability and device binding.

## Decision

### 1. Reuse `mls-core` via WASM; do not fork the core

A new `core/mls-wasm` crate becomes a **sibling of `core/mls-ffi`, not a replacement**, and mirrors
the frozen ADR-0007 contract rather than inventing a second one: object-per-client (no handle
registry), single-writer `Mutex<ClientState>`, bytes-only across the boundary (no `export_store`),
bounded/typed/redacted errors, `catch_unwind` at every entry point. `Vec<u8>` maps to `Uint8Array`,
the result enums to tagged JS objects, and `Result<_, MlsClientError>` to thrown errors preserving
variant-only redaction. `mls-ffi/src/lib.rs` is the specification for this surface.

Rationale: two bindings over one core keeps a single MLS/crypto authority and a single persistence
authority. A second core would double the audit surface for the least reviewable part of the system.

### 2. Durability: OPFS synchronous access handles, **not** IndexedDB

**IndexedDB cannot back the existing `Journal` trait.** `Journal::commit`/`load` are *synchronous*
and IndexedDB has no synchronous API. The options were:

| Option | Verdict |
|---|---|
| Make `Journal` async | Rejected for now — ripples through every `DurableSession` method and perturbs the shipped, proven iOS path for the benefit of a not-yet-existing client. |
| Buffer in memory, flush asynchronously | **Rejected outright.** `commit` would return `Ok` before the write is durable, breaking the invariant the whole module exists to provide. |
| `Atomics.wait` + SharedArrayBuffer bridge to async IDB | Rejected — requires COOP/COEP cross-origin isolation, constraining hosting and embedding for no gain over the option below. |
| **OPFS `createSyncAccessHandle()` in a Web Worker** | **Chosen.** Genuinely synchronous `read`/`write`/`flush`. Trait unchanged; `mls-core` and iOS untouched. |

OPFS has no atomic rename, so the `FileJournal` temp-file+fsync+rename trick does not transfer.
Replace it with a **two-slot journal plus a generation counter**: write the blob to the *inactive*
slot, `flush()`, then write the small generation header, `flush()`. A reader takes the slot with the
highest generation that authenticates. Because the blob is already sealed with AES-256-GCM, **the GCM
tag is the torn-write detector** — a partially written slot fails to decrypt and the reader falls
back to the previous one. This preserves all-or-nothing commit without relying on any filesystem
atomicity primitive.

Two useful side effects: `createSyncAccessHandle()` is **exclusive**, so a second browser tab cannot
acquire the journal — the single-writer invariant is enforced by the platform rather than by
convention; and the worker requirement keeps the crypto core off the main thread anyway.

### 3. Device binding: the web client is a `software`-assurance device

**There is no Secure Enclave and no App Attest equivalent on the web, and we do not pretend
otherwise.** But the existing architecture already accommodates this, and the gap is narrower than it
first appears:

- ADR-0002 already makes the **challenge/response signature over the canonical transcript** the
  primary authentication factor and App Attest explicitly "a bypassable **risk signal only**, never a
  substitute for the device-key signature." The code agrees: `attest_submit_handler` records a
  `verified` boolean and **no endpoint gates on it**. Losing App Attest therefore costs a
  defense-in-depth signal, **not** an authentication factor.
- The wire formats already match WebCrypto exactly, requiring **no server change**: `devices.
  public_key` is `octet_length = 65` (SEC1 uncompressed) = WebCrypto `exportKey("raw")`, and
  `auth-core` verifies with `Signature::from_slice`, i.e. fixed 64-byte r‖s (IEEE P1363) — precisely
  what WebCrypto ECDSA emits, and *not* DER.

**Decision:** the web client generates a **non-extractable WebCrypto ECDSA P-256 key**, persisted as
a `CryptoKey` handle in IndexedDB (IndexedDB is the right tool *here* — storing an opaque key handle
is not a durability-critical synchronous path), and signs the existing ADR-0002 transcript unchanged.
It is enrolled **only** through the ADR-0008 trusted-device SAS ceremony or recovery-secret path —
never username+password, which remains absolutely prohibited. It is recorded as
**`assurance = 'software'`**, and:

- **A `software` device MUST NOT authorize enrollment of another device.**
- The device list surfaces the class honestly to the user, per ADR-0008's transparency requirement.

This is not a new trust tier. It is the class ADR-0008 already reserved and never implemented;
migration **V21** finally makes it representable, with a **fail-closed `'software'` default** so an
un-migrated insert can never silently gain approval rights (see the migration's own commentary).

**Assurance is earned, never declared.** A client cannot state its own class — a web client would
simply claim `hardware`. Every device is therefore *created* as `Software`, by every path
(registration, trusted-device enrollment, recovery), and the only route to `Hardware` is
`AuthService::promote_to_hardware`, which the API layer may call **only after cryptographically
verifying an App Attest attestation**. This finally gives App Attest a real job that is consistent
with ADR-0002: it is still not an authentication factor (it is bypassable), but it is exactly the
right evidence for *classifying key custody*, which is all it now grants.

Two properties fall out and are covered by regression tests:

- **The privilege does not propagate.** A device enrolled *by* a `Hardware` device is still
  `Software`. Otherwise one attested phone could launder approval rights to an unlimited chain of
  unattested devices.
- **The approver is re-checked at `finish`, not only at `begin`.** A check present only in stage 1
  would be bypassed by obtaining a challenge while eligible and redeeming it after revocation or
  downgrade. Both stages call one shared `AuthService::approver` helper so they cannot drift.

The reason this rule is load-bearing: a non-extractable WebCrypto key cannot be *exfiltrated*, but
script running in the origin can **use** it. Without this restriction, one XSS becomes account-wide
device injection — exactly ADR-0008's "Downgrade via software-signer device" threat.

## Consequences

**Positive.** ADR-0005's platform-neutrality claim survives contact with reality: the relay, the
transcript, the auth schema, and the MLS core all carried over with no protocol change and no server
change. The PQ ciphersuite works unmodified in a browser.

**Honest residuals — these are real regressions relative to iOS, stated rather than buried:**

- **XSS is a signing oracle.** For as long as the page is open, injected script in the origin can
  sign transcripts with the device key. Mitigated but not eliminated by the strict CSP already
  shipped, the `software` approval ban above, and key-transparency monitoring (R-201) making a
  resulting device addition auditable. There is no iOS equivalent to this risk.
- **KeyPackage lifetimes fall back to the browser wall clock.** OpenMLS's `js` feature backs
  `SystemTime` with `Date.now()`, which the user can set freely. Lifetime enforcement becomes
  advisory on web; the server-side prekey TTL (`KEY_PACKAGE_TTL_SECS`) remains the real authority.
- **Browser storage is evictable.** OPFS may be cleared under storage pressure unless
  `navigator.storage.persist()` is granted. Losing the journal means losing ratchet state — the
  device must be re-enrolled and re-added to conversations, and its history is unrecoverable (E2EE:
  the server cannot restore it). The client must request persistence and warn honestly when it is
  denied. iOS has no comparable failure mode.
- **R-105 is amplified.** The whole durable blob is rewritten on every commit (O(total history)); on
  web that is a full OPFS write per message. The encrypted-paginated-store fix is more urgent here
  than on device.
- **No hardware attestation, by construction.** A web "device" cannot prove it is a genuine
  unmodified client on real hardware. The `software` class is exactly the acknowledgement of that.
- **The wasm-only dependencies leak into every lockfile, including the server's.** Cargo resolves
  `Cargo.lock` **target-agnostically**, so even though the new crates are `cfg(target_arch =
  "wasm32")`-gated and are *never compiled* for a native target, they are recorded in
  `core/mls-core`, `core/mls-ffi` **and `services/Cargo.lock`** (the latter because `services/api`
  dev-depends on `mls-core` for its integration harness). Concretely this adds `fluvio-wasm-timer`,
  `parking_lot 0.11`, `instant`, `futures`, `bitflags 1.3.2` and friends to the server's lockfile.
  Two consequences worth knowing rather than discovering in CI:
  - **`cargo audit` now reports `instant` as unmaintained (RUSTSEC-2024-0384) in the *services*
    workspace.** Verified non-breaking: it is an unmaintained *warning*, not a vulnerability, and all
    three CI audit invocations still exit 0. But it is new noise on the server's audit surface,
    caused entirely by a client-side feature.
  - **The generated server SBOM will list wasm-only crates** (`scripts/generate_sbom.sh`), which
    misrepresents what the deployed `nedwons-api` binary actually contains.

  If this proves objectionable, the clean fix is to move the wasm feature opt-ins out of `mls-core`
  and into the `core/mls-wasm` binding crate, so only that crate's lockfile carries them. That is
  preferable long-term and should be done when `mls-wasm` is created; the spike put them in
  `mls-core` only because no binding crate exists yet.

**Deliberately accepted cost.** Until the iOS enrollment path declares `assurance = 'hardware'`
explicitly, newly enrolled iOS devices land as `software` and cannot approve enrollments. Existing
devices are backfilled to `hardware`, so no session breaks and no user is locked out. This is the
fail-closed direction and is the immediate follow-up task.

## Verification

- **Done:** `mls-core` builds for `wasm32-unknown-unknown`; 41/41 tests execute green under
  `wasm32-wasip1` + wasmtime (`e2ee` 3, `durable` 9, `secret` 17, `membership_check` 8,
  `client_api` 4). Native suite still 77/77 green; iOS graph verified free of wasm crates. The one
  wasm test failure is `std::process::id()` in the **test helper** at `tests/file_journal.rs:16`,
  not in `FileJournal`.
- **Done:** migration **V21** applies cleanly on top of V1–V20 against a scratch PostgreSQL 17
  database via the embedded `refinery` runner; the resulting `devices` table carries
  `assurance TEXT NOT NULL DEFAULT 'software'` with the two-value CHECK constraint, existing rows
  backfilled to `hardware`, and the `devices_approvers_by_account` partial index. `cargo audit` exits
  0 in all three workspaces as CI invokes it.
- **Done:** the `assurance` enforcement is wired in `auth-core` — `Assurance` enum (`Default =
  Software`), `DeviceRecord.assurance` carried through both stores, `DeviceStore::set_assurance`,
  `AuthService::approver` shared by both enrollment stages, and `promote_to_hardware`. Five new
  regression tests in `services/auth-core/tests/invariants.rs` (auth-core 33 → 38). **Mutation-
  checked:** deleting the enforcement line makes `software_device_cannot_authorize_enrollment` and
  `approver_is_rechecked_at_finish_not_just_at_begin` fail, so the tests are load-bearing rather
  than incidentally green. Full services suite (~100 integration tests over real PostgreSQL) green
  with V21 applied; `cargo fmt --check` and `cargo clippy --all-targets` clean.
- **Done:** the App Attest → promotion call site. `attest_submit_handler` calls
  `promote_to_hardware` **only** when `verified` is true, ordered *after* the attestation is stored
  so a crash leaves an un-promoted (`Software`) device rather than a `Hardware` device with no
  attestation on record. Proven end to end without Apple hardware by
  `services/api/tests/attest_promotion.rs`, which pins a synthetic root via
  `NEDWONS_APP_ATTEST_ROOT_PEM` and drives the real verifier over HTTP; the fail-closed direction is
  guarded by `app_attest.rs::an_unverified_attestation_does_not_grant_hardware_assurance`
  (bootstrap mode stores but must not promote). **Mutation-checked**: deleting the promotion block
  fails the former. Services suite **185 tests** green; fmt + clippy clean.
- **Done:** `NEDWONS_REQUIRE_HARDWARE_APPROVER` (`main.rs`, `.env.example`), mirroring
  `NEDWONS_REQUIRE_PROOF`. It carries a **misconfiguration guard**: enabling it without
  `NEDWONS_APP_ATTEST_APP_ID` means nothing can ever earn `hardware`, so *all* enrollment would be
  refused — the server logs an actionable error at boot. Logged rather than fatal because that
  combination fails *closed* (nobody gains approval rights), making it an availability problem, not
  a security hole; refusing to boot would be the worse outcome.
  `attest_promotion.rs` now proves the **whole arc through the assembled server**: a freshly
  registered device is `software` and its enrollment attempt is refused **401**; it attests; it is
  promoted; the *same* enrollment then succeeds **200**. Mutation-checked at both points (removing
  the promotion, and flipping the config flag, each fail it).
- **Not yet done (blocks moving this ADR to Accepted):** `core/mls-wasm` crate; the OPFS journal and
  a crash-injection test proving the two-slot commit is untearable; iOS attesting reliably in the
  field, then turning `NEDWONS_REQUIRE_HARDWARE_APPROVER` on in production. **Until that flag is on,
  the control is inert and a compromised web session could approve a new device** — the class is
  recorded and earned correctly, but nothing enforces it by default.
- **Note:** `FileJournal` currently *compiles* for wasm and would fail at runtime on every call. It
  should be `cfg`-gated out of wasm builds rather than left as a runtime trap.
