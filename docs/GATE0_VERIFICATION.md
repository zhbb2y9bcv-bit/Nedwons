# Gate 0 — Repository Verification & Claim-to-Evidence Matrix

**Date:** 2026-07-17
**Scope:** Independent verification of the reported prototype state before any new feature work.
**Method:** Every claim below was checked against code, schema, migrations, tests, and a live
run — not assumed from the status report. Commands and results are recorded verbatim.

> **Headline:** The backend/auth/relay/crypto-library foundation is real and its 55 tests + live
> smoke reproduce green from a clean environment. But three material issues surfaced that were
> **not** in the prior status report, and several claims are only *partially* true because the
> security boundary they describe is never exercised by the app or on hardware. See
> **§6 Prioritized Risks** and **§7 Contradictions**.

---

## 1. Environment & reproducibility

| Tool | Version | Notes |
|------|---------|-------|
| Rust (cargo/rustc) | 1.97.1 | Installed via rustup; **not on default PATH** — must `export PATH="$HOME/.cargo/bin:$PATH"`. |
| clippy / rustfmt | 0.1.97 / 1.9.0 | |
| Swift | 6.3.3 (Apple) | Builds SentinelKit + SentinelUI for **macOS host**, not iOS. |
| PostgreSQL | 17.10 (Homebrew) | Running; `sentinel_test` and `sentinel_dev` DBs present. |
| Docker | 29.6.2 | Available (compose not exercised in this pass). |
| cargo-audit | 0.22.2 | **Was not installed** — installed during this pass to run SCA for the first time. |

**Not available in this environment:** Xcode / iOS Simulator / physical iPhone. No `xcodebuild`,
so nothing iOS-specific (Secure Enclave on device, App Attest, Keychain UI, APNs, the `@main` app
target) can be executed or proven here. Those gates remain **BLOCKED**, not failed.

Working tree: clean, branch `main`, 10 commits.

---

## 2. Check results (all reproduced this pass)

| Check | Command | Result |
|-------|---------|--------|
| auth-core fmt | `cargo fmt --manifest-path auth-core/Cargo.toml -- --check` | **clean** |
| auth-core tests | `cargo test --manifest-path auth-core/Cargo.toml` | **18 passed** (1 unit + 17 invariants) |
| workspace clippy | `cargo clippy --workspace --all-targets -- -D warnings` | **clean** |
| api integration | `cargo test -p sentinel-api` (TEST_DATABASE_URL) | **27 passed** (http 6, load 3, pg_invariants 6, relay_e2ee 5, social 5, ws_stream 2) |
| mls-core clippy | `cargo clippy --all-targets -- -D warnings` | **clean** |
| mls-core tests | `cargo test` | **3 passed** (e2ee) |
| mls-core fmt | `cargo fmt -- --check` | **DIFF (not clean)** — see R-G0-3 |
| Swift build | `swift build` | **clean** (compiles SentinelKit + SentinelUI on macOS) |
| Swift tests | `swift test` | **7 passed** (AuthTranscript 3, ClientTranscripts 3, SentinelClient 1) |
| live smoke | `scripts/swift_backend_smoke.sh` | **SMOKE_OK** (real server + real HTTP; register/login/whoami, INV-2 negative, social+group+message, clique gate) |
| SCA (services) | `cargo audit` | **6 vulnerabilities + 2 warnings** — see R-G0-1 |
| SCA (mls-core) | `cargo audit` | same 6 + 2 (shared libcrux backend) |

**Automated total: 55** (18 + 27 + 3 + 7), exactly matching the claim, **plus** the live smoke.
Test *count* is confirmed; test count is not a readiness metric (see §7–§8).

---

## 3. Claim-to-evidence matrix

Status legend: **V** verified · **P** partially verified (real but boundary not exercised) ·
**U** unverified (needs env we lack) · **C** contradicted / not as implied.

| # | Claim | Implementation | Evidence (tests) | Missing negative cases | Status |
|---|-------|----------------|------------------|------------------------|--------|
| 1 | Password **+ hardware device-key signature**; password alone can't log in (INV-2) | `auth-core/crypto.rs verify_p256` (fail-closed), `transcript.rs` (domain-separated, length-prefixed), `service.rs:182/289/326` | `login_denied_without_the_device_key`, `wrong_device_key_denied_over_postgres`, `http_login_denied_without_device_key`, smoke attacker check | Malleable/high-S signature normalization; cross-account key reuse at scale | **V** (protocol/server) |
| 1a | …engaged by the **iOS app** on real Secure Enclave | `DeviceSigner.swift SecureEnclaveDeviceSigner` exists & compiles | **none** — app code never calls it | Enclave path never run; no availability/fail-closed selection | **C** — app uses `SoftwareDeviceSigner` (see R-G0-2) |
| 2 | Argon2id + weak-password blocklist | `password.rs` (19 MiB/2/1, 12-char min, dummy hash) | `weak_passwords_are_rejected_at_registration` | Blocklist is 12 entries; params untuned | **V** (with honest R-302/R-305 debt) |
| 3 | Rotating refresh tokens + reuse detection | `service.rs`, `store.rs`, `pgstore.rs` | `refresh_rotates_and_reuse_revokes_family`, `refresh_rotate_race_at_most_one_winner` | Family revocation under partitioned DB | **V** |
| 4 | Enumeration-resistant login (decoy + dummy hash) | `service.rs:227`, `password.rs make_dummy_hash` | `login_begin_does_not_leak_account_existence`, `http_login_begin_is_enumeration_resistant` | Statistical timing under load (not just logical) | **V** |
| 5 | axum/PG API: register/login/refresh/logout/validate | `http.rs`, `main.rs`, `lib.rs` | `full_http_flow_register_login_whoami_refresh_logout` | — | **V** |
| 6 | Atomic challenge/token rules; concurrency-safe | `pgstore.rs` (DB-enforced), migrations V1 | `challenge_consume_race_exactly_one_winner`, `challenge_is_single_use`, `schema_enforces_single_active_device_and_unique_usernames` | — | **V** |
| 7 | OpenMLS E2EE; server stores **opaque ciphertext**; server lib never links MLS | `relay.rs`, `mls-core` (test-only path dep) | `mls_message_routed_through_relay_leaves_no_plaintext` (direct `SELECT` on `envelopes`) | Ciphertext-side-channel/length; malformed envelope handling | **V** (server+lib) |
| 8 | Removed group member can't read future epochs | `mls-core/src/lib.rs` | `removed_member_cannot_read_future_messages` | Re-add, fork, stale-epoch, concurrent commit | **V** (library only) |
| 9 | At-least-once, persist-before-ack, idempotent send | `relay.rs peek/ack/fanout`, migration V3 | `peek_is_non_destructive_until_ack`, `concurrent_duplicate_sends_dedup_to_one` | Client-side crash-safety (no client state machine exists) | **V** (server) |
| 10 | Long-poll + WebSocket delivery | `http.rs /v1/inbox`, `/v1/stream`, `notify.rs` | `inbox_long_poll_wakes_on_delivery`, `websocket_pushes_new_envelopes_instantly`, `websocket_requires_auth`, `idle_waiters_exceed_pool_without_deadlock` | Slow-consumer, revoked-session mid-stream, multi-instance fanout | **V** (single instance) |
| 11 | Profiles, username search, friends, requests, groups, conversation list | `social.rs`, `http.rs`, migration V4 | `profile_update_get_and_search`, `friend_request_accept_flow`, `mutual_requests_auto_accept`, `group_*`, list-conversations in smoke | IDOR sweep across all object endpoints; homoglyph/normalization abuse | **V** (functional) |
| 12 | SentinelKit: SE signer, Keychain, transcript, HTTP client | `SentinelKit/*.swift` | Swift 7 tests; `InteropEmit`→`verify_interop` (Swift-signs/Rust-verifies); transcript golden vectors | Keychain never exercised (no device) | **V** (interop) / **U** (Keychain on device) |
| 13 | SentinelUI wired screens; buttons call backend | `SentinelUI/*.swift`, `AppModel.swift` | compiles on macOS; smoke exercises same client calls | Never run on iOS; SwiftUI runtime unproven | **P** |
| 14 | 55 tests + live smoke, all green | (all of the above) | reproduced this pass | — | **V** |
| 15 | No device run, no App Attest, no MLS↔Swift binding, no rendering, no key transparency, no recovery, no audit | — | grep: no `DCAppAttest`/App Attest; **no FFI surface** (`extern`/`uniffi`/`no_mangle` = none); `mls-core` used only by its own tests | — | **V (absent, as stated)** |

---

## 4. Identifier ownership, protocol version, trust boundaries

**Identifiers.** `auth-core/ids.rs` defines `AccountId`, `DeviceId`, `TxnId`, `FamilyId` as typed
random 16-byte values, **never derived from any hardware identifier** (aligns with the no-MAC
rule). *Gap:* `conversation_id`, `sender_device`, `envelope_id` live in the relay as raw
`BYTEA`/`BIGINT` with **no typed wrapper**, and **MLS group id / epoch are not represented on the
server at all** — they exist only inside OpenMLS objects in `mls-core` tests. So there is **no
single authoritative binding between server routing membership and cryptographic (MLS) group
membership**; today they are entirely disconnected (relay membership is a plain table; no MLS
group is ever created server-side or by a client). This is the "server vs MLS membership can
diverge" hazard, in its most extreme form: there is no MLS membership in the running system yet.

**Protocol version.** Compatibility is expressed only by the `/v1` URL prefix. Envelopes and (future)
MLS application messages carry **no in-message protocol/version field** (confirmed in V2/V3). Old/new
client downgrade handling is undefined. (Roadmap Gate 0 item 8 — open.)

**Trust boundaries / data readable by each component (as built today):**

| Component | Can read |
|-----------|----------|
| iOS client | Everything (plaintext, keys) — but message rendering not implemented |
| API / relay (axum) | Message **ciphertext only**; **all social metadata in plaintext**: usernames, display names, bios, friend graph, group membership, conversation lists, timestamps, sender/recipient device ids |
| PostgreSQL | Same as API (ciphertext blobs + plaintext social/routing metadata) |
| Object storage / CDN | N/A — no media pipeline exists |
| APNs / push | N/A — not implemented |
| Observability / admin / backup | Not implemented; no redaction pipeline yet |

Message **content** privacy holds (verified by direct DB query). **Metadata** privacy does **not**:
"the server stores only ciphertext" is accurate for messages and **misleading if generalized** to
profiles/social graph, which are plaintext by construction (prefix search requires it). See R-G0-4.

**OpenMLS.** Pinned `openmls = "0.8"`, resolved **0.8.1**; provider `openmls_rust_crypto = 0.5.1`
(libcrux backend). Active ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (AES-128-GCM,
SHA-256, X25519, Ed25519). The published OpenMLS security assessment covers a specific revision;
**the audited-revision-vs-0.8.1 diff has not been reconciled** (needs the assessment PDF + changelog;
no network verification done this pass). `#![forbid(unsafe_code)]` is set in all three crates; **no
`unsafe` and no FFI** anywhere.

---

## 5. What is genuinely absent (confirmed, not just unbuilt)

- **No App Attest** — only referenced in comments.
- **No MLS↔Swift binding / no FFI** — `mls-core` is an island; the app cannot encrypt or decrypt a
  real message. No message content can be rendered.
- **No client-side MLS state machine / local encrypted store** — none exists.
- **No key transparency, no linked devices, no recovery, no E2EE backup, no media, no calls, no
  APNs, no Android.** All confirmed absent.

---

## 6. Prioritized new risks found in Gate 0 (not in prior report)

| ID | Sev | Finding | Evidence | Action |
|----|-----|---------|----------|--------|
| **R-G0-1** | ~~High~~ → **Low (resolved to tracked acceptance)** | `cargo audit` reports 6 advisories + 2 warnings in transitive `libcrux` crates. **On deeper analysis (this same pass) the initial "on the active AES-GCM path" wording was WRONG** and is corrected here: for `aarch64-apple-darwin`/default features the active HPKE+AEAD backend is **RustCrypto** (`hpke-rs-rust-crypto`, `aes-gcm 0.10.3` — verified `cargo tree -i aes-gcm`). `libcrux-aesgcm`/`aead`/`chacha20poly1305` are **not compiled** (false positives). Only `libcrux-sha3`+`libcrux-secrets` compile, and the vulnerable SHAKE/const-time-swap paths are **not invoked** by the SHA-256/AES-GCM ciphersuite. No upstream fix reachable (`hpke-rs 0.6.1` pins libcrux `^0.0.8`; `openmls_rust_crypto 0.5.1` is latest). | `cargo audit` + `cargo tree -i` (both workspaces) | **DONE:** `cargo audit` wired into CI over both workspaces; each ID documented with reachability + removal trigger in `docs/SECURITY_AUDIT_EXCEPTIONS.md`; tracked as **RISK_REGISTER R-505** (review 2026-10-17). Do not `[patch]`-force libcrux (API-breaking). |
| **R-G0-2** | **High** | The iOS app **never engages the hardware boundary**. `AppModel.register()` and the sign-in view hardcode `SoftwareDeviceSigner()`; `SecureEnclaveDeviceSigner` compiles but is never selected, and there is no Enclave-availability/fail-closed logic. The central security claim is unproven at the app layer and on hardware. | `AppModel.swift:60`, `SocialScreens.swift:64`; grep of signer usage | Wire Enclave signer + availability policy; prove on a physical iPhone (Gate 1). |
| **R-G0-4** | Med | "Server stores only ciphertext" is true for messages but **social/profile metadata is plaintext** (usernames, display names, bios, friend graph, group membership). Docs risk over-claiming. | migration V4 (`TEXT` columns), search endpoint | Make PRIVACY.md distinguish content vs metadata; design E2EE profile fields (Gate 3). |
| **R-G0-3** | Low | `mls-core` is **not fmt-clean**; CI's fmt gate only covers `auth-core`, not `api` or `mls-core`. | `cargo fmt -- --check` diff at `mls-core/src/lib.rs:48` | Run `cargo fmt`; extend CI fmt/clippy to the whole workspace + mls-core. |
| **R-G0-5** | Med | **No binding between server routing membership and MLS group membership**, and no in-message protocol version. Today there is no server-side MLS membership at all. | §4 | Define authoritative group/epoch identity + versioning before Gate 2/3. |

---

## 7. Contradictions with the two product corrections you flagged

1. **Full-clique group rule is present and load-bearing.** `social.rs all_mutually_friends` requires
   `edges == n(n-1)/2` (every pair friends) or the group is rejected `403 not_all_friends`. Removing
   it (invitations/roles/approval) is a real schema + API + client change, and it must become
   cryptographic MLS Add/Remove commits — which don't exist yet. **ADR required before changing.**
2. **Strict single-device is enforced in the schema.** `CREATE UNIQUE INDEX
   devices_one_active_per_account ON devices(account_id) WHERE NOT revoked`. Moving to controlled
   multi-device (linked-device enrollment, device list, per-device MLS membership) contradicts this
   index and the whole single-device auth flow. **ADR + migration required.**

Neither should be ripped out ad hoc; each needs an ADR (threat, migration, compatibility, tests)
first, per your non-negotiable rules.

---

## 8. Gate 0 acceptance criteria — assessment

- ✅ Current build/tests reproducible from a (near-)clean checkout — **yes** (once cargo is on PATH).
- ⚠️ Every claimed security property maps to code **and a negative test** — **mostly**, but the
  *app-level* hardware-binding claim has no test and is contradicted (R-G0-2); several MLS
  properties are proven only in the isolated library, not in any client path.
- ⚠️ Protocol, persistence, identifier ownership documented — **partially**; conversation/group/epoch
  identity and protocol versioning are **not** authoritative (R-G0-5).
- ❌ No unresolved critical contradiction between server and MLS membership — **there is one**: they
  are disconnected (R-G0-5), and the crypto backend carries High CVEs (R-G0-1).

**Gate 0 verdict: substantially passed for the auth/relay foundation; three follow-ups (R-G0-1,
R-G0-2, R-G0-5) must be resolved or ADR'd before optional features.** Do not begin secondary
features until these are addressed.

---

## 9. Next smallest launch-gating tasks (in order)

1. ~~**R-G0-1**~~ — **DONE.** Analyzed to a tracked acceptance (R-505); `cargo audit` wired into CI
   for both workspaces with documented exceptions. Upstream-fix watch open (review 2026-10-17).
2. ~~**R-G0-3**~~ — **DONE.** `cargo fmt` mls-core; CI now runs fmt/clippy on the whole workspace +
   mls-core, adds a Postgres-backed api test job, and a Swift build+test job.
3. **ADR-0008** — multi-device trust model (replaces single-device index) — design only, no code. *(done — see docs/adr/0008)*
4. **ADR-0009** — group membership model (replaces clique rule) tied to MLS commits — design only. *(done — see docs/adr/0009)*
5. **R-G0-2 (partial):** wire the Enclave signer selection + availability/fail-closed policy in the
   app layer; software path becomes an explicit, recorded lower-assurance fallback. Physical-iPhone
   proof stays BLOCKED — see the device checklist. *(app-layer wiring done; hardware run open)*
6. **Gate 2 first slice (doable here):** author the FFI/binding ADR and a *simulator-compatible*
   Rust-owned MLS client API + deterministic vectors, so message encrypt/decrypt can exist at all —
   without needing a device. *(next)*
7. **Gate 1 (BLOCKED here):** prove the Enclave signer + App Attest on a physical iPhone using the
   committed device checklist; keep the physical-device gate open.
