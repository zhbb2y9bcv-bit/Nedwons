# Risk Register

This register is the project's honesty ledger. Every unresolved assumption, accepted
risk, untested control, platform limitation, and external-audit requirement lives here.
It is a launch gate: no entry may be silently dropped. Status values are
`OPEN`, `MITIGATING`, `ACCEPTED` (with named owner), or `CLOSED` (with evidence link).

Last updated: 2026-07-17. Owner of this file: security architect.

## Legend

- **Severity**: Critical / High / Medium / Low — impact if the risk is realized.
- **Owner**: role accountable for driving the item to closure or formally accepting it.

## R-000 — Overall maturity

| Field | Value |
|-------|-------|
| Severity | High |
| Status | OPEN |
| Owner | security architect |

The product is at Milestone 0 + the first tested slice of Milestone 1. It is **not**
production-ready and must not be represented as such. The claims allowed today are only
those backed by tests in this repository. Release acceptance criteria (see
[RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) §"Release acceptance") are almost entirely
unmet.

## Untested / unavailable controls (this environment)

| ID | Risk | Sev | Status | Owner | Note |
|----|------|-----|--------|-------|------|
| R-101 | On-device Secure Enclave enrollment, App Attest, Keychain ACLs, biometrics, and the `@main` app target are **not** verified on a device/simulator. | High | MITIGATING | iOS lead | Reduced 2026-07-17: the Swift `SentinelClient` is verified against the **live** Rust backend over real HTTP (`scripts/swift_backend_smoke.sh` → SMOKE_OK), including the INV-2 negative check. **Further reduced 2026-07-17 (R-G0-2):** the app now selects the Enclave signer via `DeviceIdentity` with a **fail-closed** no-hardware policy and **persists/reloads the enrolled key** (login signs the same key — previously it signed a fresh key each launch); proven headlessly by `DeviceIdentityTests`. **Further reduced 2026-07-18 (ADR-0007):** the **UniFFI MLS binding is now implemented and proven headlessly** — `core/mls-ffi` (thin FFI shim over `mls-core`), a reproducible `MlsFfi.xcframework` (macOS + iOS device + iOS-sim slices via `scripts/build_mls_ffi.sh`), and a **Swift↔Rust integration test** in which two Rust-backed clients exchange a real MLS message, persist, relaunch, retry, and reject hostile input (`apps/ios/SentinelMLS`, host/macOS slice). The device + simulator slices **compile/link** (device is compile-only). So the binding no longer blocks. Still needs real hardware: Enclave key non-exportability, background-refresh-without-biometric, Keychain `ThisDeviceOnly` backup exclusion, **App Attest (still unwritten)**, the `@main` Xcode target, and **running** the MLS bridge on a physical device. Steps + assertions in `docs/GATE1_DEVICE_CHECKLIST.md`. |
| R-102 | Postgres atomic challenge consumption and refresh rotation. | High | **CLOSED** | backend lead | **Closed 2026-07-17.** `services/api` implements the store traits over PostgreSQL 17; `services/api/tests/pg_invariants.rs` proves the atomicity contracts against a real DB, including two true-concurrency race tests (challenge consume = exactly one winner; refresh rotate = at most one winner, reuse burns the family) and the single-active-device partial-unique-index. `http_api.rs` drives the full flow end to end. 30 tests pass. |
| R-103 | Docker/`infra` deployment definitions unvalidated. | Medium | **MITIGATING** | ops | Docker (Colima) installed 2026-07-17. `docker-compose config` validates; the `postgres:17` service starts, is healthy, and tears down. The in-container Rust image build was not run (time); Dockerfile is standard multi-stage. |
| R-305 | Password blocklist is a small embedded list, not a real compromised-credential corpus. | Medium | OPEN | backend lead | `auth-core` enforces length + a starter blocklist. Production must add a k-anonymity range-query check against a breach corpus (NIST SP 800-63B). |
| R-306 | Rate limiting is per-IP in-process (single instance). Multi-instance deployments need a shared/distributed limiter, and abuse defense needs layered per-account/global limits. | Medium | MITIGATING | backend lead | `governor` GCRA limiter per instance. **Updated 2026-07-17:** trusted-proxy client-IP extraction implemented (`SENTINEL_TRUSTED_IP_HEADER`, `build_router_cfg`) — opt-in only; a client-supplied header is ignored by default so it can't be spoofed, and each real client IP gets its own bucket behind a proxy. Tested in `http_api.rs` (trusted-header keying + header-ignored-without-trust). Still OPEN: layered per-account/global limits and a distributed limiter for multi-instance (ABUSE_MODEL.md). |
| R-307 | Access tokens are opaque random values stored server-side (hashed). This is correct but adds a DB read per authenticated request; a short-lived signed token (PASETO/JWT) may be preferable at scale. | Low | ACCEPTED | backend lead | Acceptable for v1; revisit if the session-store read becomes a bottleneck. Revocation is simpler with server-side tokens. |
| R-104 | The "server never sees plaintext" invariant (INV-1). | Critical | **CLOSED (Rust side)** | crypto integrator | **Closed 2026-07-17.** OpenMLS integrated in `core/mls-core`; `tests/e2ee.rs` proves encrypt/decrypt, that ciphertext contains no plaintext, outsiders can't decrypt, and removed members can't read future epochs. `services/api/tests/relay_e2ee.rs` routes REAL MLS ciphertext through the HTTP relay and a **direct query of the `envelopes` table confirms no plaintext at rest**. The server library does not link `mls-core`. Residual: proven in Rust; the on-device Swift path (via UniFFI) is verified in Section 3 / on device (R-101). |

## Cryptography & protocol

| ID | Risk | Sev | Status | Owner | Note |
|----|------|-----|--------|-------|------|
| R-201 | Key transparency: a malicious/compelled server could substitute a device/identity key. | High | MITIGATING | crypto integrator | **Updated 2026-07-17.** An **append-only RFC 6962 Merkle log** is implemented and tested: bindings logged at enrollment, signed tree heads (ECDSA-P256), inclusion + consistency proofs, and **client self-monitoring** (`auth_core::transparency`, `services/api/src/transparency.rs`, `SentinelKit/Transparency.swift`; the live smoke self-monitors end to end). This detects logged-key substitution and history rewriting. **Still OPEN (see `docs/KEY_TRANSPARENCY.md`):** split-view/equivocation resistance needs gossip/witnessing; efficient verifiable non-inclusion needs a verifiable map (CONIKS/Parakeet); a specialised external audit; and atomic enroll+log/reconciliation. Until those land, **manual safety-number verification remains the primary guarantee** and the "server cannot substitute keys" claim must not be made. |
| R-202 | OpenMLS 0.8.1 (MIT) selected but its audit history and our specific usage have not had an independent cryptographic review. | High | OPEN | crypto integrator | External crypto audit required pre-launch. See ADR-0001. |
| R-203 | Post-quantum path (hybrid) is documented as a direction, not implemented. MLS ciphersuite in use is classical. | Medium | ACCEPTED | crypto integrator | Acceptable for v1 provided we do not advertise PQ security. Revisit when standardized MLS PQ ciphersuites are available in OpenMLS. |
| R-204 | Sealed-sender / metadata-minimization design is drafted but not implemented; the relay will see routing metadata (sender/recipient device, timing). | Medium | OPEN | backend lead | Do not advertise metadata privacy beyond what is implemented. See PRIVACY.md. |
| R-506 | **Server routing membership and cryptographic (MLS) membership are disconnected** (Gate 0 R-G0-5). The relay's `conversation_members` is an independent source of truth and there is no server-side MLS group yet, so a routing change need not correspond to a cryptographic commit. Also: no in-message protocol version on envelopes/control messages. | High | OPEN | crypto integrator + backend lead | **Invariant (must hold):** the API routing set must not silently diverge from the set of MLS clients holding the current group epoch — but a **strictly MLS-blind relay cannot independently prove** that a claimed routing delta matches an opaque MLS commit. **Updated 2026-07-18:** the client MLS core is now bridged to Swift (ADR-0007), so this is unblocked for design (not implementation this arc). A **future ADR** must compare: (1) a server-verifiable public MLS control/commit path — and whether it violates the no-MLS-link boundary (ADR-0001); (2) a canonical **device-signed membership manifest bound to the opaque commit hash**, client-verified, with an honest statement of what the server still cannot prove; (3) a delivery design that does not treat the plaintext routing table as the authoritative security boundary. The chosen protocol must define group id, prev/next epoch, protocol version, control type, opaque commit hash, manifest hash, actor device, authorization role, resulting device set/delta, idempotency id, and expiry, with an atomic DB compare-and-swap; and cover concurrent commits, stale epochs, rejected-commit cleanup, forks, removed-device cutoff, Welcome delivery, retries, rollback, and mismatch recovery. **Do not select an option before the ADR.** |
| R-507 | Social/profile metadata (usernames, display names, bios, friend graph, group membership) is **server-readable plaintext** (Gate 0 R-G0-4). Correct for routing/search today, but "the server stores only ciphertext" must not be generalized to metadata. | Medium | MITIGATING | backend lead + product | Message *content* privacy is proven (INV-1, R-104). **Updated 2026-07-17:** PRIVACY.md now lists each plaintext metadata field in the data table and adds an explicit "Content vs. metadata — be precise" section forbidding over-claiming. Still OPEN: implementing E2EE profile fields shared post-connection + metadata minimization (Gate 3 / R-204). |

## Authentication & accounts

| ID | Risk | Sev | Status | Owner | Note |
|----|------|-----|--------|-------|------|
| R-301 | App Attest / integrity verdicts are defense-in-depth risk signals, **bypassable**, and not a substitute for device-key proof-of-possession. A jailbroken device can defeat them. | Medium | MITIGATING | iOS lead | Mandatory control is the device-key signature (implemented + tested in auth-core). Integrity is tiered/advisory. |
| R-302 | Argon2id parameters must be benchmarked on production hardware; the defaults in `auth-core` are conservative starting values, not a production-tuned benchmark. | Medium | OPEN | backend lead | Record chosen params + version for future rehash. Do not ship one dev machine's numbers as universal. |
| R-303 | Server-side pepper (KMS/HSM) is specified but not provisioned; current tests run without a pepper. | Medium | OPEN | ops | Pepper must live in KMS/HSM, never in DB or repo. |
| R-304 | Recovery flow (trusted-device approval / recovery kit) is designed (ADR-0003) but not implemented; account recovery abuse surface is therefore untested. | High | OPEN | backend lead | Recovery is a top abuse target; needs rate limits, delays, notifications, and security regression tests before launch. |
| R-308 | **Access tokens are bearer credentials, not sender-constrained.** `authed_device` (`services/api/src/http.rs`) authenticates every `/v1/*` request on `Authorization: Bearer <hex>` alone, via `AuthService::validate_access` (`auth-core/src/service.rs`) = token-hash lookup + expiry + device-not-revoked. There is **no per-request proof-of-possession of the enrolled device key**, so an access token exfiltrated from a compromised client, a TLS-terminating middlebox, or an accidentally-logged header can be **replayed from any device** until it expires or is revoked. **Verified in code 2026-07-18 (Phase 5).** | High | OPEN | backend lead | **Scope is narrower than the generic case, by design:** (a) the **refresh** path is *already* sender-constrained — `AuthService::refresh` requires a device-key P-256 signature over a `Refresh` transcript, so a stolen refresh token alone is useless; and (b) access TTL is short (default 15 min) with server-side revocation. Only the **access token within its TTL** is exposed. **Fix (future ADR — NOT this arc):** sender-constrain the access token per **RFC 9449 (DPoP)** — a device-key-signed proof per request binding method+URI, an access-token hash, a unique proof id + replay cache, a time window (+ optional server nonce), with WebSocket handling, refresh-compat, revocation, and clock-skew policy. **Do NOT ship an ad-hoc signed header.** Tracked as an ADR task. |

## Platform & store

| ID | Risk | Sev | Status | Owner | Note |
|----|------|-----|--------|-------|------|
| R-401 | Apple mandates the iOS 26 SDK + Xcode 26 for App Store uploads (effective 2026-04-28). We build with Xcode 26.6 — compliant today, but this is a moving target. | Low | MITIGATING | release eng | Re-verify each cycle. Source: developer.apple.com/news/upcoming-requirements (accessed 2026-07-17). |
| R-402 | Privacy manifest, required-reason API declarations, and App Store privacy disclosures are drafted (PRIVACY.md) but not finalized against the shipped code. | High | OPEN | iOS lead | Disclosures must match actual behavior; mismatch is a rejection and a trust failure. |
| R-403 | Legal compliance (GDPR/UK GDPR/CCPA-CPRA, children's privacy, export/sanctions, data residency, law-enforcement response) is **not** determined by code and requires qualified counsel. | High | OPEN | legal (external) | This project cannot self-certify legal compliance. |

## Supply chain & operations

| ID | Risk | Sev | Status | Owner | Note |
|----|------|-----|--------|-------|------|
| R-501 | No SBOM/provenance pipeline yet; dependency advisory monitoring (cargo-audit) must run on a real pipeline. | Medium | MITIGATING | release eng | Updated 2026-07-17: `cargo audit` **has now been run** in dev and is wired into `.github/workflows/ci.yml` as a dedicated `sca` job over **both** Rust workspaces, failing on any advisory not documented in `docs/SECURITY_AUDIT_EXCEPTIONS.md`. fmt/clippy now cover the whole workspace + mls-core, and the backend CI job runs the api integration tests against a real Postgres service. Residual (keeps this OPEN→MITIGATING): SBOM/provenance generation and running the pipeline on the actual repo runner. |
| R-505 | OpenMLS's transitive `libcrux` crates carry RustSec advisories (`cargo audit`): 4 High (8.2) + 2 Medium + 2 unmaintained. | High→Low (see note) | ACCEPTED (tracked) | crypto integrator | Assessed 2026-07-17 (Gate 0 R-G0-1). **Corrected from the initial Gate 0 report, which overstated this.** For the `aarch64-apple-darwin` build with default features the active HPKE/AEAD backend is **RustCrypto** (`hpke-rs-rust-crypto`, `aes-gcm 0.10.3`), so `libcrux-aesgcm`/`libcrux-aead`/`libcrux-chacha20poly1305` are **not compiled** (false positives, verified via `cargo tree -i`). Only `libcrux-sha3 0.0.8` + `libcrux-secrets 0.0.5` compile, and the vulnerable **SHAKE / const-time-swap** paths are not invoked by the SHA-256/AES-GCM ciphersuite. No upstream fix is reachable: `hpke-rs 0.6.1` pins `libcrux-sha3 ^0.0.8` and `openmls_rust_crypto 0.5.1` is the latest release. Each ID is documented with a removal trigger in `docs/SECURITY_AUDIT_EXCEPTIONS.md`. **Review by 2026-10-17** or when upstream ships a release off the pinned libcrux; do not `[patch]`-override (API-breaking). Realized residual risk is Low given non-reachability; recorded as a tracked acceptance, not a dismissal. |
| R-502 | Signing keys, push credentials (APNs), and App Attest server config are not provisioned; no key-compromise playbook rehearsal has occurred. | High | OPEN | ops | Separate keys per environment; never in repo/CI-visible-to-forks. |
| R-503 | External penetration test, mobile assessment, infrastructure review, and cryptographic review have **not** been performed. | Critical | OPEN | security architect | Launch blocker per mission statement. |

## Accepted risks (explicit)

| ID | Risk | Owner | Rationale |
|----|------|-------|-----------|
| R-901 | Delete-for-everyone and disappearing messages cannot guarantee deletion on a recipient who has copied, exported, screenshotted, or backed up content. | product | Inherent to any messaging system; surfaced honestly in UI and PRIVACY.md, not hidden. |
| R-902 | Screenshots cannot be reliably prevented on iOS. | product | Platform limitation; we redact the app switcher and offer previews control, and state this honestly. |
| R-903 | v1 is single-active-device (schema-enforced); a second device with correct username/password is intentionally denied. | product | A deliberate security default (device binding), mitigated by recovery (ADR-0003). **Evolution designed in ADR-0008:** controlled multi-device via an authenticated trusted-device/recovery enrollment ceremony — password-only stays denied. Design only; not yet implemented. |

## How this file is used

- Every milestone report cross-references affected risk IDs.
- No item may move to `CLOSED` without a linked evidence artifact (test, audit letter, config).
- CI should fail a release build if any `Critical` risk is `OPEN` and not explicitly,
  time-box-accepted by the named owner.
