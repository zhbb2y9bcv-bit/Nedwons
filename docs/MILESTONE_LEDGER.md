# Implementation Ledger

Ordered milestones with acceptance tests. Status reflects this working copy. Each milestone
report (in git history / PR descriptions) lists files changed, decisions, exact commands run,
results, remaining risks, and the next smallest step.

## Milestone 0 — Decisions & foundations — **DONE (this session)**

- [x] Repository inspected (empty greenfield; Apple-only per ADR-0005).
- [x] Official requirements verified with access dates (App Store: iOS 26 SDK + Xcode 26,
      2026-04-28; OpenMLS 0.8.1 MIT).
- [x] Architecture, threat/privacy/abuse models, security invariants, ADRs 0001–0006.
- [x] Monorepo layout; Rust workspace; CI intent (`.github/workflows`); design tokens
      (`apps/ios/DesignSystem`); risk register.
- **Acceptance:** docs exist, decisions recorded, `auth-core` builds. ✅

## Milestone 1 — Secure account vertical slice — **IN PROGRESS**

- [x] `auth-core`: Argon2id password adapter with dummy-hash enumeration resistance.
- [x] `auth-core`: canonical domain-separated signing transcript + shared test vectors.
- [x] `auth-core`: single-use/expiring/account+device+action-bound challenges, atomic consume.
- [x] `auth-core`: P-256 device-signature verification; device-bound login.
- [x] `auth-core`: rotating refresh-token families with reuse detection + family revocation.
- [x] Security invariant tests (INV-2, INV-4, refresh reuse) pass under `cargo test` (13 tests).
- [x] iOS `SentinelKit`: Swift transcript encoder, `ClientTranscripts` (register/login/refresh),
      `SecureEnclaveDeviceSigner` + software fallback, `KeychainStore` — builds + 6 `swift test`.
- [x] Cross-language interoperability proven: Swift and Rust produce **byte-identical**
      canonical transcripts (golden vectors in `contracts/test-vectors/`), and a Swift-signed
      ECDSA-P256 signature verifies in the Rust backend (`INTEROP_OK`).
- [x] iOS `SentinelUI`: futuristic design tokens + components + app screens (tab shell,
      onboarding with gated enrollment, empty states) — builds with `swift build`.
- [ ] Postgres implementations of the store traits with concurrency integration tests. *(R-102)*
- [ ] HTTP API layer (`axum`) exposing register/login/refresh/logout with schema validation,
      size bounds, rate limits, generic errors.
- [ ] iOS app target (`@main`) built in Xcode; real Secure Enclave enrollment + App Attest
      verified on device. *(R-101)*
- [ ] Recovery-kit flow. *(R-304)*
- **Acceptance:** valid credentials from an unregistered device cannot log in — *logic proven
  now in `auth-core`; the client signing path is proven to interoperate with the server
  verifier; end-to-end on device pending R-101*.

## Milestone 2 — E2EE direct messages — **NOT STARTED**

- [ ] OpenMLS integration in `core/`; UniFFI Swift bindings.
- [ ] Key-package (prekey) service; identity/prekey directory.
- [ ] Two devices exchange encrypted text; offline queue, retries, dedup, receipts, local
      encrypted persistence, identity verification, push wake-up.
- [ ] Evidence: server/DB/queue/push contain **no plaintext** (INV-1, R-104).

## Milestone 3 — Complete core messaging — **NOT STARTED**

Groups + epochs, attachments, reactions, replies, editing, deletion semantics, disappearing
messages, local search, message requests, blocking/reporting, privacy settings, offline polish.

## Milestone 4 — Calls & encrypted backup — **NOT STARTED**

1:1 calls (WebRTC/DTLS-SRTP), TURN privacy relay, group-call E2EE design (SFrame) if enabled,
opt-in E2EE backup with user-controlled recovery secret + tested restore.

## Milestone 5 — Hardening & store release — **NOT STARTED**

MASVS/ASVS traceability, fuzz/load/chaos, accessibility QA, perf/battery, privacy
manifests/disclosures, deletion path, store build, external audits, signed release, rollback.

## Milestone 6 — Optional isolated GPU compute — **NOT STARTED**

Only after core is stable: isolated `ComputeJob` gateway, cpu/gpu workers, quotas, failure
isolation, no plaintext by default.

## Commands run this session

```
# environment
xcodebuild -version        # Xcode 26.6
swift --version            # Apple Swift 6.3.3
rustc --version            # 1.97.1 stable (installed this session)

# auth-core (Rust): fmt clean, clippy -D warnings clean, 14 tests pass
cd services && cargo fmt --manifest-path auth-core/Cargo.toml -- --check
cargo clippy --manifest-path auth-core/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path auth-core/Cargo.toml

# SentinelKit + SentinelUI (Swift): builds; 6 tests pass
cd apps/ios/SentinelKit && swift build && swift test

# Cross-language interop: Swift signs a transcript, Rust verifies -> INTEROP_OK
swift run --package-path apps/ios/SentinelKit InteropEmit \
  | cargo run -q --manifest-path services/auth-core/Cargo.toml --example verify_interop
```
