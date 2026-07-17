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
| R-101 | iOS app is a skeleton; Secure Enclave enrollment, App Attest, Keychain ACLs, and biometrics are **not** verified on a device or simulator. | High | OPEN | iOS lead | This machine can compile Swift but no simulator/device run was performed this session. Do not claim device binding works on-device until an integration test on real hardware passes. |
| R-102 | Postgres atomic challenge consumption and refresh rotation. | High | **CLOSED** | backend lead | **Closed 2026-07-17.** `services/api` implements the store traits over PostgreSQL 17; `services/api/tests/pg_invariants.rs` proves the atomicity contracts against a real DB, including two true-concurrency race tests (challenge consume = exactly one winner; refresh rotate = at most one winner, reuse burns the family) and the single-active-device partial-unique-index. `http_api.rs` drives the full flow end to end. 30 tests pass. |
| R-103 | Docker/`infra` deployment definitions unvalidated. | Medium | **MITIGATING** | ops | Docker (Colima) installed 2026-07-17. `docker-compose config` validates; the `postgres:17` service starts, is healthy, and tears down. The in-container Rust image build was not run (time); Dockerfile is standard multi-stage. |
| R-305 | Password blocklist is a small embedded list, not a real compromised-credential corpus. | Medium | OPEN | backend lead | `auth-core` enforces length + a starter blocklist. Production must add a k-anonymity range-query check against a breach corpus (NIST SP 800-63B). |
| R-306 | Rate limiting is per-IP in-process (single instance). Behind a proxy the real client IP must come from a *trusted* forwarded header, and multi-instance deployments need a shared/distributed limiter. | Medium | OPEN | backend lead | `governor` GCRA limiter is in place per instance; layered per-account/global limits and trusted-proxy IP extraction are follow-ups (ABUSE_MODEL.md). |
| R-307 | Access tokens are opaque random values stored server-side (hashed). This is correct but adds a DB read per authenticated request; a short-lived signed token (PASETO/JWT) may be preferable at scale. | Low | ACCEPTED | backend lead | Acceptable for v1; revisit if the session-store read becomes a bottleneck. Revocation is simpler with server-side tokens. |
| R-104 | MLS protocol integration (OpenMLS) not yet wired; no end-to-end ciphertext exists yet, so the "server never sees plaintext" invariant is **asserted by design, not yet demonstrated by test**. | Critical | OPEN | crypto integrator | This is the headline E2EE claim. It is a launch blocker until Milestone 2 evidence exists. |

## Cryptography & protocol

| ID | Risk | Sev | Status | Owner | Note |
|----|------|-----|--------|-------|------|
| R-201 | **Key transparency is not implemented.** Without it, a malicious or compelled server could substitute a device/identity key. Safety-number verification detects this only if users actually compare. | High | OPEN | crypto integrator | Launch-blocking for any claim stronger than "trust-on-first-use with manual verification". Plan: append-only transparency log or auditable key directory (Milestone 3+). |
| R-202 | OpenMLS 0.8.1 (MIT) selected but its audit history and our specific usage have not had an independent cryptographic review. | High | OPEN | crypto integrator | External crypto audit required pre-launch. See ADR-0001. |
| R-203 | Post-quantum path (hybrid) is documented as a direction, not implemented. MLS ciphersuite in use is classical. | Medium | ACCEPTED | crypto integrator | Acceptable for v1 provided we do not advertise PQ security. Revisit when standardized MLS PQ ciphersuites are available in OpenMLS. |
| R-204 | Sealed-sender / metadata-minimization design is drafted but not implemented; the relay will see routing metadata (sender/recipient device, timing). | Medium | OPEN | backend lead | Do not advertise metadata privacy beyond what is implemented. See PRIVACY.md. |

## Authentication & accounts

| ID | Risk | Sev | Status | Owner | Note |
|----|------|-----|--------|-------|------|
| R-301 | App Attest / integrity verdicts are defense-in-depth risk signals, **bypassable**, and not a substitute for device-key proof-of-possession. A jailbroken device can defeat them. | Medium | MITIGATING | iOS lead | Mandatory control is the device-key signature (implemented + tested in auth-core). Integrity is tiered/advisory. |
| R-302 | Argon2id parameters must be benchmarked on production hardware; the defaults in `auth-core` are conservative starting values, not a production-tuned benchmark. | Medium | OPEN | backend lead | Record chosen params + version for future rehash. Do not ship one dev machine's numbers as universal. |
| R-303 | Server-side pepper (KMS/HSM) is specified but not provisioned; current tests run without a pepper. | Medium | OPEN | ops | Pepper must live in KMS/HSM, never in DB or repo. |
| R-304 | Recovery flow (trusted-device approval / recovery kit) is designed (ADR-0003) but not implemented; account recovery abuse surface is therefore untested. | High | OPEN | backend lead | Recovery is a top abuse target; needs rate limits, delays, notifications, and security regression tests before launch. |

## Platform & store

| ID | Risk | Sev | Status | Owner | Note |
|----|------|-----|--------|-------|------|
| R-401 | Apple mandates the iOS 26 SDK + Xcode 26 for App Store uploads (effective 2026-04-28). We build with Xcode 26.6 — compliant today, but this is a moving target. | Low | MITIGATING | release eng | Re-verify each cycle. Source: developer.apple.com/news/upcoming-requirements (accessed 2026-07-17). |
| R-402 | Privacy manifest, required-reason API declarations, and App Store privacy disclosures are drafted (PRIVACY.md) but not finalized against the shipped code. | High | OPEN | iOS lead | Disclosures must match actual behavior; mismatch is a rejection and a trust failure. |
| R-403 | Legal compliance (GDPR/UK GDPR/CCPA-CPRA, children's privacy, export/sanctions, data residency, law-enforcement response) is **not** determined by code and requires qualified counsel. | High | OPEN | legal (external) | This project cannot self-certify legal compliance. |

## Supply chain & operations

| ID | Risk | Sev | Status | Owner | Note |
|----|------|-----|--------|-------|------|
| R-501 | No SBOM/provenance pipeline yet; dependency advisory monitoring (cargo-audit) is configured in CI intent but not enforced on a running pipeline. | Medium | OPEN | release eng | CI defined in `.github/workflows`; not executed in this environment. |
| R-502 | Signing keys, push credentials (APNs), and App Attest server config are not provisioned; no key-compromise playbook rehearsal has occurred. | High | OPEN | ops | Separate keys per environment; never in repo/CI-visible-to-forks. |
| R-503 | External penetration test, mobile assessment, infrastructure review, and cryptographic review have **not** been performed. | Critical | OPEN | security architect | Launch blocker per mission statement. |

## Accepted risks (explicit)

| ID | Risk | Owner | Rationale |
|----|------|-------|-----------|
| R-901 | Delete-for-everyone and disappearing messages cannot guarantee deletion on a recipient who has copied, exported, screenshotted, or backed up content. | product | Inherent to any messaging system; surfaced honestly in UI and PRIVACY.md, not hidden. |
| R-902 | Screenshots cannot be reliably prevented on iOS. | product | Platform limitation; we redact the app switcher and offer previews control, and state this honestly. |
| R-903 | v1 is single-active-device by default; a second device with correct username/password is intentionally denied. | product | This is a feature (device binding), mitigated by the recovery model (ADR-0003). |

## How this file is used

- Every milestone report cross-references affected risk IDs.
- No item may move to `CLOSED` without a linked evidence artifact (test, audit letter, config).
- CI should fail a release build if any `Critical` risk is `OPEN` and not explicitly,
  time-box-accepted by the named owner.
