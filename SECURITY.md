# Security

This document describes the security posture, hardening baseline, and the
vulnerability-disclosure process. It complements [THREAT_MODEL.md](THREAT_MODEL.md)
(what we defend against) and [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) (how).

## Standards baseline

- **OWASP MASVS/MASTG** — mobile verification baseline (iOS).
- **OWASP ASVS** + **OWASP API Security Top 10** — backend/API controls.
- **NIST SP 800-63B** — authentication guidance (used as guidance; no claim of formal
  government compliance without independent assessment).
- **NIST SSDF** — secure development lifecycle.

A traceability matrix mapping each control to code, tests, evidence, exceptions, and owners
is maintained at [docs/TRACEABILITY.md](docs/TRACEABILITY.md) (seeded; grows per milestone).

## Client hardening (iOS)

- Non-exportable Secure Enclave P-256 device key; strict Keychain ACLs (`ThisDeviceOnly`),
  passcode/biometric gating where appropriate.
- Local database encrypted with a Keychain-held key; iOS Data Protection classes per access
  need. No passwords stored on device.
- App-switcher snapshot redaction; optional local app lock; minimized notification previews.
  (iOS cannot prevent screenshots — stated honestly.)
- Least-privilege entitlements; audited URL schemes, universal links, pasteboard, app groups,
  keychain access groups. Accurate privacy manifest + required-reason API declarations.
- TLS 1.3 with authenticated hostname validation; **no** `trustAll`/permissive
  `TrustManager` path can enter a release build. Pinning decided per threat model with
  backup pins and rotation if adopted.
- App Attest as **defense-in-depth only** — never a substitute for device-key proof.

## Backend hardening

- Memory-safe Rust; schema-first, versioned APIs; strict allowlist validation with max
  sizes/depth/counts; idempotent, atomic, replay-aware mutations.
- Object-level authorization on every endpoint (no IDOR/BOLA); no trust in client-supplied
  identity/role/ownership. DB constraints + compare-and-swap enforce authorization close to
  the data.
- Secrets in KMS/HSM/secret manager; workload identity; least privilege; rotation; no
  long-lived secrets in images, CI variables visible to forks, source, binaries, or logs.
- Separate keys/identities/databases/object-stores/domains per environment
  (dev/staging/prod).
- Network segmentation, restricted egress (SSRF prevention), non-root minimal images,
  read-only filesystems where possible, dropped Linux capabilities, resource limits, signed
  artifacts. Production admin requires phishing-resistant MFA + JIT least privilege;
  **there is no "view user messages" admin function.**

## CI security gates (enforced intent — see RISK_REGISTER R-501)

CI must fail on: format/lint/type/compile/test failures; committed secrets; known
critical/high dependency vulns without an approved, time-bounded exception; insecure release
config (debug signing, cleartext traffic, exported components, unsafe entitlements, missing
privacy metadata); migration failures; missing SBOM/provenance for release artifacts.
Tooling: SAST, SCA (`cargo-audit`), secret scanning, mobile binary analysis, IaC scanning,
API fuzzing, property-based tests and fuzzers for parsers/transcripts/crypto adapters.

## Vulnerability disclosure

- A machine-readable [`.well-known/security.txt`](contracts/security.txt) is published with
  a monitored security contact and this policy's URL.
- Report privately to the security contact. We acknowledge within a target window, triage by
  severity, and coordinate disclosure. Do not test against other users' accounts or data.
- We maintain an incident-response plan, a key-compromise playbook, and a dependency
  emergency-update process (see [docs/runbooks/](docs/runbooks/)). A bug bounty is planned
  post-launch.

## Pre-launch external review (required, not yet done — R-503)

Independent **mobile**, **backend/infrastructure**, and **cryptographic** reviews are
required before public production launch. Findings must be remediated or formally accepted
by the responsible owner.
