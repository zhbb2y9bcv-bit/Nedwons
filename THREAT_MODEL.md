# Threat Model

Method: **STRIDE** for security threats, **LINDDUN** for privacy threats. This document
lists assets, attackers, entry points, the threat enumeration, and — most importantly —
the **security invariants**, each mapped to a test (existing or planned). An invariant
without a test is a claim we are not yet allowed to make.

Scope: Apple-only client, Rust backend. Last updated 2026-07-17.

## 1. Assets

| Asset | Where | Protection |
|-------|-------|-----------|
| Message/attachment plaintext | On device only | E2EE (MLS); local encrypted store |
| Private device key (proof-of-possession) | Secure Enclave | Non-exportable hardware key |
| Private MLS/identity keys | Keychain (ThisDeviceOnly) + Enclave-wrapped where possible | At-rest key hierarchy |
| Password | Never stored plaintext; Argon2id hash server-side | Argon2id + salt + KMS pepper |
| Refresh token | Client Keychain; server stores hash only | Rotation + reuse detection |
| Routing metadata | Server DB | Minimized; retention-bounded |
| Social graph / presence | Server DB (minimized) | Off-by-default presence; minimization |

## 2. Attackers

Network MITM; malicious/compromised server, DBA, cloud/CDN/object-store operator, push
provider, analytics provider; malicious users (malformed content, abuse); compromised
client environments (jailbroken, hooked, repackaged, screen-controlled); thief with a
stolen locked/unlocked device; insider/support-tool misuse; CI/dependency/signing-key
compromise; spam/harassment/impersonation/fraud actors; passive traffic-analysis observers.

## 3. Entry points

Registration, login, refresh, device enrollment, recovery, username/password change,
account deletion, message send/receive, receipts, attachment upload/download, push token
registration, call signaling/TURN issuance, reporting, and all admin endpoints.

## 4. STRIDE (selected, highest-signal)

| Threat | Example | Control | Invariant / test |
|--------|---------|---------|------------------|
| **S**poofing | Attacker logs in with stolen password | Mandatory device-key proof-of-possession | INV-2 (tested) |
| Spoofing | Server substitutes a device/identity key | Safety numbers + key transparency (planned) | INV-9 (planned, R-201) |
| **T**ampering | Modified auth transcript | Signature over canonical transcript | INV-4 (tested) |
| Tampering | Reordered/duplicated messages | MLS counters + dedup | INV-*, Milestone 2 |
| **R**epudiation | Deny an action | Tamper-evident audit events, no secret logging | INV-8 |
| **I**nfo disclosure | Server reads messages | E2EE; server sees ciphertext only | INV-1 (planned test, R-104) |
| Info disclosure | Push leaks content | Opaque wake-up payloads | INV-7 |
| Info disclosure | Logs leak secrets/plaintext | Source-side redaction, allowlist fields | INV-8 |
| **D**enial of service | Login brute force / lockout abuse | Layered rate limits; no permanent victim lockout | ABUSE_MODEL.md; INV-5 |
| **E**levation | Client claims a role/ownership | Server trusts no client-supplied authz | INV-6 |
| Elevation | Replay a consumed challenge/token | Single-use, atomic consume; refresh family revoke | INV-4, INV-3 (tested) |

## 5. LINDDUN (privacy, selected)

| Threat | Example | Control |
|--------|---------|---------|
| **L**inkability | Correlate users across requests | Random correlation IDs unrelated to user IDs; minimal metadata |
| **I**dentifiability | Hardware identifier tracking | **No MAC/IMEI/ad-ID/serial used** (ADR-0002); random account/device IDs |
| **N**on-repudiation (privacy sense) | User cannot deny participation | Minimize retained routing/presence; sealed-sender (planned) |
| **D**etectability | Observe that two users talk | Metadata minimization; evaluate sealed sender (R-204, not yet advertised) |
| **D**isclosure of info | Address-book upload | Contact discovery by username/QR/invite only; no raw address book |
| **U**nawareness | Users don't know what's shared | Reporting shows exactly what will be sent; privacy settings granular |
| **N**on-compliance | Retention beyond need | DATA_RETENTION.md schedules; deletion propagation (INV-10) |

## 6. Security invariants (the contract)

Each invariant is enforced by a test where possible. **T** = tested in this repo now,
**P** = planned with a named milestone.

| ID | Invariant | Status |
|----|-----------|--------|
| INV-1 | The service never receives message/attachment/call/backup/local-search **plaintext** in the normal E2EE path. | **T (Rust)** — `mls-core/tests/e2ee.rs` (ciphertext has no plaintext; outsider/removed-member cannot decrypt) + `nedwons-api/tests/relay_e2ee.rs` (real MLS ciphertext through the HTTP relay; direct DB query confirms no plaintext at rest). On-device Swift path pending (R-101). |
| INV-2 | Username + password **without** an active registered device key cannot create or refresh a session. | **T** — `auth-core` tests `login_denied_without_device_key`, `refresh_requires_device_signature`. |
| INV-3 | A private device/identity key is never exportable from secure hardware when the platform supports it. | **P** — verified by on-device test (R-101); enforced by Secure Enclave key attributes. |
| INV-4 | Every challenge is action-bound, account-bound, device-bound, expiring, and single-use. | **T** — `auth-core` tests for replay, expiry, wrong-action, wrong-account, wrong-device, double-consume. |
| INV-5 | Every state-changing API op is authenticated, object-level authorized, replay-aware, schema-validated, size-bounded, and idempotent where retried. | **P** — Milestone 1/2 API layer; `auth-core` proves the replay/idempotency core. |
| INV-6 | The backend never trusts a client-supplied user id, role, group membership, device status, timestamp, entitlement, receipt, or authz decision. | **P** — enforced at API/DB layer; `auth-core` never accepts client-asserted identity. |
| INV-7 | Push providers receive no message plaintext or decryption key. | **P** — Milestone 2 push dispatch; payloads are opaque locators. |
| INV-8 | Logs/traces/metrics/crash/analytics contain no passwords, tokens, private keys, plaintext, contact book, full IP history, or raw recovery material. | **P** — source-side redaction; log-redaction tests in Milestone 1/2. |
| INV-9 | Protocol downgrades and identity-key changes are visible and cannot silently remove security properties. | **P** — explicit versioning (no silent negotiation); key-change UI + transparency (R-201). |
| INV-10 | Revocation and deletion propagate to active sessions and queued server data on documented, tested timelines. | **P** — Milestone 1 (session revocation) + retention jobs; partially in `auth-core` (family revoke). |

## 7. Fail-closed policy

Authentication, authorization, integrity, signature, replay, protocol-version, and
key-state errors **fail closed** (deny, audit without storing secrets). Network and
availability errors **fail safe and recoverable** (retry with backoff, no data loss, no
security downgrade). This split is enforced in `auth-core`'s error type: `AuthError`
distinguishes `Denied` (security, generic external message) from transient conditions.

## 8. Out of scope for v1 (explicit)

- Preventing screenshots (platform limitation, R-902).
- Guaranteeing deletion on a recipient who copied content (R-901).
- Full metadata privacy / sealed sender (R-204, not advertised).
- Post-quantum protection (R-203, not advertised).
- Android/Samsung (ADR-0005).
