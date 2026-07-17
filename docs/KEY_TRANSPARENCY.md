# Key Transparency (R-201)

MLS encrypts to whatever device credentials it is given. It does **not** prove the server handed
out the *right* keys. A malicious or compelled key-directory server could substitute a victim's
device key for an attacker's (a MITM on identity). Key transparency (KT) is the defence: make the
key directory **auditable** so substitution and history-rewriting are detectable.

This document states precisely what Sentinel's KT does and — just as importantly — what it does
**not** yet do. Do not describe protection this system does not provide.

## What is implemented

An **append-only Merkle transparency log** using the **RFC 6962** (Certificate Transparency)
construction — a mature, precisely specified *standard*, not a bespoke protocol. It is pure, tested
Rust in `auth_core::transparency`, driven by a Postgres-backed directory in
`services/api/src/transparency.rs`, and verified on the client in
`SentinelKit/Transparency.swift`.

- **Every account→device-key binding is a log leaf.** At device enrollment the server appends
  `account || device || public_key` as an RFC 6962 leaf (gapless index).
- **Signed Tree Heads (STHs).** The server signs `(tree_size, root, timestamp)` with the log's
  ECDSA-P256 key (production: KMS/HSM). Clients verify the signature under a **pinned** log public
  key distributed out of band (in the shipped app binary), not one the server hands them at runtime.
- **Inclusion proofs.** A client verifies its own enrolled key is present under the signed root —
  so the server cannot serve a key it never logged.
- **Consistency proofs.** A client verifies a newer STH is an append-only extension of one it saw
  before — so the server cannot rewrite history (retroactively swap a logged key).
- **Client self-monitoring.** The client trusts nothing here: `selfMonitorKeyTransparency` fetches
  the STH, verifies its signature under the pinned key, fetches its account's logged bindings
  (pinned to the STH size), verifies each inclusion proof against the signed root, and checks the
  logged key is exactly the one it enrolled. Outcomes: `ok`, `keyMismatch` (substitution),
  `notIncluded` (server never published it), `logKeyChanged`, `badSignature`, `badProof`.

**Tested:** `auth-core/tests/transparency.rs` property-tests inclusion + consistency over many tree
sizes with tamper/rewrite rejection and anchors the hashing against raw SHA-256;
`services/api/tests/transparency.rs` proves a client verifies a signed STH, that its enrolled key is
included (no substitution), and append-only growth; `SentinelKitTests/TransparencyTests.swift` unit-
tests the Swift verifier; and the live smoke has the Swift client self-monitor against the real Rust
server end to end.

## What is NOT implemented (do not claim these)

- **Split-view / equivocation resistance.** A malicious server could show *different but internally
  consistent* logs to different clients. Detecting this needs **gossip / third-party witnessing**
  (clients and independent monitors cross-checking STHs). Not built. Until it is, a client only
  knows *its own* view is self-consistent — not that it is the *same* log everyone else sees.
- **Efficient verifiable non-inclusion / "this is the latest key".** Proving the *absence* of a
  rogue key, or that a returned key is the newest for an account, efficiently and privately, needs a
  **verifiable map** (CONIKS / Parakeet-style VRF-indexed prefix tree). Not built. Self-monitoring
  approximates it: a client enumerates *its own* logged bindings and flags any it did not create.
- **Independent audit.** This is a standard construction, carefully tested, but has **not** had a
  specialised third-party cryptographic review. Required before claiming KT protection at launch.
- **Atomic enroll+log / reconciliation.** The binding is appended best-effort at registration; a
  transient failure is logged, not fatal (the *client's* self-monitor is the real check, and would
  flag a missing binding). Production should couple enrollment and the append transactionally, plus
  a reconciliation sweep.

## Honest posture

Today: **manual safety-number verification remains the primary guarantee against a malicious key
directory**, backed by this log which detects logged-key substitution and history rewriting via
client self-monitoring. This is a strong, standard foundation — but it is **not** a complete
anti-equivocation KT system, and must not be marketed as "the server cannot substitute keys" until
gossip/witnessing, a verifiable map, and an external audit land (tracked in RISK_REGISTER R-201).
