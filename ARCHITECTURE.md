# Architecture

Working name: **Nedwons**. Platform scope: **Apple only** (iOS/iPadOS), per
[ADR-0005](docs/adr/0005-apple-only-scope.md). Backend: **Rust modular monolith**, per
[ADR-0004](docs/adr/0004-backend-language.md).

This document defines components, trust boundaries, and data flows. It is intentionally
concrete about **what the server can and cannot see**, because that boundary is the whole
product.

## 1. System overview

```
┌───────────────────────────── Apple device (trusted, user-controlled) ─────────────────────────────┐
│  SwiftUI app (apps/ios)                                                                             │
│    ├─ UI / view models                                                                              │
│    ├─ Local encrypted store (SQLCipher-class DB, key in Keychain, Data Protection classes)          │
│    ├─ Rust crypto core (core/) via UniFFI  ── MLS state, message (un)sealing, transcript encoding    │
│    ├─ Secure Enclave: non-exportable P-256 device key  (proof-of-possession signer)                 │
│    └─ Keychain: DB wrapping key, refresh token, MLS secrets   (ThisDeviceOnly ACLs)                 │
└───────▲───────────────────────────────────────────────────────────────────────────────▲───────────┘
        │ TLS 1.3 (authenticated; optional pinning)                                        │ APNs
        │                                                                                  │ (opaque wake-up only)
┌───────┴──────────────────── Backend trust zone (assumed hostile to plaintext) ──────────┴───────────┐
│  services/ (Rust modular monolith, CPU-only core path)                                              │
│   ┌────────────┐ ┌───────────────┐ ┌──────────────┐ ┌───────────────┐ ┌──────────────┐             │
│   │ accounts / │ │ device        │ │ key directory│ │ conversation/ │ │ message relay│             │
│   │ auth       │ │ registry      │ │ (MLS key     │ │ group authz   │ │ + offline    │             │
│   │            │ │               │ │  packages)   │ │               │ │ envelope Q    │             │
│   └────────────┘ └───────────────┘ └──────────────┘ └───────────────┘ └──────────────┘             │
│   ┌────────────┐ ┌───────────────┐ ┌──────────────┐ ┌───────────────┐ ┌──────────────┐             │
│   │ attachment │ │ push dispatch │ │ call signal /│ │ abuse / report│ │ audit / sec   │             │
│   │ authz      │ │               │ │ TURN creds   │ │               │ │ events        │             │
│   └────────────┘ └───────────────┘ └──────────────┘ └───────────────┘ └──────────────┘             │
│         │                    │                                                                        │
│   ┌─────▼──────┐      ┌──────▼───────┐        ┌───────────────────────┐   ┌───────────────────────┐  │
│   │ PostgreSQL │      │ object store │        │ ephemeral queue/cache │   │ KMS / HSM (secrets,   │  │
│   │ (durable   │      │ (ciphertext  │        │ (NOT source of truth  │   │  pepper, signing)     │  │
│   │  state)    │      │  attachments)│        │  for auth/msg)        │   │                       │  │
│   └────────────┘      └──────────────┘        └───────────────────────┘   └───────────────────────┘  │
│                                                                                                      │
│   ┌───────────────── isolated GPU compute zone (Milestone 6, optional, no plaintext) ────────────┐  │
│   │  ComputeJob queue → cpu/gpu workers; no access to account/message DBs or signing keys.        │  │
│   └───────────────────────────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## 2. Trust boundaries

| # | Boundary | What crosses it | Assumption |
|---|----------|-----------------|------------|
| TB-1 | Secure Enclave ↔ app process | Signatures and MLS operations request key *use*, never key *material*. | Private keys are non-exportable; the app process is more exposed than the Enclave. |
| TB-2 | App ↔ backend (TLS 1.3) | Opaque ciphertext envelopes, signed auth transcripts, minimal routing metadata. | The network and the server are hostile to plaintext. The server authenticates devices but cannot read messages. |
| TB-3 | Backend ↔ PostgreSQL / object store / queue | Public device keys, refresh-token **hashes**, ciphertext, routing rows. | A compromised DBA or cloud operator must not obtain message plaintext or private keys. |
| TB-4 | Backend ↔ APNs | Opaque wake-up locator only. | The push provider must learn no message content or keys. |
| TB-5 | Core backend ↔ GPU compute zone | `ComputeJob` payloads only, no credentials/plaintext. | GPU workers are a separate, lower-trust zone; core messaging never depends on them. |
| TB-6 | Backend ↔ operators/support | Aggregate metrics, audit events. **No "read user messages" capability exists.** | Insider access is a modeled threat (see THREAT_MODEL.md). |

## 3. What the server stores (and does not)

**Stores:** random account IDs, normalized usernames, Argon2id password *hashes*,
public device keys, device record metadata (platform, app version, attestation status,
enrollment/last-security-event time, revocation state), refresh-token *hashes* with
family lineage, MLS key packages (public), ciphertext message envelopes with minimal
routing metadata + TTL, ciphertext attachments (object store), push tokens (revocable),
abuse/rate-limit counters, tamper-evident audit events.

**Never stores:** private device keys, private identity/MLS secrets, message or
attachment plaintext, decryption keys, passwords, biometric templates, raw recovery
material, or a backdoor/escrow key. There is no support-decryption path.

## 4. Core data flows

### 4.1 Registration (device binding — replaces the original MAC-address idea)

1. App requests a registration challenge. Server issues a random, single-use, short-lived
   challenge bound to the transaction, app version, protocol version, and action.
2. App generates a **non-exportable P-256 key in the Secure Enclave**.
3. App builds a canonical transcript (domain-separated: action, protocol version, account
   registration id, public key, challenge, expiration, transaction id) and signs it with
   the Secure Enclave key. App Attest assertion is attached as defense-in-depth.
4. Server verifies the signature against the presented public key, verifies App Attest,
   atomically consumes the challenge, and stores only the **public** key + metadata.

### 4.2 Login (two-stage, device-bound — the tested slice)

```
App ──(1) begin login (username, password) over TLS──▶ Server
Server: enumeration-resistant credential check (Argon2id verify, dummy-hash path,
        constant-ish timing, generic errors)
Server ──(2) fresh challenge bound to {account, device record, action=Login, proto, txn}──▶ App
App: Secure Enclave signs canonical login transcript
App ──(3) signature + transcript──▶ Server
Server: verify signature with the account's ACTIVE device public key;
        atomically consume challenge; fail closed on any mismatch/replay/expiry
Server ──(4) session: short-lived access token + rotating opaque refresh token──▶ App
```

**Invariant (tested in `services/auth-core`):** stage (2)–(4) cannot succeed without a
signature from the enrolled private key. Username + password alone → no session.

### 4.3 Send a direct message (Milestone 2 target)

1. App validates/normalizes input, mints a random client message id, writes a local
   pending record (immediate local ack after durable local queue).
2. Rust core encrypts via MLS for the recipient's device(s)/epoch.
3. App sends a bounded opaque envelope with an idempotency key.
4. Relay authenticates the sending device, authorizes conversation membership, stores/routes
   ciphertext, returns a **server receipt** (delivery to server, *not* a decryption claim).
5. Recipient dedups, decrypts locally, persists to the local encrypted store, and returns an
   **encrypted** delivery/read receipt per privacy settings.

## 5. Module boundaries (backend)

Each `services/` module owns its tables and exposes an internal API; cross-module calls are
explicit. This modular-monolith shape (ADR-0004) keeps strong boundaries without premature
microservice operational cost. Modules: accounts/auth, device registry, key directory,
conversation/group authz, message relay + offline queue, attachment authz, push dispatch,
call signaling/TURN, abuse/reporting, key transparency (planned), audit/security events,
admin. `auth-core` (implemented) is the pure, storage-agnostic logic used by accounts/auth.

## 6. Storage-seam design (why `auth-core` uses traits)

`auth-core` defines `CredentialStore`, `DeviceStore`, `ChallengeStore`, and
`RefreshTokenStore` traits with in-memory implementations for tests. The production
backend implements them over PostgreSQL, where **atomicity is enforced by the database**
(`DELETE ... RETURNING` / `UPDATE ... WHERE consumed = false`, unique constraints,
compare-and-swap version columns). This keeps security logic pure and unit-testable now,
with the durability/atomicity guarantees added at the DB layer without changing the logic.
See [docs/adr/0006-storage-seam.md](docs/adr/0006-storage-seam.md).

## 7. CPU-first; GPU-optional

Registration, auth, key distribution, routing, attachments, push, groups, and calls run
entirely on CPU servers. GPUs are never on the login/message path. Future AI/media features
default to on-device; any server-side compute goes through an isolated `ComputeJob` gateway
(TB-5) that has no access to credentials, message DBs, or signing keys, and whose failure
cannot affect core messaging. See [ARCHITECTURE.md §GPU](#7-cpu-first-gpu-optional) and
Milestone 6.
