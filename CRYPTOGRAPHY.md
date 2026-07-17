# Cryptography

**No custom cryptography.** Every primitive, protocol, ratchet, KDF, AEAD, password hash,
RNG, and signature format comes from a mature, maintained, independently reviewed
implementation used through a narrow adapter. This document records the choices, the key
lifecycle, and — explicitly — what is and is not protected.

See [ADR-0001](docs/adr/0001-messaging-protocol.md) for the protocol selection rationale.

## 1. Selected building blocks

| Purpose | Choice | Source / provenance | Notes |
|---------|--------|---------------------|-------|
| Group + 1:1 messaging protocol | **MLS (RFC 9420)** via **OpenMLS 0.8.1** | crates.io, MIT license (verified 2026-07-17) | Integrated in `core/mls-core` behind a narrow API. One protocol for 1:1 and groups; epoch-based membership; forward secrecy + post-compromise security. Tests prove no plaintext in ciphertext and removed-member epoch exclusion. |
| Message AEAD / KDF | Provided by MLS ciphersuite | RustCrypto within OpenMLS | We do **not** mix suites ad hoc; the ciphersuite is chosen explicitly and versioned. Default: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (classical). |
| Device proof-of-possession signature | **ECDSA P-256** | `p256` crate (RustCrypto) | Server-side verification; client signer is the Secure Enclave. Deterministic (RFC 6979) on the software test side. |
| Password hashing | **Argon2id (RFC 9106)** | `argon2` crate (RustCrypto) | Unique per-account salt; params benchmarked per environment; optional KMS pepper. |
| Attachment encryption | Per-object random key, chunked AEAD | RustCrypto AEAD | Fresh key per attachment; keys travel only inside the E2EE envelope. |
| RNG | Platform CSPRNG | `getrandom` / SecRandomCopyBytes (iOS) | No custom RNG. |
| Transcript hashing | SHA-256 | `sha2` (RustCrypto) | Used inside ECDSA and for domain-separated transcript digests. |
| Constant-time comparison | `subtle` | RustCrypto | For token/hash equality. |
| Secret zeroization | `zeroize` | RustCrypto | Best-effort wipe of sensitive buffers. |

All versions are pinned via `Cargo.lock`; advisories tracked with `cargo-audit` in CI
(intent recorded; see RISK_REGISTER R-501).

## 2. Properties the protocol must provide (and MLS does)

- End-to-end authentication + encryption for every message and control event.
- Forward secrecy and post-compromise security (key healing).
- Asynchronous setup while a recipient is offline (key packages).
- Unique per-device identity keys; signed key-package lifecycle.
- Replay, duplicate, out-of-order, skipped-key, and state-rollback handling.
- Authenticated group membership with **epoch changes after add/remove** — a removed
  member cannot decrypt future epochs.
- Cryptographic binding of conversation, sender device, recipient device/group epoch,
  message type, protocol version, and counters as associated data.
- Cryptographic agility via **explicit versioning** — never silent negotiation to a
  weaker suite.

## 3. Post-quantum

Classical MLS ciphersuite in v1. A hybrid PQ path is a documented direction, gated on
standardized, reviewed MLS PQ ciphersuites being available in OpenMLS. **We do not
advertise PQ security today** (RISK_REGISTER R-203).

## 4. The canonical authentication transcript

Device binding (registration, login, refresh, sensitive account ops) signs a **canonical,
length-prefixed, domain-separated transcript**. Canonical encoding matters: an ambiguous
encoding is a signature-forgery/confusion risk. The exact format is defined in
`services/auth-core/src/transcript.rs` and mirrored in the iOS client and
[contracts/](contracts/). Structure:

```
transcript =
    len32(DOMAIN)      || DOMAIN            // ASCII domain-separation tag, e.g. "app.sentinel.auth.v1"
 || u16(PROTOCOL_VER)
 || u8(ACTION)                              // Register=1, Login=2, Refresh=3, PasswordChange=4, DeviceEnroll=5, AccountDelete=6
 || len32(ACCOUNT_ID)  || ACCOUNT_ID        // 16-byte random internal account id
 || len32(DEVICE_ID)   || DEVICE_ID         // 16-byte random device record id
 || len32(PUBKEY)      || PUBKEY            // SEC1-encoded P-256 public key
 || len32(CHALLENGE)   || CHALLENGE         // 32-byte server-issued random challenge
 || u64(EXPIRES_AT)                         // unix seconds
 || len32(TXN_ID)      || TXN_ID            // 16-byte transaction id
```

The whole byte string is signed with ECDSA-P256 (SHA-256). Each field is length-prefixed so
no two distinct field vectors can serialize to the same bytes. The **DOMAIN + ACTION** bind
the signature to a specific purpose, preventing a signature captured for one action from
being replayed as another. Test vectors live alongside the code so the iOS client and the
Rust backend produce byte-identical transcripts.

## 5. Key lifecycle

| Key | Generation | Storage | Rotation | Destruction |
|-----|-----------|---------|----------|-------------|
| Device proof key (P-256) | Secure Enclave at registration | Non-exportable in Enclave | On re-enrollment / recovery | Key deleted on device revocation/wipe |
| MLS identity/leaf keys | Rust core on device | Keychain (ThisDeviceOnly) / Enclave-wrapped | Per MLS epoch/key-package lifecycle | Cryptographic erasure on account delete |
| Local DB wrapping key | Random on first run | Keychain (ThisDeviceOnly, biometric/passcode gated) | On app-lock policy change | Wiped on logout-with-erase / uninstall |
| Refresh token | Server random; client holds opaque value | Client Keychain; server stores hash | **Rotated every use**; family tracked | Family revoked on reuse/logout |
| Password hash | Argon2id server-side | PostgreSQL (hash + params) | Rehash on param upgrade or password change | Deleted on account deletion |
| Server pepper | Provisioned in KMS/HSM | KMS/HSM only, never DB/repo | Per rotation policy | KMS lifecycle |
| Attachment object key | Random per object on sender | Inside E2EE envelope only | N/A (per-object) | With message deletion / TTL |

## 6. Identity verification & key transparency

- **Safety numbers / fingerprints** with QR scanning; clear identity-change warnings that
  are *not* trained-away noise (shown only on real changes).
- **Key transparency** (append-only log or auditable key directory) is the mechanism that
  makes malicious server key substitution *detectable*. It is **not implemented yet**
  (RISK_REGISTER R-201) and is a launch blocker for any claim stronger than
  trust-on-first-use + manual verification.

## 7. What is NOT protected (honest limits)

- **Metadata**: the relay sees routing metadata and timing unless/until sealed-sender is
  implemented (R-204). We do not claim metadata privacy beyond what ships.
- **Endpoint compromise**: E2EE protects data in transit and at rest on the server, not a
  device already controlled by an attacker.
- **Recipient behavior**: screenshots, exports, and photographs of the screen defeat
  disappearing/delete-for-everyone (R-901/R-902).
- **No backdoor**: there is no universal key, moderation key, support-decryption, or silent
  AI upload. A future server-side feature needing plaintext would be a new, explicit,
  opt-in design — not a quiet change to this one.
