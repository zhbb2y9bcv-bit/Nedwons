# ADR-0016: Hybrid post-quantum MLS ciphersuite (X-Wing)

- **Status:** **Accepted — implemented 2026-07-20.** The MLS ciphersuite is now
  `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (IANA 0x004D). Key establishment is hybrid
  post-quantum; signatures remain classical (Ed25519) by deliberate, documented choice. Verified
  end-to-end: Rust core + FFI + Swift bridge (host **and** iOS 26.5 simulator) + live relay run,
  with the relay unchanged.

## Context

Nedwons' confidentiality rests on MLS key agreement (RFC 9420). The prior ciphersuite
(`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) uses an X25519 (classical Diffie–Hellman) KEM.
That is exposed to **harvest-now-decrypt-later (HNDL)**: an adversary can record today's ciphertext
and the public KEM material, then recover the session keys once a cryptographically-relevant quantum
computer exists. This is the same threat Signal (PQXDH) and Apple iMessage (PQ3) addressed.

The threat is specific to **key agreement**. Symmetric primitives (the MLS ChaCha20-Poly1305 record
layer, AES-256-GCM at-rest, HKDF, SHA-256, the Merkle transparency log) are not meaningfully
weakened by quantum attackers at our parameter sizes. **Signatures** (Ed25519 MLS credentials,
Secure Enclave P-256 device identity, KT log signatures, sender certs, DPoP) carry **no HNDL
exposure**: a signature is verified in real time, and a future quantum computer cannot retroactively
forge an authentication that already succeeded.

## Decision

**Adopt a hybrid PQ KEM now; keep signatures classical for now.**

1. **KEM → X-Wing** (X25519 **+** ML-KEM-768, combined). Hybrid means security is **never worse than
   the classical suite**: an attacker must break *both* X25519 and ML-KEM to recover a key, so even a
   flaw in the newer ML-KEM cannot regress us below today's guarantee. This closes the HNDL gap for
   all MLS key establishment: key packages, Welcomes, and the commit path secrets.

2. **Signatures stay Ed25519 (classical).** Rationale, stated honestly:
   - No HNDL exposure (above), so there is no *confidentiality* urgency.
   - The **Apple Secure Enclave has no post-quantum support**. Our hardware-backed device identity
     (ADR-0002) depends on non-exportable Enclave keys. Forcing a PQ-only signature today would mean
     **abandoning hardware-backed device binding** — a real, immediate security regression traded for
     a not-yet-urgent one. That trade is not worth it.
   - The right end state is **hybrid dual-signing** (Enclave P-256 **and** a software PQ signature
     such as ML-DSA), which our versioned, domain-separated transcripts already leave room for. That
     is tracked as future work (**R-908**), not this ADR.

## Implementation

- **`core/mls-core`**: `CIPHERSUITE` / `CIPHERSUITE_NAME` set to the X-Wing suite (0x004D). No other
  code change — MLS, the durable state machine, sizes, and the FFI surface are ciphersuite-agnostic.
  The FFI `capabilities()` string now reports the PQ suite.
- **Vendored provider** (`core/vendor/openmls_rust_crypto`): the stock `openmls_rust_crypto 0.5.1`
  left the X-Wing KEM arm `unimplemented!()`. We vendor it via `[patch.crates-io]` in **all three**
  workspaces (`core/mls-core`, `core/mls-ffi`, `services`) with three minimal, `PQ patch`-commented
  changes: implement the X-Wing KEM arm, advertise the suite in `supports`, and lift the `hpke-rs`
  stack to **0.7.0** with its `experimental` feature (RustCrypto `x-wing` + `ml-kem` — libcrux stays
  off the executed KEM path). See the vendored crate's README for the exact diff and retirement
  trigger (an upstream provider that supports X-Wing directly).
- **Relay: no change.** The relay is MLS-blind — it forwards opaque ciphertext and never links the
  MLS core (its `mls-core` dependency is dev-only, for the integration harness). Larger PQ key
  packages/Welcomes stay far inside existing bounds (below), so no endpoint limits changed. This is
  the blind-relay architecture paying off: a ciphersuite change touched **zero** relay code.

## Consequences

- **Positive — supply-chain hygiene improved as a side effect.** The `hpke-rs 0.7` upgrade advanced
  the whole transitive libcrux chain to advisory-fixed versions (`libcrux-sha3 0.0.10`,
  `libcrux-secrets 0.0.6`) and dropped `libcrux-aesgcm` entirely. **All seven previously-suppressed
  libcrux RUSTSEC advisories are now resolved** — `cargo audit` is clean across all three workspaces
  except one compile-time proc-macro advisory (`docs/SECURITY_AUDIT_EXCEPTIONS.md`, R-505 largely
  closed).
- **Wire sizes grow, comfortably within bounds.** Measured hybrid sizes: key package **2647 B**
  (limit 65536), Welcome **5435 B** and commit **5428 B** (relay body limit 262144) — ~2–4 % of the
  caps. No limit changes needed.
- **Pre-release timing = free.** No deployed groups exist to migrate; the ciphersuite is pinned with
  no negotiation. Doing this after launch would have required a live group-reinitialization
  migration.
- **Honest residual.** This delivers **post-quantum confidentiality**, not post-quantum
  authentication. An attacker with a future quantum computer still could not read past traffic
  (the win), but PQ *signature forgery* is out of scope until hybrid dual-signing lands (R-908). We
  document this rather than marketing "fully post-quantum."

## Verification

- Rust: `mls-core` (8 test binaries), `mls-ffi` (6) green on the PQ provider; `mls-ffi` `envelope`
  fuzz target 15 000 runs, no crash. `capabilities` contract test updated.
- Services: all 27 integration binaries green against a fresh `nedwons_test`, including
  `membership_sim` and `self_group` which drive **real X-Wing MLS clients through the relay**.
- Swift: `NedwonsMLS` bridge tests (13) pass on host **and** in the iOS 26.5 simulator (real X-Wing
  messages exchanged); `NedwonsApp` (10) green; xcframework rebuilt (bindings surface unchanged);
  Nedwons app + NotificationService **BUILD SUCCEEDED**.
- Live: `scripts/self_group_live_run.sh` → **LIVE_OK** (auth → secret → self-group link →
  consumption fan-out) with real X-Wing bytes over a booted `nedwons-api`.
