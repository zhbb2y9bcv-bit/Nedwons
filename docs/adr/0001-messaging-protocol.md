# ADR-0001: Messaging protocol and cryptographic library

- **Status:** Accepted
- **Date:** 2026-07-17
- **Deciders:** security architect, crypto integrator
- **Sources accessed 2026-07-17:** crates.io API for `openmls` (0.8.1, MIT);
  RFC 9420 (MLS), RFC 9750 (MLS architecture); Signal `libsignal` license/support statement.

## Context

We need end-to-end encryption for 1:1 and group messaging with forward secrecy,
post-compromise security, asynchronous setup, authenticated group membership with epoch
changes, and no custom cryptography. The mission forbids writing our own primitives/ratchet
and forbids copying AGPL code into a closed-source product.

Candidates evaluated:

1. **Signal Protocol via `libsignal`** — PQXDH + Double Ratchet, the most field-proven
   design. However, the repository states outside use is unsupported, exposes unstable
   integration APIs, and is **AGPL-3.0**. Using it in a closed-source commercial app would
   require open-sourcing our app or a separate license/support agreement from Signal.
   Re-implementing Signal Protocol from the spec to dodge the license is explicitly rejected
   (it would be custom crypto and legally dubious).
2. **MLS (RFC 9420) via OpenMLS** — standardized IETF protocol; one protocol covers 1:1 and
   groups; epoch-based membership with rekeying on add/remove; forward secrecy +
   post-compromise security. OpenMLS **0.8.1 is MIT-licensed** (verified today), which is
   legally compatible with a closed-source commercial product. It has a growing audit history
   and active maintenance.

The product chose Apple-only (ADR-0005) and a Rust backend/core (ADR-0004), so a Rust MLS
library integrates cleanly on both client (via FFI) and server.

## Decision

Adopt **MLS (RFC 9420)** as the messaging protocol, implemented with **OpenMLS 0.8.1
(MIT)**, used through a narrow adapter in `core/`. Ciphersuite is chosen **explicitly and
versioned** (default `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`); no silent suite
negotiation. Test vectors are shared across iOS and backend.

## Consequences

**Positive:** legally clean for closed source; one protocol for 1:1 + groups; standardized
and independently specified; native Rust fit; epoch rekeying gives clean membership security.

**Negative / risks:**
- MLS 1:1 has less large-scale field history than Double Ratchet in Signal's deployment
  (accepted; MLS is standardized and reviewed). *(R-202)*
- Requires a small, fuzzed Rust↔Swift FFI boundary (ADR-0004 / `core/`).
- **Key transparency is still required** to detect malicious server key substitution; MLS
  does not provide it by itself. *(R-201, launch blocker for stronger claims.)*
- Independent cryptographic review of our OpenMLS usage is required pre-launch. *(R-202, R-503)*
- Post-quantum: classical ciphersuite in v1; hybrid PQ deferred until standardized MLS PQ
  suites are available in OpenMLS, and not advertised meanwhile. *(R-203)*

## Rejected

- `libsignal` (AGPL/unsupported for external use) without a license — legal risk.
- Reimplementing any protocol from a specification — custom crypto, forbidden.
- Mixing AEAD/KDF suites ad hoc — forbidden; suite is explicit and versioned.
