# ADR-0004: Backend and shared core language — Rust

- **Status:** Accepted
- **Date:** 2026-07-17
- **Deciders:** backend lead, security architect
- **Decision input:** explicit product choice — "Rust (Recommended)".

## Context

We need a memory-safe backend and a shared cryptographic/protocol core. The messaging
protocol library chosen (ADR-0001) is **OpenMLS**, a Rust crate. The client is Apple-only
(ADR-0005), so the core reaches Swift through an FFI boundary.

## Decision

Use **Rust** for both the backend (`services/`, a modular monolith) and the shared crypto
core (`core/`). The core is exposed to Swift via **UniFFI** with a small, fuzzed API surface.

Rationale:
- Memory safety without a GC, appropriate for security-sensitive network code.
- **One language and one crypto-adapter surface** shared between core and backend — fewer FFI
  boundaries to fuzz, and canonical transcripts/test vectors live in one place and are reused
  verbatim on the server.
- OpenMLS and the RustCrypto ecosystem (`p256`, `argon2`, `sha2`, `hmac`, `subtle`, `zeroize`)
  are mature, maintained, and auditable.

Datastores: **PostgreSQL** for durable relational state; an **object store** for ciphertext
attachments; a deliberately scoped **ephemeral queue/cache** only where needed. Redis-class
stores are **never** the source of truth for auth, revocation, membership, or message
durability.

## Consequences

**Positive:** shared canonical encoding across client-core and server (the `transcript`
module is literally reused); strong safety; good async story (`tokio`/`axum`).

**Negative / risks:**
- Slower to write than Go; smaller hiring pool. *(Accepted.)*
- FFI boundary must be memory-safe at the API boundary and fuzzed (ADR-0001 consequence).
- Async Rust has a learning curve; mitigated by keeping security logic (`auth-core`) pure and
  storage-agnostic (ADR-0006).

## Rejected

- **Go** — faster to write and excellent for relay/WebSocket work, but would place crypto
  logic in a second language, requiring test vectors and canonical transcripts to cross an
  extra boundary. The single-language benefit outweighed Go's velocity for this project.
- **Microservices from day one** — rejected in favor of a modular monolith until scale
  evidence justifies the operational cost; module boundaries are kept strong so extraction is
  possible later.
