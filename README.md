# Nedwons

Nedwons is a private, end-to-end encrypted messaging application for Apple platforms
(iPhone and iPad, distributed through the Apple App Store). "Nedwons" is the working
product name and may change before launch.

> **Honesty first.** No software of this complexity can be honestly called perfect,
> unhackable, "military-grade", or zero-risk. This project does not make those claims.
> Its concrete goal is: no known critical/high vulnerabilities at launch, no custom
> cryptography, security invariants enforced by tests, an independently reviewable
> design, external audits before public production launch, and a documented
> vulnerability-disclosure and patch process. See [RISK_REGISTER.md](RISK_REGISTER.md)
> for everything that is unproven, assumed, or accepted.

## Scope decision (this repository)

This project was originally specified as iOS **and** Android. Per an explicit product
decision recorded in [docs/adr/0005-apple-only-scope.md](docs/adr/0005-apple-only-scope.md),
**the first release targets Apple platforms only.** No Android/Samsung code, build
tooling, or store metadata is produced. The backend, cryptographic core, and wire
contracts are deliberately kept platform-neutral so a second platform remains possible
later without redesign.

## Repository layout

| Path         | Owner boundary | Contents |
|--------------|----------------|----------|
| `apps/ios/`  | iOS            | Native Swift / SwiftUI application (Xcode project). |
| `core/`      | Shared crypto  | Rust protocol/crypto integration core, exposed to Swift over a narrow, fuzzed FFI. |
| `services/`  | Backend        | Rust backend modules (modular monolith): accounts, device registry, key service, relay, push, abuse, audit. |
| `contracts/` | Cross-cutting  | Versioned API and wire schemas; canonical-transcript definitions; shared test vectors. |
| `infra/`     | Ops            | Local dev environment and deployment definitions (CPU services; future isolated GPU pool). |
| `docs/`      | All            | Architecture, threat/privacy/abuse models, ADRs, runbooks, and test evidence. |

## Documents you should read first

1. [ARCHITECTURE.md](ARCHITECTURE.md) — components, trust boundaries, data flows.
2. [THREAT_MODEL.md](THREAT_MODEL.md) — STRIDE + LINDDUN, attackers, and the executable security invariants.
3. [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) — protocol, primitives, key lifecycle, what is and isn't protected.
4. [SECURITY.md](SECURITY.md) — hardening posture and vulnerability-disclosure process.
5. [PRIVACY.md](PRIVACY.md) / [DATA_RETENTION.md](DATA_RETENTION.md) / [ABUSE_MODEL.md](ABUSE_MODEL.md).
6. [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) and [RISK_REGISTER.md](RISK_REGISTER.md).
7. [PERFORMANCE.md](PERFORMANCE.md) — messaging efficiency: fan-out, long-poll, idempotency, and the counterintuitive pitfalls.

## Build & test status (this working copy)

| Component | Toolchain present | Compiles here | Tested here |
|-----------|-------------------|---------------|-------------|
| `services/auth-core` (Rust) | Rust 1.97.1 stable | ✅ | ✅ `cargo test` — 17 unit + golden vector |
| `services/api` (Rust: Postgres stores + axum HTTP + E2EE relay + WebSocket) | Rust 1.97.1 + PostgreSQL 17 | ✅ | ✅ 24 integration tests vs **real Postgres**: concurrency races, full HTTP flow, MLS relay + DB no-plaintext, fan-out, idempotency, long-poll, WebSocket push, at-least-once peek/ack, load (idle-waiters > pool) |
| `core/mls-core` (Rust: OpenMLS E2EE) | Rust 1.97.1 | ✅ | ✅ 3 tests — encrypted exchange, no plaintext in ciphertext, removed-member epoch |
| `apps/ios/NedwonsKit` (Swift crypto/protocol + full HTTP client) | Xcode 26.6 / Swift 6.3.3 | ✅ `swift build` | ✅ `swift test` — 7 tests |
| `apps/ios/NedwonsUI` (design system + **wired app screens + AppModel**) | Swift 6.3.3 | ✅ `swift build` | — (buttons wired to the client; runs in Xcode) |
| **Swift client ↔ live backend** (auth + profiles + friends + groups + messaging) | Swift + Rust + Postgres | ✅ | ✅ `scripts/swift_backend_smoke.sh` — SMOKE_OK (INV-2 negative, befriend→group→deliver, non-friend-group 403) |
| `apps/ios/NedwonsUI` (SwiftUI design system + screens) | Swift 6.3.3 | ✅ `swift build` | — (visual; no unit tests) |
| Cross-language interop (Swift signs → Rust verifies) | both | ✅ | ✅ `INTEROP_OK` + byte-identical transcript vectors |
| `infra` (docker-compose) | Docker/Colima (installed) | ✅ `config` validates | ✅ Postgres service verified up; API image build not run |
| `apps/ios/Nedwons` (`@main` app target) | Xcode 26.6 | requires Xcode app target (see apps/ios/README.md) | ⚠️ not run on a simulator/device (R-101) |
| `core/mls-ffi` Rust↔Swift MLS bridge (UniFFI 0.29) | Rust 1.97.1 + Swift 6.3.3 | ✅ implemented + packaged (`scripts/build_mls_ffi.sh` → `MlsFfi.xcframework`, macOS+iOS+sim) | ✅ Swift↔Rust integration test on the host slice **and RUNNING in the iOS simulator** (`scripts/test_mls_sim.sh`); + Rust FFI/adversarial tests + fuzz. Device slice compiles; **on-device *run* still R-101.** |

See each milestone report in the git history for exactly what was run and what was not.

## Current milestone

**Milestone 0 (foundations) + the first tested slice of Milestone 1 (device-bound auth).**
The implemented, *tested* security property today is:

> A valid username and password, presented from a device that does **not** hold the
> account's enrolled private device key, cannot create a session.

This is proven by `cargo test` in `services/auth-core`. See
[docs/MILESTONE_LEDGER.md](docs/MILESTONE_LEDGER.md).
