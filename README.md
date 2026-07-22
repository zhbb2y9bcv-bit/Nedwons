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

| Component | Toolchain | Compiles | Tested |
|-----------|-----------|----------|--------|
| `services/auth-core` (Rust: device-bound auth logic) | Rust 1.97.1 | ✅ | ✅ `cargo test` — unit tests + golden cross-language vectors |
| `services/api` (Rust: Postgres stores + axum HTTP + E2EE relay + WebSocket) | Rust 1.97.1 + PostgreSQL 17 | ✅ | ✅ integration tests against **real Postgres**: concurrency races, full HTTP flow, relay-blindness (no plaintext in the DB), fan-out, idempotency, long-poll, WebSocket push, at-least-once ack, load (idle waiters exceeding the connection pool) |
| `core/mls-core` (Rust: OpenMLS E2EE core) | Rust 1.97.1 | ✅ | ✅ unit + property tests — encrypted exchange, no plaintext in ciphertext, removed-member epoch, crash-safe durable state, secret-message state machine |
| `core/mls-ffi` (Rust↔Swift MLS bridge, UniFFI 0.29) | Rust 1.97.1 + Swift 6.3.3 | ✅ packaged as `MlsFfi.xcframework` (macOS + iOS device + iOS simulator) via `scripts/build_mls_ffi.sh` | ✅ Rust-side integration/adversarial tests, continuous fuzzing (`content_decode`, `envelope`, `secret_state`), and a Swift↔Rust bridge test **running in the iOS simulator** (`scripts/test_mls_sim.sh`) |
| `apps/ios/NedwonsKit` (Swift crypto/protocol + full HTTP client + SwiftUI app shell) | Xcode 26.6 / Swift 6.3.3 | ✅ `swift build` | ✅ `swift test` |
| `apps/ios/NedwonsApp` (composition layer: real `SecretEngine` + self-group linker over the live MLS core) | Swift 6.3.3 | ✅ `swift build` | ✅ `swift test`, driven against the real Rust core |
| `apps/ios/Nedwons` (`@main` app target + Notification Service Extension) | Xcode 26.6 | ✅ builds and runs on the iOS simulator | ✅ launched, exercised, and screenshotted on-simulator; **not yet run on a physical device** (needs Apple Developer provisioning — App Group, shared Keychain, push cert, App Attest environment) |
| Swift client ↔ live backend (auth, profiles, friends, groups, messaging, self-group device linking) | Swift + Rust + Postgres | ✅ | ✅ live end-to-end scripts (`scripts/swift_backend_smoke.sh`, `scripts/self_group_live_run.sh`) against a booted server |
| Cross-language interop (Swift signs → Rust verifies, and vice versa) | both | ✅ | ✅ byte-identical golden test vectors on both sides |
| `infra` (docker-compose) | Docker/Colima | ✅ `config` validates | ✅ Postgres service verified up |

The backend, `mls-core`, and `mls-ffi` workspaces are formatted and linted clean (`cargo fmt`,
`cargo clippy -D warnings`) and audited for dependency vulnerabilities (`cargo audit`); the one
outstanding advisory is an unmaintained compile-time-only macro crate with no runtime exposure.
See each milestone report in the git history for exactly what was run and what was not.

## Current state

The messaging core, backend, and iOS client are implemented and tested end to end: device-bound
authentication, MLS group messaging with **hybrid post-quantum key exchange** (X-Wing: X25519 +
ML-KEM-768), sealed-sender delivery, key transparency with client-side self-monitoring, multi-device
support via a device self-group, view-once secret messages, and a Notification Service Extension for
contentless push. The implemented, *tested* security properties include:

> A valid username and password, presented from a device that does **not** hold the account's
> enrolled private device key, cannot create or refresh a session.

> The relay routes only opaque MLS ciphertext; a direct query of its own database confirms it
> never stores plaintext.

These are proven by the automated test suites listed above, not asserted. The remaining gaps are
strictly hardware- and deployment-bound (physical-device testing, Apple provisioning, live push
delivery, external security audits) — see [RISK_REGISTER.md](RISK_REGISTER.md) for the complete,
honest list of what is unproven, assumed, or accepted. See
[docs/MILESTONE_LEDGER.md](docs/MILESTONE_LEDGER.md) for the full history.
