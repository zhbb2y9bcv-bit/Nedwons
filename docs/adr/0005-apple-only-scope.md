# ADR-0005: First release targets Apple platforms only

- **Status:** Accepted
- **Date:** 2026-07-17
- **Deciders:** product, security architect
- **Decision input:** explicit product choice — "make this Apple only; do not make it
  available whatsoever for Android devices."
- **Sources accessed 2026-07-17:** Apple upcoming-requirements (iOS 26 SDK + Xcode 26 minimum,
  effective 2026-04-28), developer.apple.com/news/upcoming-requirements.

## Context

The original brief covered iOS **and** Android/Samsung. The product owner decided to ship
Apple-only for the first release. This machine has Xcode 26.6 / Swift 6.3.3 (so iOS is
genuinely buildable) and no Android SDK.

## Decision

Target **iOS/iPadOS only**, distributed through the **Apple App Store**. Produce **no**
Android/Samsung/Google-Play/Galaxy-Store code, build tooling, flavors, or store metadata.

Keep the **backend, cryptographic core, and wire contracts platform-neutral** so a second
platform remains feasible later **without** redesign:
- `core/` (Rust) has no Apple-specific types at its API boundary; the Apple-specific parts
  (Secure Enclave, Keychain) live in `apps/ios`.
- `contracts/` and the canonical transcript are defined independent of platform.
- No decision here bakes in an assumption that would need reversing to add Android.

Build baseline: **iOS 26 SDK, Xcode 26+** (Apple mandate since 2026-04-28). We use Xcode
26.6 — compliant. Re-verify each release cycle (R-401).

## Consequences

**Positive:** smaller surface to build, test, and audit; deeper Apple platform integration
(Secure Enclave, App Attest, Keychain, Data Protection, APNs) without a lowest-common-
denominator abstraction; faster to a genuinely working, testable product.

**Negative / risks:**
- No Android reach for v1 (explicit product tradeoff).
- Cross-platform interoperability tests in the mission are **scoped to Apple↔Apple + backend**
  for now; a future Android target would add Android↔Apple vectors.
- We must resist Apple-specific leakage into `core/` and `contracts/` to keep the door open;
  reviewers should guard this boundary.

## Notes

This ADR supersedes all Android/Samsung requirements in the original brief for v1. If a
second platform is later approved, add a new ADR rather than editing this one.
