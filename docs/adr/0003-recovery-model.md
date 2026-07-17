# ADR-0003: Account recovery model — Recoverable Secure Mode (default)

- **Status:** Accepted
- **Date:** 2026-07-17
- **Deciders:** product, security architect
- **Decision input:** explicit product choice — "Recoverable secure mode (recommended)".

## Context

Device binding (ADR-0002) means a lost device would, by default, mean a lost account. The
mission requires an explicit, deliberate recovery choice and forbids making legitimate
recovery impossible without warning.

## Decision

Default to **Recoverable Secure Mode**:

- A new device can be enrolled **only** via (a) approval from an existing trusted device, or
  (b) a high-entropy, one-time **recovery kit** generated on the original device.
- Recovery requires reauthentication, an **enrollment delay** for risky cases, security
  **notifications** to existing devices, server-side **rate limits**, and **revocation** of
  old sessions on completion.
- Recovery does **not** silently restore message plaintext unless the user separately enabled
  an **E2EE backup** with a user-controlled recovery secret.
- **Trusted-device transfer** uses a QR-mediated, short-lived authenticated key agreement with
  a human-verifiable **short authentication string**; the old device displays exactly what is
  being approved; the server cannot substitute a device key undetectably.

**Irrecoverable Strict Mode** remains available as an opt-in: no trusted device and no
recovery kit means permanent account/message loss, shown clearly at setup behind a deliberate
confirmation. Mode is immutable or downgrade-only (strict→recoverable is *not* offered
silently; recoverable→strict requires explicit re-consent).

## Consequences

**Positive:** a dropped phone is not automatically catastrophic; recovery is cryptographically
sound (no server-substitutable key); users who want maximum strictness can opt in.

**Negative / risks:**
- Recovery is a **top abuse target** — needs delays, rate limits, notifications, and security
  regression tests before launch. *(R-304)*
- The recovery kit is high-value; UI must make its loss consequences and safe storage clear.
- A **Devices screen** must show device name, platform, enrollment date, last activity
  (privacy-rounded), trust state, and revoke — and must not let a user revoke the **last
  recovery path** without an explicit irreversible-loss warning.

## Status of implementation

Designed here; **not implemented** (R-304). The `auth-core` slice implements enrollment and
device-bound login primitives that recovery will build on (challenge binding, device records,
session/family revocation).
