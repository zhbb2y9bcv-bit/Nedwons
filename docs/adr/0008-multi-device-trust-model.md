# ADR-0008: Controlled multi-device trust (replaces strict single-active-device)

- **Status:** Accepted (design only — no code in this change)
- **Date:** 2026-07-17
- **Deciders:** security architect, iOS lead, backend lead, crypto integrator
- **Supersedes:** the single-active-device posture of ADR-0002 / R-903 (does **not** relax the
  password-only prohibition — that stays absolute).
- **Related:** ADR-0002 (device binding), ADR-0003 (recovery), ADR-0007 (MLS binding), ADR-0009
  (group membership), R-201 (key transparency), R-G0-2 (Enclave wiring), R-G0-5 (server↔MLS membership).
- **Sources accessed 2026-07-17:** Signal "Linked Devices" and device-transfer docs (for the QR +
  short-authentication-string enrollment pattern); RFC 9420 §on Add/Remove for per-device leaves.

## Context

v1 enforces **one active device per account** via the partial unique index
`devices_one_active_per_account ON devices(account_id) WHERE NOT revoked` (Gate 0 confirmed this is
real and load-bearing). A second device with the correct username/password is intentionally denied
(R-903). That is the correct *security* default, but it is not a viable *product*: mainstream
messengers need a phone + tablet, device upgrades, and desktop later. The correction must add
controlled multi-device **without** ever allowing password-only access (non-negotiable rule 3) and
**without** letting the server silently inject a device.

## Decision

Allow an account to hold **multiple non-revoked devices**, but a device may only be enrolled through
one of two authenticated ceremonies — never username+password alone:

1. **Trusted-device approval (primary path).** An already-enrolled device approves the new one:
   - The new device displays a QR code encoding its fresh device public key + a nonce.
   - The existing device scans it; both run an **ephemeral authenticated key agreement** and each
     displays a **short authentication string (SAS)** derived from the transcript. The user confirms
     the SAS matches on both screens (defeats a MITM injecting a rogue key).
   - The existing device signs an **enrollment authorization** binding {account, new device pubkey,
     device metadata} and the user approves after a local unlock/user-presence check.
   - App Attest is attached as defense-in-depth (bypassable signal only — R-301).
2. **Recovery-secret enrollment (no other device available).** The high-entropy recovery secret from
   ADR-0003 authorizes enrollment, with rate limits, notifications to any other devices, and an
   optional time delay/cancel window.

**Each device is one MLS client** — its own credential and leaf key; leaf private keys are never
shared or exported between devices. A newly enrolled device is added to the account's conversations
by an **authenticated MLS Add commit issued from an existing member device**, not by the server
(ADR-0009 makes MLS membership authoritative). Until it is added and processes the Welcome, it
cannot read any conversation.

**Device list & revocation.** The account exposes a device list (type/name, enrolled-at,
last-active, revoke). Revoking a device fails **closed** and cascades: invalidate its access tokens
+ refresh families, delete its push tokens and unclaimed KeyPackages, and drive an **MLS Remove
commit** so it cannot decrypt future epochs. Enrollment and revocation events are recorded in the
account's key-transparency record (R-201) so a server cannot add/hide a device undetected.

The first device remains the **primary** for bootstrap purposes only; there is no security tier
difference between hardware-backed devices beyond primary-vs-linked labeling. Software-signer devices
(R-G0-2 fallback) are a distinct **lower-assurance** class and are ineligible to *approve* new
enrollments.

## Alternatives considered

- **Keep single-active-device.** Rejected: blocks the product; upgrades already force the recovery
  path for every user.
- **Server-mediated device add (server vouches).** Rejected: the server could inject a device — the
  exact substitution threat key transparency exists to catch. SAS + transparency removes server trust.
- **Password (or password+OTP) to add a device.** Rejected: violates rule 3; a phished password must
  never yield a new session-capable device.
- **One shared account key across devices.** Rejected: destroys per-device revocation and MLS's
  per-leaf forward secrecy; a compromise of any device compromises all.

## Migration & backward compatibility

- **Schema:** drop `devices_one_active_per_account`; keep `devices` (add `label`, `kind`,
  `enrolled_at`, `last_active_at`, `assurance` ∈ {hardware, software}). Add `device_enrollments`
  (authorizing device, SAS-confirmed flag, method ∈ {trusted_device, recovery}, transparency ref).
  Existing accounts have exactly one device → it becomes the primary; **no data migration needed**
  and no existing session breaks (purely additive).
- **Protocol:** introduce an explicit enrollment message version (see R-G0-5 — envelopes/control
  messages currently carry no in-message version). Old clients that predate multi-device must reject,
  not silently ignore, an enrollment control message.
- **R-903** is rewritten from "single-active-device by default" to "additional devices require an
  authenticated enrollment ceremony; password-only is denied."

## Threats & mitigations

| Threat | Mitigation |
|--------|------------|
| Stolen unlocked primary approves a rogue device | Approval requires local user-presence/biometric; every other device is notified; transparency log makes it auditable; revocation is one tap. |
| MITM injects attacker key during QR scan | SAS comparison on both screens; enrollment authorization is signed over the agreed transcript. |
| Server silently enrolls a device | Enrollment must appear in the append-only transparency record; clients monitor their own device list (R-201). |
| Revocation race (device used mid-revoke) | Revocation is a single atomic state change that invalidates tokens + drives MLS Remove; fail-closed on any auth/epoch mismatch. |
| Downgrade via software-signer device | Software devices are lower-assurance and cannot approve enrollments; surfaced honestly in the UI. |

## Tests planned (before this ships as code)

- Enroll a second device via the SAS ceremony end to end; it can decrypt only after the MLS Add/Welcome.
- **Password-only add is denied** (regression guard for rule 3).
- Recovery-secret enrollment path with rate limit + notification.
- Revoked device: cannot refresh, cannot read the next epoch, push tokens purged.
- Transparency record contains every enroll/revoke; a device absent from it is rejected by the client.
- Concurrent enroll + revoke resolves deterministically (no orphaned MLS leaf).

## Consequences

Unlocks the product's multi-device requirement while keeping password-only impossible and making the
server untrusted for device identity. Hard dependencies: the MLS-Swift binding (ADR-0007), a
server-side representation of MLS membership (R-G0-5), and key transparency (R-201). This ADR is
**design only**; implementation is sequenced after those land.
