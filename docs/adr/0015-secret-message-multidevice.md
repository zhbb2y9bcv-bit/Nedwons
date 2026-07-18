# ADR-0015: Account-wide single-consumption for Secret Messages (multi-device)

- **Status:** Proposed (design only — **not implemented**). The shipped Secret Message feature
  enforces view-once **per device**; this ADR designs the account-wide guarantee across a user's
  devices. Written before the protocol change, per the repo rule.
- **Date:** 2026-07-18
- **Deciders:** crypto integrator, backend lead, security architect
- **Context:** ADR-0008 (multi-device trust), ADR-0010 (MLS-authoritative membership), ADR-0012/0014
  (sealed sender), and the Secret Message feature (`mls_core::secret`).

## Problem

A view-once secret is delivered (like any MLS application message) to **every** device in the
recipient's group membership — each device holds its own sealed copy and its own reveal state. Today
the "one viewing opportunity" is enforced **per device**: the user could open the same secret once on
their phone *and* once on their tablet. The intended guarantee is **once per account**: consuming it
on any one device consumes it everywhere.

This is genuinely hard because the enforcement must stay **E2EE and relay-blind** — the server must
never learn that a message is secret, nor which message was consumed, nor its contents. So the
consumption signal cannot be a plaintext server flag; it must travel as opaque, encrypted state.

## Options considered

1. **Server consumption token (rejected).** The recipient's devices tell the relay "secret X
   consumed"; other devices poll. Rejected: it reveals to the relay that a message is secret and
   which one was consumed — a metadata leak that violates the feature's core property.
2. **MLS application "consumption" control message (preferred).** When a device begins the reveal, it
   sends a tiny **E2EE application message to its own account's other devices** — a new
   `Content` kind, `SecretConsumed{secret_id}` — through the same MLS group (opaque to the relay).
   Peer devices, on receiving it, transition that `secret_id` straight to `Consumed` (fail-closed:
   the *first* device to open wins; others never open). This reuses the existing content-envelope +
   durable state machine + at-least-once delivery; the relay sees only another opaque envelope.
3. **Self-group / device-sync channel (variant of 2).** If per-account device fan-out is later
   modelled as its own MLS sub-group (a "self group" of a user's devices, cf. Signal's sync
   messages), the consumption message rides that channel instead of the conversation group. Cleaner
   isolation; more infrastructure. Deferred behind option 2.

## Decision (proposed)

Adopt **option 2** with a race rule and a fail-closed default:

- Add `Content::SecretConsumed { secret_id }` (a new kind in the versioned content envelope, so it
  is E2EE + relay-blind + forward-compatible). It carries **no plaintext**, only the id.
- **`begin_secret_reveal` becomes: (a) atomically mark local `Countdown`, THEN (b) emit a
  `SecretConsumed{secret_id}` to the account's other devices.** Ordering matters — a device commits
  its own consumption locally before/independently of the peers hearing about it.
- On receiving `SecretConsumed{secret_id}`, a peer device force-`consume()`s that secret (idempotent;
  scrubs body). If it was still `Sealed`, it goes straight to `Consumed` and never opens. If it was
  mid-reveal (a genuine concurrent open on two devices within network latency), it also consumes —
  so at most a brief overlap is possible, never a second *fresh* opportunity.
- **Concurrency / partition rule:** the guarantee is "**at most one clean view per account, and
  never a re-view**." Two devices opening within the sync-propagation window is the only residual
  overlap; it is bounded by delivery latency and cannot be turned into a second viewing later
  (both end `Consumed`). A device that is **offline** when the consumption message is sent consumes
  it on next sync (the message is queued like any envelope); until it syncs, that offline device
  could still open its copy once — this must be **documented honestly** (offline devices are
  eventually-consistent, not instantly account-locked).

## Consequences

- **Positive:** account-wide single-view with **zero** new server knowledge (no secret flag, no
  consumed-id leak); reuses the content envelope, the durable state machine, at-least-once delivery,
  and the existing dedup/replay protections; forward-compatible via the versioned content kind.
- **Negative / honest limits:** not perfectly atomic across devices — a sub-second concurrent open
  and an offline device are eventually-consistent, not instantaneous. This is inherent to a
  relay-blind design and must be stated in `SECRET_MESSAGES.md`, not hidden.
- **Testing before it can be claimed:** a ≥3-real-client simulation (sender + two recipient devices)
  proving: open on device A → device B (online) never opens; a concurrent A/B open ends with both
  `Consumed`; an offline B consumes on reconnect; the relay stores only opaque envelopes throughout.

## Rollout

1. `content`: add `SecretConsumed` kind (+ golden vectors, bounds, fuzz) — pure, no behavior change.
2. `durable`/`ffi`: emit on `begin_secret_reveal`; apply on receipt; new `InboundOutcome` /
   `InboundResult` variant so the client routes it. Multi-client simulation test.
3. Swift: the app fans the consumption message to the account's devices (same send path).

Until step 2 lands, the Secret Message guarantee remains **single-device**, as stated in
`docs/SECRET_MESSAGES.md` and RISK_REGISTER.
