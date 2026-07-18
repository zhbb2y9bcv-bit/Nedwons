# ADR-0015: Account-wide single-consumption for Secret Messages (multi-device)

- **Status:** **Accepted — implemented 2026-07-18** (option 2, then upgraded to **option 3**).
  Account-wide single-consumption works via an E2EE, relay-blind `SecretConsumed` control message. As
  of the option-3 upgrade it rides the account's **device self-group** (below), so the conversation's
  other party (the sender) no longer even receives the read signal. The race/offline caveats below
  remain **inherent** and are documented honestly in `docs/SECRET_MESSAGES.md`.
- **Implementation (option 2 core):** `Content::SecretConsumed { secret_id }` (new versioned content
  kind, bounded, fuzzed); `DurableSession::emit_secret_consumption` (idempotent, builds the control
  message once after a recipient reveals) + `process_inbound` force-consumes on receipt (new outcome
  `SecretConsumedRemotely`); FFI `secret_consumption_envelope` + `InboundResult::SecretConsumedRemotely`;
  Swift `MlsClientSecretEngine` fans it out via an injected broadcast closure.
- **Implementation (option 3 upgrade, 2026-07-18):** a second MLS group — the account's **self-group**
  of only its own devices — lives in the same `Member` provider as the conversation, so one atomic
  blob persists both. `emit_secret_consumption` tags the control message with `Channel::SelfGroup`
  when a self-group exists; `encrypt` routes it through the self-group; the peer applies it via the
  new `process_self_inbound` path (`DurableSession` / FFI). Self-group establishment mirrors
  conversation membership: `create_self_group` / `add_self_device` / `join_self_group` (+ FFI +
  `has_self_group`). A single-device or unlinked account gracefully falls back to option 2. **Proven:**
  mls-core `consumption_syncs_over_the_self_group_without_the_sender_learning` (real 4-party: sender +
  phone + tablet; phone reveals → tablet consumed; the sender is not in the self-group and **cannot
  decrypt** the signal) + `self_group_persists_across_reopen`; FFI `consumption_over_the_self_group_across_the_ffi`;
  SentinelApp `testRevealFansOutOverTheSelfGroupSenderNeverSeesIt`. Original option-2 tests retained.
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
3. **Self-group / device-sync channel (variant of 2) — ADOPTED as the 2026-07-18 upgrade.** Per-account
   device fan-out is modelled as its own MLS sub-group (a "self group" of a user's devices, cf.
   Signal's sync messages), and the consumption message rides that channel instead of the conversation
   group. This closes option 2's one leak: because the conversation's other party is not a member of
   the self-group, they never receive — and cannot decrypt — the "opened" signal (option 2 sent it
   through the conversation, so the sender learned of the read, a read-receipt-like disclosure). The
   cost is the extra self-group: its own MLS ratchet + an establishment handshake (create/add/join)
   between the account's devices. The self-group shares the conversation's provider store, so it adds
   no second persistence authority — one atomic blob still persists everything.

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
