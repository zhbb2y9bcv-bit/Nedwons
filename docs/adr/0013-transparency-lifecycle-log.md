# ADR-0013: Transparency log — device-lifecycle events & kind-tagged leaf schema v2 (R-201)

- **Status:** Proposed (design only — **not yet implemented**). Written to precede the protocol
  change per the repo rule "write/update an ADR before changing protocol/crypto/storage behavior."
- **Date:** 2026-07-18
- **Deciders:** crypto integrator, backend lead, security architect
- **Sources:** RFC 6962/9162 (Certificate Transparency leaf typing via a leaf-type byte); CONIKS
  (key-directory monitoring, including *removal* auditability).

## Problem (R-201 residual)

The transparency log (`auth_core::transparency` + `services/api/src/transparency.rs` +
`SentinelKit/Transparency.swift`) today logs **only device additions** — one leaf per
account→device-key **binding**, appended at registration / enrollment / recovery. A self-monitoring
client checks that *its own* binding is present under the signed root, so the server cannot
**silently add** a device-key it never logged.

It logs **nothing when a device is revoked.** So a malicious or compromised server can **revoke a
victim's device with no auditable trace** — dropping them from future epochs, or clearing the way
for a substituted device — and a monitoring client has no signed evidence the removal happened. The
device *lifecycle* is only half-auditable (adds, not removes).

## Why this needs a schema change (the leaf-type-confusion trap)

The current leaf entry is, verbatim:

```
binding_leaf = account(16) || device(16) || u16(pubkey_len) || pubkey
```

There is **no leaf-type tag**. If we add a second leaf kind (revocation) without one, we must prove
no revocation leaf can ever equal the bytes of some *binding* leaf for different inputs — and we
cannot, by construction: a binding leaf begins with 16 arbitrary account-id bytes, so any fixed tag
we prepend to a revocation leaf could coincide with some account id's prefix. **Leaf-type confusion
in a Merkle transparency log is a real attack** (a crafted entry of one type read as another). The
only sound fix is an explicit, unambiguous **leaf-type tag on every leaf**.

## Decision

Introduce **leaf schema v2**: every leaf gains a leading domain-separated header
`len32(DOMAIN) || u8(LEAF_KIND)`, with a versioned `DOMAIN = "app.sentinel.kt-leaf.v2"`.

```
leaf_v2 = len32(DOMAIN) || u8(KIND) || body
KIND = Binding(1) | Revocation(2)
Binding.body    = account(16) || device(16) || len32(pubkey) || pubkey
Revocation.body = account(16) || device(16) || u64(revoked_at)
```

(Length prefixes widen to `len32` for the injective, domain-separated discipline used everywhere
else in the codebase — see `sender_cert`/`membership`/auth transcript — so no two distinct field
vectors collide.) The kind byte makes the two leaf types **disjoint by construction**.

### Migration (append-only log ⇒ both schemas coexist forever)

The log is append-only; existing v1 binding leaves **cannot be rewritten**. So:

- Leaves already in the log stay **v1** (`encode_binding`, no header). New leaves are **v2**.
- The stored row already carries the exact `entry` bytes that were hashed, and inclusion proofs are
  over `hash_leaf(entry)` regardless of the entry's internal shape — so **existing proofs keep
  verifying untouched**. Only the *interpretation* of an entry's bytes is schema-dependent.
- Clients must parse **both**: a leaf with the v2 `DOMAIN` header is v2; otherwise it is a v1
  binding. (v1 bytes can never begin with `len32(DOMAIN)` for this exact domain unless an account id
  happened to start with those 4 length bytes *and* the domain string followed — vanishingly
  unlikely, and the client resolves ambiguity by preferring the v2 parse only when the **entire**
  header matches, else v1.) A cleaner alternative — a one-time **epoch marker leaf** recording "v2
  begins at index N" — is noted as an option if the heuristic is judged insufficient at review.

### Client monitoring gains

- Existing check (own binding present) is **unchanged** — v1 and v2 binding leaves both satisfy it.
- **New check:** a client can detect a **revocation of its own device** it did not initiate — a
  v2 Revocation leaf for its `(account, device)` under the signed root — and raise the same
  identity-change alarm as a substituted key. This is the auditability the current log lacks.

## Scope & slicing (deliberate, because it touches a shipped, client-pinned structure)

1. **auth-core:** add `LeafKind`, `encode_leaf_v2` (Binding + Revocation), and a `decode_leaf`
   that returns the kind + fields, keeping `encode_binding` (v1) for the historical golden vector.
   New golden vectors for both v2 kinds. *(pure, fully testable — the safe first slice.)*
2. **api:** append a Revocation leaf inside `revoke_own_device` (best-effort, mirroring
   `append_binding_best_effort`); switch new binding appends to v2; expose revocation leaves in the
   account view.
3. **SentinelKit:** parse both schemas; add the "was my device revoked without my action?" monitor.

Each slice is committed and tested on its own. Until slice 1 lands this ADR is **Proposed**, and
R-201 keeps its current wording (adds are auditable; **removals are not yet**).

## Consequences

- **Positive:** the full device lifecycle becomes auditable under the signed root; closes a real
  "silent revocation" gap; the kind tag also future-proofs the log for later leaf types
  (e.g. log-key-rotation checkpoints).
- **Negative / risks:** two coexisting leaf schemas add parser complexity and a (tiny, bounded)
  ambiguity heuristic the external reviewer must sign off on; the epoch-marker alternative removes
  the heuristic at the cost of a one-time migration leaf. Neither weakens existing proofs.
- **Non-goal:** this does not add split-view/gossip defense, a verifiable map, or log-key rotation
  (separate R-201 residuals). It only makes *removals* auditable alongside *additions*.
