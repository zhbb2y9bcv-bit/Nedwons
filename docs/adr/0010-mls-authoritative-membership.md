# ADR-0010: MLS-commit-authoritative membership via device-signed manifests (R-506)

- **Status:** Accepted — reference implementation + headless multi-client simulation + **client
  wiring** (staged commits through `mls-ffi`, a byte-identical Swift manifest encoder, and the
  proposer/recipient endpoints) landed in this repo. Legacy-path migration, application-envelope
  versioning, recipient signature verification, and the `@main` app screens (R-101) are follow-ups.
- **Date:** 2026-07-18
- **Deciders:** crypto integrator, backend lead
- **Supersedes/extends:** ADR-0009's "MLS membership becomes authoritative" sketch

## Problem

The relay's `conversation_members` table and the cryptographic (MLS) group are **two independent
sources of truth**. Today a routing change requires no cryptographic evidence at all, so:

- a compromised/compelled **server** can silently remove a device from routing (denial of service /
  partition — the victim believes they are in the group and receives nothing) or add a device
  (which cannot decrypt, but observes ciphertext timing/size and becomes a wedge);
- a malicious **member** can issue an MLS commit whose effect differs from what the server was told
  (governance bypass at the crypto layer: OpenMLS does not know ADR-0009's admin rules);
- benign races (add applied in routing but the commit lost, or vice versa) produce members who can
  decrypt but receive nothing, or receive ciphertext they can never decrypt.

**Invariant this ADR enforces:** *the API routing set must not silently diverge from the set of MLS
clients holding the current group epoch.*

**The structural tension:** a strictly **MLS-blind** relay (ADR-0001 / INV-1: the server never
links the MLS library and stores only opaque bytes) **cannot parse an opaque commit**, so it cannot
by itself verify that a claimed routing delta matches the commit's actual cryptographic content.
Any design must say precisely who verifies what.

## Options compared

### Option 1 — server-verifiable public MLS control path

Send commits as MLS `PublicMessage` (signed, unencrypted framing) so the relay can parse the
add/remove proposals and verify the routing delta itself.

- ✅ Server independently verifies correspondence; no trust in the committer's claim.
- ❌ **Breaks the MLS-blind boundary**: the relay must link an MLS parser — the exact TCB expansion
  ADR-0001 forbids (parsing hostile MLS structures server-side, version/ciphersuite coupling, a new
  class of server-side memory/logic bugs in security-critical code).
- ❌ Leaks group-operation structure to the server in plaintext framing (metadata regression
  against R-204's direction).
- ❌ Couples server deployment to MLS library upgrades.

**Rejected.** The no-MLS-link boundary is a founding constraint; weakening it to gain server-side
verification inverts our trust design (the server is the adversary we defend against).

### Option 2 — device-signed membership manifest bound to the opaque commit hash *(chosen)*

The committing device uploads, together with the opaque commit ciphertext, a small **plaintext,
canonically-encoded, device-signed manifest** describing the membership change. The server verifies
the **signature, authorization, ordering, and binding**; recipient clients — who *can* see inside
the commit — verify **correspondence** (the manifest matches what the commit actually did) before
merging.

- ✅ Relay stays MLS-blind: it verifies one ECDSA-P256 signature over a canonical domain-separated
  transcript — machinery `auth-core` already has and tests (same key the device enrolled for auth,
  already logged in the transparency log, R-201).
- ✅ Server enforces exactly what it legitimately can: **who** may change membership (ADR-0009
  governance), **in what order** (atomic per-group epoch compare-and-swap ⇒ linearized membership
  history, no server-side forks), and **atomicity** (routing delta + commit fan-out + welcome
  delivery + removed-device cutoff in one transaction).
- ✅ Every honest recipient client verifies correspondence before merging; a lying committer is
  detected by the entire group.
- ⚠️ Honest limitation (stated in full below): the server cannot detect a committer whose manifest
  lies about the opaque commit's content; only clients can.

### Option 3 — stop treating the routing table as a security boundary (group mailbox)

Deliver every group ciphertext to a per-group mailbox; any enrolled group participant fetches all
of it; MLS alone decides who can decrypt.

- ✅ Removes the divergence problem by removing per-device routing authority.
- ❌ Removed members keep observing ciphertext (volume/timing metadata) until some other mechanism
  cuts them off — which reintroduces the same authorization problem one level up.
- ❌ Bandwidth/storage blow-up; breaks the per-device queue/ack/retention model (DATA_RETENTION)
  and the delivery-cutoff guarantee we already give on leave.
- ❌ The server still needs *some* membership notion for abuse control and mailbox ACLs.

**Rejected as the primary design** — it relocates the problem rather than solving it. One idea is
retained: routing is treated as a *delivery optimization with an authorization gate*, never as
proof of cryptographic membership; the crypto truth lives only in clients' MLS state.

## Decision

**Option 2.** Membership changes are accepted **only** as `(manifest, signature, commit
ciphertext[, welcome ciphertext])` bundles. The relay verifies signature + governance + epoch CAS +
hash binding and applies routing/delivery atomically; clients verify commit↔manifest
correspondence before merging and refuse mismatches.

## Protocol: the membership manifest (v1)

### Fields (all fixed-width or length-prefixed; canonical encoding below)

| # | Field | Type | Meaning |
|---|-------|------|---------|
| 1 | `version` | domain tag | `nedwons-membership-manifest-v1` (domain separation = explicit protocol version; a v2 re-tags). |
| 2 | `group_id` | 16 B | The conversation. |
| 3 | `prev_epoch` | u64 BE | MLS epoch the commit was built against. |
| 4 | `next_epoch` | u64 BE | Resulting epoch; MUST equal `prev_epoch + 1`. |
| 5 | `control_type` | u8 | 1 = add, 2 = remove, 3 = self-leave. (One kind per commit in v1 — no mixed adds+removes; simpler to verify, matches product flows.) |
| 6 | `commit_hash` | 32 B | SHA-256 of the exact opaque commit ciphertext bytes uploaded alongside. Binds manifest ↔ commit bytes. |
| 7 | `actor_device` | 16 B | The committing device (must equal the authenticated device). |
| 8 | `added` | list | (account_id 16 B, device_id 16 B) pairs, sorted; empty unless add. |
| 9 | `removed` | list | device_id 16 B entries, sorted; empty unless remove/leave. |
| 10 | `idempotency_key` | 16 B | Same precise scope as message sends: names ONE logical commit upload; identical retry dedups, different payload under the same key → 409. |
| 11 | `expires_at` | u64 BE | Unix seconds; server rejects expired manifests (bounds replay window in transit; the epoch CAS is the real anti-replay). |

The **manifest hash** = SHA-256 of the canonical encoding; it is what gets recorded in the
audit log and (future) transparency structures. The **signature** is ECDSA-P256 by the actor's
**enrolled device auth key** — the key the server verified at registration and appended to the
transparency log. Canonical encoding: the domain tag, then each field length-prefixed (u32 BE),
lists length-prefixed per element — the same injective transcript style as `auth-core`'s existing
transcripts (no ambiguity, no cross-protocol collision).

### Server acceptance (one transaction — all or nothing)

1. `authed_device` — request is by an enrolled, unrevoked device; it MUST equal `actor_device`.
2. **Signature** verifies against the actor's enrolled device public key.
3. **Freshness**: `expires_at` in the future; `next_epoch == prev_epoch + 1`.
4. **Hash binding**: `commit_hash == SHA-256(uploaded commit bytes)`; for adds, a welcome for each
   added device is present.
5. **Governance (ADR-0009, re-checked in the txn)**: actor is a routing member; adds/removes
   require admin; self-leave requires `removed == [actor's devices]`; adds are refused on a block
   between the added account and any member; a welcome-less or member-duplicating add is refused.
6. **Idempotency**: same `(actor_device, idempotency_key)` with the same manifest hash → return
   the prior outcome (no re-apply); with a different manifest hash → `409 idempotency_conflict`.
7. **Epoch CAS**: `UPDATE conversations SET epoch = next WHERE conversation_id = ? AND epoch =
   prev`. Zero rows ⇒ `409 stale_epoch` (a concurrent commit won; nothing was applied). This
   linearizes membership history per group — **exactly one commit per epoch transition**.
8. **Apply atomically**: insert/delete `conversation_members` rows per the delta; enqueue the
   commit ciphertext to every *pre-change* member device except the actor (removed devices do NOT
   get the removal commit — MLS removes don't need delivery to the removed party, and cutting
   delivery immediately is the point); enqueue each welcome to its added device (targeted);
   **purge removed devices' undelivered envelopes for this conversation** (delivery cutoff, as
   leave already does); append the manifest + signature to the `membership_events` audit log
   (append-only; unique per `(group, next_epoch)`).
9. Commit the transaction; wake long-poll/WebSocket waiters.

Rejections are generic at the HTTP surface (`403 forbidden`, `409 stale_epoch`,
`409 idempotency_conflict`, `400 invalid_input`) — no membership oracle beyond what the caller
already knows.

### Client acceptance (the correspondence check — before merging)

A recipient processing an inbound commit envelope with its accompanying manifest MUST, **before
merging the staged commit**:

1. Verify the manifest signature (the actor's device key, obtainable/pinned via the key directory
   + transparency log) — *optional in the reference slice, required once the directory exposes
   per-device keys to members;* the reference simulation focuses on step 2–4, which need no key
   distribution.
2. Check `commit_hash` equals the hash of the received commit bytes.
3. Check `prev_epoch` equals the local group epoch and `next_epoch = prev + 1`.
4. **Inspect the staged commit** (adds → credential identities of added members; removes → leaf
   indices resolved to identities against the *pre-merge* member list) and require the sets to
   equal the manifest's `added`/`removed` device identities exactly.
5. Only then merge. On any mismatch: **discard the staged commit without merging**, surface a
   security event, and enter resync (below). A lying committer therefore changes nothing for any
   honest member; the group's crypto state simply does not advance on their lie.

### Failure-mode coverage (required by R-506)

| Case | Handling |
|------|----------|
| Concurrent commits | Epoch CAS: exactly one winner per `prev → prev+1`; losers get `409 stale_epoch`, discard their pending local commit (`clear pending`), refetch state, rebase, retry with a fresh idempotency key. |
| Stale epoch | Same as above — detected at CAS time; nothing partially applied. |
| Rejected commit cleanup | Client-side: on any 4xx, the local pending MLS commit is discarded before rebuilding (never merge a commit the server refused — that IS the divergence we're preventing). |
| Forks | Server-side forks are impossible per group (CAS + unique `(group, next_epoch)`); a client that detects epoch/hash mismatch against the event log has diverged and must resync. |
| Removed-device cutoff | Routing removal + queued-envelope purge in the same transaction; the removed device receives nothing after the commit is accepted. Post-removal secrecy is MLS's job (proven in `e2ee.rs`). |
| Welcome delivery | Uploaded and enqueued in the same transaction as the commit — an add cannot land in routing with the welcome lost. |
| Retries | Idempotency key with the message-send semantics (dedup identical, conflict different). |
| Rollback | Single transaction — a failure anywhere applies nothing. |
| Mismatch recovery / resync (v1) | A member whose local state cannot process the group's next commit (or who refused a lying commit) re-enters via a fresh add: publish a new key package, be re-added by an admin (new epoch). Losing unread history is accepted v1 behavior — never silently re-derive or trust server-supplied state. A finer-grained resync protocol is future work. **Reference-simulation finding (hardens this rule):** OpenMLS *consumes the commit's decryption secret on processing* (forward secrecy), so a refused commit can never be re-processed from the same bytes — after refusing a lie the member is desynced *by construction* and resync/re-add is the **only** recovery, not merely the recommended one. Verified in `mls-core/tests/membership_check.rs`. |

## What the server still cannot prove (honest statement — do not overclaim)

- The server **cannot verify that the manifest's claimed delta equals the opaque commit's actual
  content.** A *valid member* whose manifest lies is accepted server-side; the routing table then
  reflects the lie until clients react. Every honest recipient detects the mismatch and refuses to
  merge, so the **cryptographic** group never follows the lie — but delivery for the lied-about
  epoch is wrong until repair (bounded metadata/DoS harm, no confidentiality harm).
- A malicious server can still **refuse service** (drop commits/messages) or collude with a
  malicious member to mis-route. Censorship-evidence (client-side delivery beacons, cross-member
  gossip of the event log) is future work; note the event log is append-only and auditable.
- The manifest binds to the actor's **device auth key**; the binding between that key and the
  actor's *MLS credential* rests on the server's device record + the transparency log (R-201).
  Logging MLS signature keys in the transparency log is future work.
- None of this has had external cryptographic review (R-202/R-503 remain launch blockers).

## Consequences & migration

- `conversations` gains an `epoch` column (CAS anchor) and a `membership_events` append-only audit
  table (migration V10). The relay stays MLS-blind: it stores/verifies hashes, signatures, and 16-
  byte ids — never MLS structures.
- New endpoint `POST /v1/conversations/{id}/commit`. The reference implementation + a headless
  multi-client simulation (real MLS clients through the real relay, including the lying-manifest
  case) land with this ADR.
- **Legacy paths**: `create_conversation`, invite-accept, join-request-approve, direct `add
  member`, and `leave` still mutate routing without commits. They remain during migration and are
  the documented gap: R-506 stays MITIGATING (not CLOSED) until clients drive all membership
  through commits and the legacy mutation paths are gated off. Invite/join flows will compose with
  this protocol (the admin's *accept* becomes an add-commit; the token/consent logic of ADR-0009
  is unchanged).
- **Swift wiring** (follow-up): expose the correspondence check through `mls-ffi`
  (`process_commit_checked`) and drive the new endpoint from `NedwonsKit`; then two-device flows
  on simulator/hardware (R-101).
- Envelope-level protocol versioning for *application* messages remains open (tracked in R-506's
  residual); membership control messages are versioned by the manifest domain tag as of v1.
