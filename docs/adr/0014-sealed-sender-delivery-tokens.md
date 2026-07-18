# ADR-0014: Sealed-sender delivery — abuse model & delivery access keys (R-204, ADR-0012 Slice 2)

- **Status:** Proposed (design only — **not implemented**). This is the gating decision for the
  sealed-sender *delivery* path: it changes the relay's trust/abuse model, so per the repo rule it is
  written and reviewed **before** any code. ADR-0012 decided sealed sender in principle and shipped
  the sender-certificate primitive + issuance + recipient key-match verification; this ADR nails down
  *how anonymous delivery is prevented from becoming a spam channel.*
- **Date:** 2026-07-18
- **Deciders:** crypto integrator, backend lead, security architect (+ external review before ship)
- **Sources:** Signal "sealed sender" + "unidentified access" (delivery access key = profile-key
  material presented at delivery); Signal message-requests UX.

## The problem this ADR exists to solve

Identified delivery today gives the relay one free abuse control: **every send is authenticated**, so
the relay enforces conversation membership and rate-limits per sender device (`send_targeted` /
`fanout_message` both call `member_in_txn(sender_device)`; the idempotency unique index is
`(sender_device, recipient_device, idempotency_key)`). Sealed-sender delivery deliberately throws
that away — the relay must accept a message **without learning the sender**. Remove the authenticated
sender and you remove membership enforcement, per-sender rate limiting, and server-side block
enforcement all at once. Anonymous write to any inbox = a spam firehose. **The delivery access key
(DAK) is what replaces the authenticated sender as the abuse gate.**

## Decision — delivery access keys (Signal's model, stated precisely)

### The primitive

- Each **recipient account** holds a 32-byte random **delivery access key** `K_r`, rotatable.
- The recipient registers a **verifier** `V_r = SHA-256(K_r)` with the relay over an *authenticated*
  endpoint (it authenticates as itself to set its own gate). The relay stores `V_r`, never `K_r`.
- The recipient distributes `K_r` **only to approved senders, only inside the E2EE channel** (e.g.
  in a control message when a contact/friendship is established, or in a group Welcome). The relay
  never sees `K_r` in transit — it is ciphertext to the relay.
- To deliver a sealed message, the sender calls the **unauthenticated** delivery endpoint and
  presents `K_r` (hex) in a header alongside `recipient_device`, `ciphertext`, `idempotency_key`.
- The relay accepts iff `SHA-256(presented) == V_r` (constant-time compare), then enqueues the
  envelope **with no sender identity**. Mismatch → reject (see fallback below).

### What the DAK does and does NOT do (the honest core of this ADR)

- It gates **who may deliver sealed messages to a recipient**: only holders of the recipient's
  *current* `K_r`. Rotating `K_r` (on block, on contact removal, periodically) instantly revokes
  every old holder — that is the recipient's spam/abuse control.
- On first presentation, **the relay learns `K_r`** (it must, to hash-compare — symmetric model).
  Consequence: a malicious relay could itself enqueue sealed envelopes to the recipient. **This does
  not break authenticity:** a relay cannot forge a valid **sender certificate** (it lacks the
  sender-cert signing key), and the recipient runs `SenderCertificate.verifySealedSender` (landed) —
  so a relay-injected sealed message has no verifiable sender and is dropped by the client. **The DAK
  gates spam volume, not sender authenticity.** State this plainly in `PRIVACY.md`; do not imply the
  DAK hides the sender from a relay that already colludes.
- A stronger, relay-doesn't-learn-the-secret construction (recipient-issued per-sender capabilities,
  or a VOPRF/blind-signature token) is recorded under *Alternatives* for a later iteration; the
  symmetric DAK is chosen first for being simple, reviewed, and sufficient against the actual threat
  (open-relay spam), given the certificate check backstops authenticity.

### Layered abuse controls (DAK is necessary, not sufficient)

1. **DAK gate** — above. The primary control.
2. **Recipient-side block enforcement.** The relay can't enforce blocks on a sealed message (it
   doesn't know the sender). The recipient's client, after `verifySealedSender` yields the sender
   account, **drops messages from blocked accounts locally**. Blocks therefore also **rotate `K_r`**
   so a blocked contact loses sealed access at the relay too, not just client-side.
3. **Message-requests fallback for non-holders.** A sender without `K_r` (first contact) cannot send
   sealed; it falls back to **identified** delivery into a *message-request* inbox (quarantine), so
   first contact still works but through the authenticated, rate-limited, block-enforced path. Sealed
   is an optimization for *established* contacts, never the only way to reach someone.
4. **Per-recipient rate limits.** Because the sender is unknown, the relay rate-limits sealed
   deliveries **keyed on `recipient_device`** (GCRA, reusing the R-306 limiter) to bound flooding
   even by a DAK holder or a relay that learned `K_r`.
5. **Size cap + retention** unchanged (opaque-ciphertext body limit, `SENTINEL_ENVELOPE_TTL_DAYS`).

## What a sealed envelope stores (metadata minimization)

A sealed envelope stores **only** `(recipient_device, ciphertext, idempotency_key, created_at)` —
**no `sender_device`, no `conversation_id`.** The recipient learns the conversation from the E2EE
payload. This means sealed sending uses **client-side fan-out**: the sender encrypts per recipient
device and delivers each sealed envelope individually (trading the server-side `INSERT..SELECT`
fan-out efficiency for privacy). Server-side fan-out stays for identified/control traffic.

### Storage & idempotency: a separate table, not a weakened one

Do **not** make `envelopes.sender_device`/`conversation_id` nullable — that would weaken the proven
NOT-NULL + `(sender_device, recipient_device, idempotency_key)` constraints on the identified path
(R-102-adjacent invariants). Instead add a **`sealed_envelopes`** table:

```
sealed_envelopes(
  id BIGSERIAL PK,
  recipient_device BYTEA NOT NULL (len 16),
  ciphertext BYTEA NOT NULL,
  idempotency_key BYTEA NOT NULL (len 16),   -- sender-chosen 128-bit random
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered BOOLEAN NOT NULL DEFAULT FALSE
)
UNIQUE (recipient_device, idempotency_key)   -- re-scoped: no sender to key on
```

Idempotency is re-scoped to `(recipient_device, idempotency_key)`. Because the key is 128-bit random
and sender-chosen, a *cross-sender* collision (which would drop one message) has probability ≈2⁻¹²⁸ —
acceptable, and documented; unlike the identified path there is no 409 `idempotency_conflict` signal
(the relay can't tell "same sender retrying" from "different sender colliding"), so a duplicate key is
simply a silent no-op insert. The recipient's inbox read (`/v1/inbox`, authed as itself) unions
identified + sealed envelopes; sealed ones carry no sender field.

## Endpoints

- `PUT /v1/delivery-access-key` (**authed**) — body `{ verifier: hex(SHA-256(K_r)) }`; upserts `V_r`
  for the caller's account. Rotation = call again with a new verifier.
- `POST /v1/sealed/deliver` (**unauthenticated**) — header `X-Delivery-Key: hex(K_r)`, body
  `{ recipient_device, ciphertext, idempotency_key }`. Verifies `SHA-256(K_r)==V_r` for the recipient
  device's account (constant-time), rate-limits per `recipient_device`, inserts into
  `sealed_envelopes`. Returns a generic `202`/`403` with **no** sender/recipient oracle beyond
  deliver-or-not. Never reveals whether a recipient exists distinct from a bad key (uniform response).
- Reads: existing `GET /v1/inbox` returns sealed envelopes too (sender field absent) + existing ack.

## Rollout slices (each independently committed + tested; do not land as one change)

- **2a — DAK primitive + registration (landed 2026-07-18).** `auth_core::delivery_key`
  (`verifier` = SHA-256, constant-time `verify`, `is_valid_verifier`; 5 tests incl. a pinned
  SHA-256("") vector for cross-language agreement) + `PUT /v1/delivery-access-key` (authed; stores
  only `V_r`) + `PgRelay::set_delivery_verifier`/`delivery_verifier` + migration V16
  `delivery_access_keys`. Integration-tested: register, rotate (old key revoked), malformed
  verifier → 400, unauth → 401. **No delivery path yet** — registering a verifier changes no
  delivery behavior, so this slice carries no trust-model change.
- **2b — sealed delivery.** `sealed_envelopes` migration + unauthenticated `POST /v1/sealed/deliver`
  with the DAK gate + per-recipient rate limit + uniform-response no-oracle behavior + inbox
  surfacing. This is the **trust-model change** — gated on this ADR being Accepted + external review.
- **2c — client.** Sender: obtain the recipient DAK (delivered via E2EE on contact/Welcome), send
  sealed via client-side fan-out. Recipient: `verifySealedSender` (already landed) + recipient-side
  block drop + block→rotate. Message-request fallback for non-holders.
- **2d — padding / cover traffic** (size/timing) — separate, later; out of scope here.

R-204 stays **OPEN/MITIGATING** until 2a–2c ship and a test demonstrates the relay stores **no**
sender for a sealed message while a rotated DAK denies a revoked sender.

## Alternatives considered

- **Keep authenticating the sender but don't store it.** Rejected: the auth layer (token→account)
  still learns the sender; not sealed in any meaningful sense.
- **Relay-doesn't-learn-the-secret tokens** (recipient-signed per-sender capabilities; VOPRF/blind
  signatures). Stronger (relay never holds `K_r`), but heavier and less-reviewed; the certificate
  check already backstops authenticity, so deferred as a possible 2e hardening.
- **Make `envelopes` columns nullable.** Rejected: weakens the identified path's proven constraints;
  a separate `sealed_envelopes` table isolates the new mode.

## Consequences

- **Positive:** the relay stops learning the sender (and conversation) for established-contact
  traffic; abuse is bounded by a recipient-controlled, instantly-rotatable key + recipient-side
  policy; the identified path and its invariants are untouched.
- **Negative / risks:** client-side fan-out costs the sender N deliveries (efficiency ↓ for privacy
  ↑); the relay learns `K_r` (spam-gate only — documented); recipient-side block enforcement is a
  behavior shift that must be spelled out in `PRIVACY.md`/`ABUSE_MODEL.md`; sealed idempotency drops
  a cross-sender key collision silently (≈2⁻¹²⁸). None of these weaken E2EE or authenticity.
