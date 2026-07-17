# Sentinel Auth API (v1)

Wire contract for the device-bound authentication endpoints served by `services/api`. All
binary fields are lowercase hex. All requests are JSON with `Content-Type: application/json`
and **strict schemas** (unknown fields → `422`). Bodies are capped at 8 KiB. Production
serves this only over TLS 1.3.

Base path: `/v1`. Health: `GET /healthz` → `200 "ok"`.

## Error model

Errors are generic by design (enumeration resistance, fail-closed):

| HTTP | body `error` | Meaning |
|------|--------------|---------|
| 400  | `invalid_input` | Malformed field (bad hex, wrong length, username shape). |
| 400  | `weak_password` | Password fails policy (length/blocklist). Client-correctable. |
| 401  | `denied` | Any authentication/authorization/replay/expiry failure. No detail. |
| 409  | `username_unavailable` | Registration only: username taken. |
| 422  | (axum) | JSON shape/unknown-field rejection. |
| 429  | `rate_limited` | Per-IP quota exceeded. |
| 500  | `internal` | Storage/internal fault. No detail. |

## Endpoints

### `POST /v1/register/begin` → `200`
Body: `{}`. Returns a `Register` challenge:
```json
{ "account_id":"<16B hex>", "device_id":"<16B hex>", "txn_id":"<16B hex>",
  "nonce":"<32B hex>", "expires_at": <unix secs> }
```
The client generates its Secure Enclave key, builds the `Register` transcript
(CRYPTOGRAPHY.md §4) from these fields + its public key, and signs it.

### `POST /v1/register/finish` → `200` (session) | `409` | `400`
```json
{ "username":"alice", "password":"…(≥12 chars)…",
  "device_public_key":"<65B SEC1 hex>", "txn_id":"<16B hex>", "signature":"<64B hex>" }
```

### `POST /v1/login/begin` → `200` (always a challenge)
```json
{ "username":"alice", "password":"…" }
```
Returns a `Login` challenge with the same shape as register/begin. **Always** returns a
challenge — a decoy for unknown accounts or bad passwords — so this step reveals nothing.

### `POST /v1/login/finish` → `200` (session) | `401`
```json
{ "txn_id":"<16B hex>", "signature":"<64B hex>" }
```
Succeeds only with a signature from the enrolled device key (INV-2).

### `POST /v1/session/refresh` → `200` (session) | `401`
```json
{ "refresh_token":"<32B hex>", "signature":"<64B hex>" }
```
The signature is over a `Refresh` transcript whose nonce is `SHA-256(refresh_token)` and
whose `txn_id` is derived from it (`refresh_txn_id`). Rotates the token; reuse of a retired
token revokes the whole family.

### `POST /v1/session/logout` → `204`
```json
{ "refresh_token":"<32B hex>" }
```

### `GET /v1/session/whoami` → `200` | `401`
Header: `Authorization: Bearer <32B access-token hex>`. Returns
`{ "account_id":"…","device_id":"…" }`.

## Session object
```json
{ "account_id":"<16B hex>", "device_id":"<16B hex>",
  "access_token":"<32B hex>",  "access_expires_at": <unix secs>,
  "refresh_token":"<32B hex>", "refresh_expires_at": <unix secs> }
```

Tokens are opaque bearer values. Possession of the access token authorizes API calls until
expiry; possession of the refresh token **plus** a device-key signature is required to
rotate. This is the same flow the iOS client drives; `services/api/tests/http_api.rs`
exercises it end to end against real PostgreSQL.

## Relay endpoints (E2EE messaging)

All require `Authorization: Bearer <access-token hex>`. The server stores and forwards
**opaque ciphertext** only — it never decrypts, and the server library does not link the MLS
implementation. Bodies may be up to 256 KiB (envelopes).

### `POST /v1/keypackages` → `204`
`{ "key_package": "<hex>" }` — publish an MLS key package ("prekey") for the caller's device.

### `POST /v1/keypackages/claim` → `200` | `404`
`{ "account_id": "<16B hex>" }` → `{ "device_id": "<16B hex>", "key_package": "<hex>" }`.
Atomically pops one key package for the target account's device (to add them to a group).

### `POST /v1/conversations` → `200`
Body `{}`. Creates a conversation with the caller as first member →
`{ "conversation_id": "<16B hex>" }`.

### `GET /v1/conversations` → `200`
The caller's conversations, most recent first, each with its members (for the Chats list):
`[ { "conversation_id": "<16B hex>", "member_account_ids": [ "<16B hex>", … ] }, … ]`.

### `POST /v1/conversations/{id}/leave` → `204`
Leave a conversation (consent withdrawal, ADR-0009). Removes **all** of the caller's devices from
routing membership and purges their queued undelivered envelopes for it; future fan-out excludes
them and they can no longer send (`403`). Idempotent — leaving a conversation you're not in (or
that doesn't exist) is a `204` no-op; ids are opaque random values so nothing is disclosed. When
the last member leaves, the conversation row and any leftover envelopes are deleted.

### `POST /v1/conversations/{id}/members` → `204` | `403`
`{ "account_id": "<16B hex>" }` — direct-add a target account's active device to routing.
Direct add is consent-by-proxy, so it is tightly gated (ADR-0009): the caller must be an **admin**
of the conversation **and friends with the target**, and no block may exist between the target and
any current member. Strangers join via invite links (their own consent). The target device is
resolved server-side (never client-asserted).

### `POST /v1/conversations/{id}/members/remove` → `204` | `403`
`{ "account_id" }` — **admin** removes a member: same exit path as leave (routing removal, queued
mail purged, role dropped). Removing yourself is a `leave` (`400`).

## Group governance (ADR-0009): admins, invites, join requests

The group creator is its first **admin**. All of the following except `invites/accept` require the
caller to be a member **and** admin (else a generic `403`).

### `POST /v1/conversations/{id}/invites` → `200`
`{ "expires_in_secs"?: <60..2592000, default 604800>, "max_uses"?: <1..1000, default 100> }` →
`{ "invite_token": "<32B hex>", "expires_at": <unix>, "max_uses", "uses" }`. Mint an invite-link
token (high-entropy bearer value — treat it like a credential).
### `GET /v1/conversations/{id}/invites` → active invites `[ { invite_token, expires_at, max_uses, uses }, … ]`
### `POST /v1/conversations/{id}/invites/revoke` → `204`  `{ "invite_token" }`

### `POST /v1/invites/accept` → `200` | `403`
`{ "invite_token": "<32B hex>" }` → `{ "conversation_id", "status": "joined" | "requested" }`.
Present a token as yourself (**the joiner's own consent**). Joins immediately, or files a join
request when the group requires approval. One generic `403` on any refusal (invalid/expired/
revoked/exhausted token, already a member, or a block against any current member) — the token must
not become an oracle for group/block state. Each successful join/request consumes one use.

### `GET /v1/conversations/{id}/requests` → pending join requests `[ "<account_id hex>", … ]`
### `POST /v1/conversations/{id}/requests/approve` → `204` | `404 no_request`  `{ account_id }`
Blocks are re-checked at approval time; a now-blocked requester's request is consumed without joining.
### `POST /v1/conversations/{id}/requests/deny` → `204`  `{ account_id }`

### `POST /v1/conversations/{id}/admins` → `204` | `404 not_member`  `{ account_id }` — promote
### `POST /v1/conversations/{id}/admins/demote` → `204` | `409 last_admin`  `{ account_id }`
Demoting the last admin is refused. When the last admin **leaves**, the earliest remaining member
is auto-promoted, so a populated group is never unmanageable.
### `POST /v1/conversations/{id}/settings` → `204`  `{ "join_approval": <bool> }`

### `POST /v1/conversations/{id}/messages` → `200` | `403`
`{ "ciphertext": "<hex>", "idempotency_key": "<16B hex>" }`. One MLS application ciphertext,
**fanned out server-side** to every other member device (the client uploads once, not once
per recipient). Idempotent per key. Returns `{ "delivered": <int> }` — the number of devices
newly queued (0 on an idempotent retry). Caller must be a member (object-level authz).

### `POST /v1/conversations/{id}/welcome` → `200` | `403`
`{ "recipient_device": "<16B hex>", "ciphertext": "<hex>", "idempotency_key": "<16B hex>" }`.
Targeted delivery of an MLS Welcome to a specific joining device. Idempotent; returns
`{ "envelope_id": <int> }`.

### `GET /v1/inbox[?wait=N]` → `200`
**Peeks** the caller's undelivered envelopes **in delivery order** WITHOUT marking them
delivered: `[ { "id", "conversation_id", "sender_device", "ciphertext" }, … ]`. Ordered
delivery is required — MLS commits/welcomes must be processed in order. The client persists
them locally and then calls `/v1/inbox/ack`; a crash between peek and persist loses nothing
(at-least-once). With `?wait=N` (seconds, capped at 30) this **long-polls**: returns
immediately if mail is present, otherwise parks until a send wakes it or `N` elapses —
near-zero idle latency without holding a DB connection.

### `POST /v1/inbox/ack` → `204`
`{ "ids": [<envelope id>, …] }`. Acknowledge durably-persisted envelopes so they stop being
served and become eligible for retention purge. Scoped to the caller's own device; idempotent.

### `GET /v1/stream` (WebSocket)
Upgrade with `Authorization: Bearer <access-token hex>` on the handshake. The server **pushes**
new envelopes the instant they arrive (sub-second, no polling): server→client
`{ "envelopes": [ … ] }`, client→server `{ "ack": [<id>, …] }`. Same at-least-once queue as
HTTP — unacked envelopes re-deliver on reconnect. Unauthenticated upgrades are rejected.

`services/api/tests/{relay_e2ee,ws_stream,load}.rs` drive these flows with real MLS
ciphertext and verify, by direct database query, that no plaintext is stored; they also cover
fan-out, idempotent retry, long-poll and WebSocket wake-on-delivery, at-least-once peek/ack,
and idle-waiters-exceed-pool. See [PERFORMANCE.md](../PERFORMANCE.md).

## Profiles, friends, and groups

All require a Bearer access token. Profiles and the friendship graph are social/routing
metadata (never message content). Group creation no longer requires a friend clique (ADR-0009):
any members may be grouped as long as no pair among them has blocked each other.

### `GET /v1/profile` → `{ account_id, username, display_name, bio }`
### `PUT /v1/profile` → `204`  `{ display_name (≤64), bio (≤256) }`
### `GET /v1/profile/{account_id}` → a profile
### `GET /v1/profiles/search?q=<prefix>` → `[ { account_id, username, display_name }, … ]`
Username-**prefix** search (min 2 chars, capped, rate-limited) — deliberate discovery, not a
bulk directory dump.

### `GET /v1/friends` → `[ summary, … ]`
### `GET /v1/friends/requests` → incoming pending requests `[ summary, … ]`
### `POST /v1/friends/request` → `{ "status": "requested" | "friended" | "already_friends" }`
`{ "account_id": "<16B hex>" }`. Auto-friends if the other side already requested you.
### `POST /v1/friends/accept` → `204` | `404 no_request`  `{ account_id }`
### `POST /v1/friends/decline` → `204`  `{ account_id }`
### `POST /v1/friends/remove` → `204`  `{ account_id }`

### Blocking (abuse control)
### `GET /v1/blocks` → `[ summary, … ]` — accounts you have blocked
### `POST /v1/blocks` → `204`  `{ "account_id": "<16B hex>" }`
Block an account. Atomically removes any existing friendship and pending requests in either
direction. Idempotent. A subsequent `POST /v1/friends/request` between the two (either way) returns
`403 blocked` while the block stands.
### `POST /v1/blocks/remove` → `204`  `{ account_id }` — unblock (does not restore prior friendship)

### `POST /v1/reports` → `200 { "report_id": <int> }`
`{ "account_id": "<16B hex>", "reason": "…(1–500)…", "evidence": "…(optional, ≤16 KiB)…" }`.
Files an abuse report. Because messages are E2EE, `evidence` is **only** what the reporting client
chose to submit (a rendered excerpt) — the server never derives it from message content. Cannot
report yourself (`400`).

Note: `POST /v1/friends/request` may now also return `403 {"error":"blocked"}`. `services/api/tests/social.rs`
covers the full block flow (sever, refuse both directions, list, reversible).

### `POST /v1/groups` → `200` | `403 not_friends` | `403 blocked_member`
`{ "member_account_ids": [ "<16B hex>", … ] }`. Creates a group; the creator becomes its first
**admin**. Listing someone is a direct add, so the creator must be **friends with each listed
member** (`403 not_friends` otherwise — strangers join via invite links, their own consent).
Members need **not** be friends with each other (no clique). No pair within the group may have
blocked each other (`403 blocked_member`). Returns `{ "conversation_id", "member_account_ids" }`
and adds all members' active devices to routing. `services/api/tests/social.rs` and
`services/api/tests/groups.rs` cover the gates end to end.
