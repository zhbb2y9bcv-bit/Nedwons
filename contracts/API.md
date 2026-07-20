# Nedwons Auth API (v1)

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
| 409  | `idempotency_conflict` | Send only: the idempotency key was already used by this sender device for a **different** ciphertext or conversation. Keys name one logical send; retry with a fresh key. Refused rather than silently deduplicated, which would drop the new message while reporting success. |
| 409  | `commits_required` | A legacy membership mutation was attempted on an MLS-authoritative conversation; use `POST /commit` (ADR-0010). |
| 409  | `stale_epoch` | A membership commit's `prev_epoch` was superseded by a concurrent commit; rebase on `/epoch` and retry. |
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

## Key transparency (R-201)

An append-only RFC 6962 Merkle log of account→device-key bindings (auth'd reads). Clients verify
STH signatures under a **pinned** log key and self-monitor their own account. See
[KEY_TRANSPARENCY.md](../docs/KEY_TRANSPARENCY.md) for the honest scope.

### `GET /v1/transparency/sth` → signed tree head
`{ "tree_size", "root_hash":"<32B hex>", "timestamp", "signature":"<64B hex>", "log_public_key":"<65B SEC1 hex>" }`.
`signature` is ECDSA-P256 over the canonical `encode_sth(tree_size, root, timestamp)`.

### `GET /v1/transparency/consistency?first=N&second=M` → `{ "proof": ["<hex>", …] }` | `400`
RFC 6962 consistency proof that tree size `M` append-only-extends size `N` (`0 < N ≤ M ≤ size`).

### `GET /v1/transparency/account/{account_id}[?tree_size=N]` → account view
`{ "tree_size", "bindings":[ { "leaf_index", "device_id", "public_key", "entry":"<hex>", "proof":["<hex>",…] }, … ] }`.
Each binding's inclusion proof is computed at `tree_size` (defaults to current). A client verifies
each proof against an STH root at the same size and checks the logged key is the one it enrolled.
`services/api/tests/transparency.rs` drives the full self-monitor flow.

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
Atomically pops one **non-expired** key package for the target account's device (to add them to a
group). Key packages past their TTL (30 days) are never handed out and are purged — a stale prekey
must never be used to add a device (MLS hygiene).

### `GET /v1/keypackages/count` → `200`
Authed. `{ available, low_watermark }` — how many non-expired key packages the caller's device still
has published. The client publishes more when `available ≤ low_watermark`, so the device stays
addable while offline.

### `GET /v1/sender-certificate` → `200` | `401` (ADR-0012, R-204)
Authed. Issues a short-lived sealed-sender certificate for the caller's device:
`{ account_id, device_id, sender_public_key, expires_at, signature, cert_public_key }` (all hex).
`signature` is a 64-byte r‖s ECDSA-P256 signature, made with the server's dedicated
sender-certificate key, over the canonical `SenderCert` encoding (`app.nedwons.sender-cert.v1`).
The device embeds the certificate inside the E2EE payload of a sealed-sender message so the
recipient verifies who sent it while the relay never learns the sender. `cert_public_key` is the
SEC1 signing-key public key — production clients **pin** it out of band; it is returned for
bootstrap/discovery. The relay stays MLS-blind (it signs only the four bound fields). Certificates
are short-lived (24h) so a leaked or rotated cert key stops being trusted quickly.

### `PUT /v1/delivery-access-key` → `204` | `400` | `401` (ADR-0014 Slice 2a, R-204)
Authed. Body `{ verifier }` (hex `SHA-256(K_r)`, exactly 32 bytes) registers/rotates the caller
account's sealed-sender **delivery access verifier**. The relay stores only the hash, never the
delivery access key `K_r` itself (the recipient distributes `K_r` to approved senders over the E2EE
channel). A second call replaces the verifier — rotation instantly revokes old-key holders at the
relay. No sealed-delivery endpoint consumes this yet (Slice 2b, gated on ADR-0014 review), so
registering a verifier changes no delivery behavior today.

### `POST /v1/conversations` → `200`
Optional body `{ mls_authoritative?: bool }` (default false). When `true`, the conversation is
**MLS-commit-authoritative** (ADR-0010): its routing membership changes ONLY through `/commit`, and
the legacy direct-mutation endpoints below (`/members`, `/members/remove`, `/leave`, `/invites`,
`/join-requests/approve`) return `409 commits_required`. Absent/`{}` keeps the legacy behavior.
Genesis (epoch 0) is the creator alone; members are added via commits.
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
mail purged, role dropped). Removing yourself is a `leave` (`400`). *(Legacy routing-only path;
being migrated to `/commit` — ADR-0010 / R-506.)*

### `POST /v1/conversations/{id}/commit` → `200` | `403` | `409` | `400` (ADR-0010, R-506)
MLS-commit-authoritative membership change. Body:
`{ control_type (1=add,2=remove,3=self-leave), prev_epoch, next_epoch, commit_hash (32B hex),
added: [{account_id, device_id}], removed: [device_id...], idempotency_key (16B hex), expires_at,
signature (hex), commit (hex), welcomes: [hex...] }`. `signature` is ECDSA-P256 by the actor's
enrolled device key over the canonical manifest (`auth_core::membership`); lists must be sorted +
duplicate-free; one welcome per added device. The MLS-blind server verifies signature + commit-hash
binding + governance (ADR-0009) + a per-conversation **epoch compare-and-swap**, then atomically
applies routing, fans the opaque commit to pre-change members (minus actor/removed) + targeted
welcomes, cuts removed devices' queued mail, and appends to the audit log. Returns
`{ applied, next_epoch }` (`applied:false` on an idempotent retry). `409 stale_epoch` = a concurrent
commit won (rebase on `/epoch` and retry); `409 idempotency_conflict` = key reused with a different
manifest. **Recipients MUST run the commit↔manifest correspondence check before merging** — the
server cannot verify an opaque commit's content matches the manifest.

### `GET /v1/conversations/{id}/epoch` → `200` | `403`
Members only. `{ epoch }` — the current membership epoch, for rebasing after `stale_epoch`.

### `GET /v1/conversations/{id}/membership/{epoch}` → `200` | `403` (ADR-0010)
Members only (generic `403` for non-members and unknown epochs — no oracle). `{epoch}` is the
event's `next_epoch`. Returns the stored manifest decoded plus its evidence:
`{ control_type, prev_epoch, next_epoch, commit_hash, actor_device, added: [{account_id, device_id}],
removed: [device_id...], idempotency_key, expires_at, manifest (hex), signature (hex) }`. A recipient
at local epoch N fetches `N+1` to learn the `added`/`removed` device identities for the client-side
commit↔manifest correspondence check (and, once the key directory exposes the actor's device key,
to verify `signature` over `manifest`).

## Account recovery (ADR-0003)

### `POST /v1/recovery/set` → `204` | `400`
Authed. `{ recovery_secret }` — set/replace the account's recovery secret (a generated
high-entropy code; stored only as an Argon2id hash). `400 weak_password` if shorter than the
minimum. Set this while you still hold a device.

### `POST /v1/recover/begin` → `200`
Unauthenticated. `{ username }` → `{ account_id, device_id, txn_id, nonce, expires_at }`, reserving
the recovering device's id. **Enumeration-resistant**: a challenge is always returned, whether or
not the account (or a recovery secret) exists.

### `POST /v1/recover/finish` → `200` | `401`
Unauthenticated. `{ username, recovery_secret, txn_id, device_public_key (65B hex), signature (64B
hex) }` — the recovery secret authorizes and the new device self-signs the `DeviceEnroll` transcript
(proof of possession). Returns a **session for the recovered device**. Generic `401` on a wrong/unset
secret or a bad signature. Recovery restores **account access, not E2EE message history**.

## Password change (device-signed + current password)

### `POST /v1/session/password/begin` → `200`
Authed. Returns a `PasswordChange` challenge `{ account_id, device_id, txn_id, nonce, expires_at }`
for the device to sign.

### `POST /v1/session/password/finish` → `204` | `400` | `401`
Authed. `{ txn_id, signature (64B hex), current_password, new_password }`. Requires BOTH factors —
the device signature over the `PasswordChange` transcript (proof of possession) AND the current
password — then validates the new password (length + blocklist + breach corpus, R-305) and rehashes
it (Argon2id + pepper if configured, R-303). `401 denied` on a bad signature or wrong current
password; `400 weak_password` if the new password fails policy/breach. Existing device-bound sessions
continue (they are not password-derived); the new password governs future logins.

## Controlled multi-device (ADR-0008)

### `POST /v1/devices/enroll/begin` → `200`
Authed as an existing (trusted) device. Reserves the new device's id + a nonce:
`{ device_id, txn_id, nonce, expires_at }`. The trusted device signs the `DeviceEnroll` transcript
(binding account + the reserved new device id + the new device's public key + nonce).

### `POST /v1/devices/enroll/finish` → `200` | `401`
Authed as the trusted device. `{ txn_id, device_public_key (65B hex), signature (64B hex) }` — the
trusted device's signature authorizing the new device. Returns a **session for the new device**
(relayed to it over the pairing channel). Refused (generic `401`) on a bad signature, an expired
challenge, or at the per-account device cap. A stolen username/password can never add a device.

### `GET /v1/devices` → `200`
Authed. The account's devices: `[{ device_id, revoked, current }]`.

### `POST /v1/devices/revoke` → `204` | `403`
Authed. `{ device_id }` — revoke one of the caller's own devices (cascades access-token + refresh
family invalidation). `403` if the device is not the caller's.

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
**Sealed-sender envelopes** (ADR-0014) also appear here with `"sealed": true`, **no**
`sender_device`, and **no** `conversation_id` (the relay never learned them; the recipient
recovers the sender + conversation from the decrypted payload). Sealed ids are a **separate id
space** from identified ones — ack them via `sealed_ids`, not `ids`.

### `POST /v1/inbox/ack` → `204`
`{ "ids": [<envelope id>, …], "sealed_ids": [<sealed envelope id>, …] }`. Acknowledge
durably-persisted envelopes so they stop being served and become eligible for retention purge.
`sealed_ids` is optional (existing clients that send only `ids` are unaffected). Scoped to the
caller's own device; idempotent.

### `POST /v1/sealed/deliver` → `202` | `403` | `429` (ADR-0014 Slice 2b, R-204)
**Unauthenticated.** Delivers a sealed-sender message. Header `X-Delivery-Key: <hex K_r>` (the
recipient's 32-byte delivery access key; **never logged**); body
`{ recipient_device, ciphertext, idempotency_key }` (all hex; `idempotency_key` is a
sender-chosen 128-bit random). The relay verifies `SHA-256(K_r)` against the recipient account's
registered verifier and, on match, stores an envelope with **no sender and no conversation** →
`202`. Unknown device, unset verifier, and wrong/absent key all return the **same** `403` (no
existence oracle; the constant-time compare runs on every path). Authorized deliveries are
rate-limited per **recipient** device (`429`). Idempotent on `(recipient_device, idempotency_key)`.
Register/rotate the verifier via `PUT /v1/delivery-access-key`.

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
