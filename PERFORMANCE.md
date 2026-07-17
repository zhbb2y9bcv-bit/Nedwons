# Performance & messaging efficiency

Real messaging speed is dominated by things a single-message demo never shows: round-trips,
idle delivery latency, retry behavior under packet loss, and fan-out cost in groups. This
document records what is **implemented and tested**, and — just as importantly — the
counterintuitive choices where the "obvious" optimization is wrong for an E2EE system.

## Implemented and tested

### 1. Server-side fan-out (N→1 uploads per group message)
An MLS application message is **one ciphertext** the whole group decrypts. A naive client
uploads it once per recipient device (N uploads, N× bandwidth, N× latency). Instead the
client uploads once to `POST /v1/conversations/{id}/messages` and the server fans it out to
every other member device in **a single SQL statement** (`INSERT ... SELECT ... FROM
conversation_members ... ON CONFLICT DO NOTHING`). For a 50-person group that's 1 upload
instead of 50. Tested in `relay_e2ee.rs` (`delivered` count).

### 2. Long-poll inbox (near-zero idle delivery latency)
Polling means delivery latency ≈ poll interval and constant wasted requests. `GET
/v1/inbox?wait=N` returns immediately if mail is present, otherwise **parks** until a send
wakes it (in-process `tokio::sync::Notify` keyed by device) or `N` seconds elapse. Crucially
a parked waiter holds **no database connection** — only a cheap async task — so idle clients
cost nothing. Tested: `inbox_long_poll_wakes_on_delivery` asserts the waiter returns in well
under the timeout when a message is sent 200 ms in.

*Honest limit:* the notifier is per-process. Across multiple API instances a waiter and its
sender may be on different processes, so production adds a cross-instance signal (PostgreSQL
`LISTEN/NOTIFY` or a bus). The database stays the source of truth and every wait is
timeout-bounded, so a missed cross-instance wake only delays by the timeout — it never loses
a message. WebSocket/QUIC streaming is the next upgrade beyond long-poll.

### 3. Idempotent send (safe aggressive retries)
Every send carries a 16-byte `idempotency_key`. A retry after a dropped response is a no-op
(unique index `(sender_device, recipient_device, idempotency_key)`), so clients can retry
**immediately and aggressively** instead of using conservative long backoffs to avoid
duplicates. Faster recovery from transient loss, and no duplicate messages. Tested: the
idempotent-retry assertion (`delivered == 0` on replay).

## Counterintuitive choices (where the obvious optimization is wrong)

- **Do not compress on the server.** Envelopes are ciphertext, which is incompressible —
  gzip/br buys nothing and just burns CPU. Worse, compressing **attacker-influenced plaintext
  together with secrets before encryption** enables compression-oracle attacks (CRIME/BREACH
  class). Any compression must happen client-side, before MLS encryption, over content that
  doesn't mix secrets with attacker-controlled data, and is a deliberate per-message decision
  — never a blanket transport feature.
- **MLS padding is a speed/privacy tradeoff, not free.** Padding message length hides
  plaintext size from traffic analysis but costs bandwidth. This is a conscious knob
  (`MlsGroup` padding), not something to minimize away for "speed".
- **Don't precompute what the Enclave must do live.** The device-key signature can't be
  cached or precomputed; it's a live Secure Enclave operation. Optimize the *transcript build*
  around it, not the signature.
- **Argon2 is meant to be slow.** Login latency includes a deliberately expensive password
  hash. It runs on `spawn_blocking` so it never stalls the async reactor, but you do not tune
  it *down* for speed — you sit it behind the device-key check and rate limits.

## Already in place (supporting the above)

- **CPU/blocking work off the reactor.** Argon2, ECDSA verification, and all DB calls run on
  `spawn_blocking`, so the async runtime stays responsive under load.
- **Connection pooling** (`r2d2`, 16 conns) with lazy connect; the sync Postgres client is
  isolated from the async runtime (see `pgstore` / `main`).
- **Targeted indexes**: `envelopes_inbox (recipient_device, id)` for ordered inbox reads;
  partial unique indexes for idempotency and single-active-device; `key_packages_by_account`.
- **Ordered delivery**: `fetch_inbox` sorts by id (MLS requires in-order processing of
  commits/welcomes) — a bug caught by `relay_e2ee.rs`.
- **HTTP keep-alive / TLS reuse**: `URLSession` (client) and hyper (server) reuse connections
  by default, amortizing TLS handshakes across messages.

## Worthwhile next steps (not yet done)

- **WebSocket (or WebTransport) delivery** to replace long-poll for sub-100 ms push and to
  carry typing/presence cheaply. Long-poll is the stepping stone.
- **Explicit delivery ack** so the server purges delivered ciphertext on client confirmation
  (DATA_RETENTION.md) rather than on fetch — turns at-most-once fetch into at-least-once with
  client dedup, preventing loss if a client crashes mid-fetch.
- **Prepared-statement reuse** for the hottest queries (the sync `postgres` client re-parses
  string queries; caching `Statement` handles per pooled connection removes a parse per call).
- **Batch key-package claim / prekey prefetch** so adding several members is one round trip.
- **Attachment path**: chunked, resumable, per-object-key encryption uploaded to object
  storage out-of-band, with only the key + hash inside the E2EE envelope (ARCHITECTURE.md).
- **APNs push** for wake-from-background so a closed app still receives messages promptly
  (payloads remain opaque wake-ups — no plaintext, PRIVACY.md).
- **Load & soak tests**: connection fan-out, group fan-out, reconnect storms with jittered
  backoff, and long-poll under many idle waiters (validates the "zero DB cost while idle"
  claim at scale).
