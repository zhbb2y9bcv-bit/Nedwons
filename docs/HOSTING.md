# Production hosting

What actually has to run, who can see what, and what it costs. Every price below is an **estimate
that must be re-verified against current provider pricing** before it is relied on — cloud pricing
changes often and varies by region.

## 1. Who hosts the messages?

**You do — not Apple.** The App Store is a distribution channel: it hosts the *application binary*
and delivers updates. It does not host conversations, does not operate the relay, and does not store
message data.

Nedwons must operate (or contract) the servers that accept, queue, and deliver ciphertext. If those
servers stop, messaging stops, even though the app is still installed and downloadable.

## 2. What Apple provides vs. what Nedwons must run

| Apple provides | Nedwons must operate |
|----------------|----------------------|
| App Store distribution, updates, TestFlight | The HTTP API (`services/api`) |
| Apple Push Notification service (APNs) — carries a **contentless** wake push | The ciphertext relay + inbox queues |
| Secure Enclave, Keychain, Data Protection on device | PostgreSQL (accounts, devices, routing metadata, queued ciphertext) |
| App Attest attestation service | The key-transparency log + its signing key |
| iCloud (not used for message content) | Any future encrypted attachment storage (object store) |

APNs never carries plaintext. The push is a wake signal; the Notification Service Extension then
fetches and decrypts on device.

## 3. How a message travels

1. Sender's device encrypts with MLS (hybrid post-quantum X-Wing key exchange). Plaintext never
   leaves the device.
2. The device `POST`s the opaque ciphertext to the API, authenticated with a short-lived access
   token plus a device-key proof.
3. The relay stores the ciphertext in the recipient's inbox queue. It is a routing envelope only —
   the relay has no key that can open it (INV-1, proven by `relay-blindness` tests that query the
   database directly).
4. APNs delivers a contentless wake push, or the recipient's live WebSocket/long-poll picks it up.
5. The recipient's device fetches, decrypts locally, and acknowledges. Acked envelopes age out per
   the retention TTL (30 days by default).

## 4. Services in this repository that need production hosting

| Component | What it is | Hosting need |
|-----------|-----------|--------------|
| `services/api` | Axum HTTP server, modular monolith: auth, devices, social, relay, push, transparency | Long-running compute, 2+ instances behind a load balancer |
| PostgreSQL | Accounts, devices, refresh tokens, social graph, conversation membership, queued ciphertext | Managed Postgres with automated backups + PITR |
| Key-transparency log | Append-only RFC 6962-style log; clients self-monitor their own keys | Runs inside `services/api`; **needs a durable, protected signing key (KMS/HSM)** |
| APNs credentials | Push certificate / auth key (`.p8`) | Secret manager, never in the image |
| Attachment store | Not yet implemented | Object storage with per-object encryption when built |

Not needed in production: `infra/docker-compose.yml` (local dev only), the smoke/live-run scripts
(CI and manual verification only).

## 5. Three realistic approaches

### A. Managed beta (recommended for now)
A single small container instance plus managed Postgres — e.g. Fly.io, Render, or Railway.

- ~$5–15/mo compute, ~$15–25/mo managed Postgres, ~$0–5 egress.
- **Roughly $25–50/mo** for a private beta of tens to low hundreds of users.
- Fast to stand up, TLS and deploys handled, no Kubernetes to babysit.
- Accepts single-region and modest availability, which a beta can tolerate.

### B. Production cloud with managed database and HA
AWS/GCP: 2+ API instances across availability zones behind an ALB, RDS/Cloud SQL with Multi-AZ and
PITR, KMS for the log signing key and APNs secrets, private subnets with restricted egress.

- ~$60–150/mo compute, ~$120–300/mo Multi-AZ Postgres, ~$20–40/mo load balancer, plus KMS, backups,
  logging and egress.
- **Roughly $250–600/mo** at low-to-moderate scale, growing mainly with database size and egress.
- This is the tier that can honestly claim availability and durability.

### C. Operationally independent / self-managed
Dedicated or bare-metal servers (Hetzner, OVH) running Postgres yourself with streaming replication.

- **Roughly $50–150/mo** for materially more raw capacity.
- Materially cheaper per unit, but you own patching, replication, backup verification, monitoring,
  and on-call. Attractive later for jurisdictional control or margin; a poor use of time now.

**Recommendation: (A) for the current stage.** There is no production traffic, physical-device
testing is unfinished, and external audits have not happened. Spending on HA before the product is
validated buys nothing. The API is a stateless Rust binary against Postgres, so moving from (A) to
(B) is a deployment change, not a rewrite — do it when a real user base or an availability
commitment justifies it.

## 6. What each provider can still observe

Be precise here, because this is where "private messenger" claims usually become dishonest.

**Cannot be observed by any host:** message plaintext, MLS group secrets, message keys. These exist
only on devices.

**Can be observed by the hosting provider:**
- Stored ciphertext, and its size and timing.
- Network metadata: source IPs, connection times, request volume, TLS SNI.
- Database contents that are metadata by nature: which accounts exist, which devices are enrolled,
  conversation membership, queue depth, timestamps.
- Infrastructure logs the platform generates (load balancer access logs, platform audit logs) unless
  explicitly reduced.
- A managed-database provider can read the database. Sealed sender (ADR-0012/0014) narrows what the
  *relay* learns about who is talking to whom, but it does not hide that an account exists or that
  ciphertext is queued for it.

**Do not claim "no logs" without verifying every layer** — application, load balancer, database,
platform audit trail, and any CDN or WAF. Each defaults to logging something. A defensible claim
names what is retained and for how long.

## 7. Operations without logging plaintext

- **Logging:** structured logs with an explicit deny-list; never log request bodies, ciphertext,
  tokens, or key material. Log identifiers, not content. Short retention (e.g. 14–30 days).
- **Metrics:** counts, latencies, queue depths, error rates. No payloads.
- **Backups:** automated, encrypted, with periodic *restore drills* — an untested backup is not a
  backup. Backups contain ciphertext and metadata, never plaintext, so a backup leak is far less
  severe than it would be in a plaintext system. That is a design benefit worth keeping true.
- **Secrets:** KMS or a secret manager for the transparency log signing key, database credentials,
  and the APNs key. No long-lived secrets in images, environment files, or CI variables visible to
  forks. Rotate on a schedule and on suspicion.
- **Incident response:** documented severity levels, a key-compromise playbook, and a dependency
  emergency-update path. Because there is no "view user messages" admin function, an operator
  compromise leaks metadata and ciphertext — not conversations. Keep it that way.

## 8. Apple Developer configuration required

None of this is done yet; all of it needs a paid Apple Developer account.

- **App ID + provisioning** for `app.nedwons.*`, including the Notification Service Extension's own
  App ID.
- **APNs authentication key** (`.p8`) or push certificate, with separate sandbox and production
  environments.
- **App Groups** — the app and the Notification Service Extension share a container so the extension
  can reach the MLS store.
- **Keychain sharing group** — the extension needs the at-rest key after first unlock.
- **App Attest** — separate development and production attestation environments; used strictly as
  defense-in-depth, never as a substitute for device-key proof.
- **Background modes: remote notification** (already declared in `project.yml`).
- **Privacy manifest + required-reason API declarations** before App Store submission.
- **Push Notifications capability** enabled on the App ID.

## 9. Production-readiness items still unverified

- Physical-device behaviour of everything hardware-bound: Secure Enclave key generation, Keychain
  ACLs, App Group and Keychain-group sharing with the extension. Simulator results do **not**
  establish these.
- Live APNs delivery and Notification Service Extension decryption on a real device.
- A durable, non-ephemeral transparency log signing key. The dev server currently generates an
  ephemeral key and logs a warning; production must supply `NEDWONS_LOG_SIGNING_KEY` from KMS.
- TLS termination, certificate management, and any pinning decision.
- Load and soak testing at realistic fan-out.
- External mobile, backend/infrastructure, and cryptographic reviews (R-503).
- Backup restore drills and a rehearsed incident-response run-through.

No cloud accounts, billing, or infrastructure have been created. Nothing here has been deployed.
