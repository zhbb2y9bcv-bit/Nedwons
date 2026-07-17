# Privacy

Privacy is the default. Sentinel collects the minimum data necessary to deliver encrypted
messages and defend the service from abuse. This document is the source for the eventual
Apple Privacy "Nutrition Label", the iOS privacy manifest, permission purpose strings, and
the public privacy policy — all of which must **match actual behavior** (RISK_REGISTER
R-402).

> Legal compliance (GDPR/UK GDPR/CCPA-CPRA, children's privacy/age assurance, data
> residency, export/sanctions, law-enforcement response) is **not** determined by this
> document or by code and requires qualified counsel (R-403).

## What we do NOT do

- No advertising SDKs, cross-app trackers, or session-replay SDKs.
- No invasive device fingerprinting. **No MAC address, IMEI, advertising ID, serial number,
  or any persistent hardware identifier** is collected, hashed, or transmitted (ADR-0002).
- No sale of user data. No raw address-book upload. No universal content scanning. No
  encryption backdoor.

## Data we process

| Data | Purpose | Retention | Visibility |
|------|---------|-----------|-----------|
| Random account ID | Identity | Life of account | Server (opaque) |
| Username (normalized) | Discovery/login | Life of account | Server; visible to contacts |
| Password (Argon2id hash) | Auth | Life of account | Server (hash only) |
| Public device key + metadata | Device binding | Life of device enrollment | Server (public key only) |
| Ciphertext message envelopes | Delivery | Until delivered + short TTL, then purged | Server (ciphertext only) |
| Ciphertext attachments | Delivery | TTL-bounded | Object store (ciphertext only) |
| Routing metadata (sender/recipient device, timestamps) | Delivery | Minimized; short retention | Server |
| Push token | Wake device | Until rotated/invalid | Server + APNs (opaque) |
| IP address / proxy logs | Abuse defense, ops | Short, documented window | Server (access-controlled) |
| Abuse/rate-limit counters | Abuse defense | Short, rolling | Server |
| Crash data (opt-in, scrubbed) | Reliability | Bounded | Server (no plaintext/usernames/tokens) |

Message and attachment **content is never processed server-side** — it is E2EE and the
server holds only ciphertext.

## Contact discovery

Default: **username, QR code, or invite link.** No raw address book is uploaded. If optional
contact matching is added later, it will use explicit permission, purpose limitation,
revocation/deletion, and a reviewed privacy-preserving design. A plain hash of phone numbers
is **not** treated as private (the domain is trivially enumerable).

## User controls (granular)

Read receipts, typing indicators, presence/last-seen, link previews, calls-from-unknown,
notification previews, disappearing-message timers, blocked users, data download/export,
backup on/off, and account deletion. Presence and typing are **off by default** and, when
enabled, are aggressively expired and metadata-minimized.

## Blocking & reporting

- **Blocking** takes effect across message requests, groups (where feasible), calls, invites,
  presence, and notifications.
- **Reporting is user-initiated.** The reporting user deliberately selects which decrypted
  messages/evidence to include, and the UI shows exactly what will be shared. There is **no**
  universal scanning and **no** decryption backdoor. Because the server cannot read E2EE
  content, moderation tradeoffs are handled via local pre-encryption warnings, user reporting,
  and blocking — documented honestly, not worked around with a hidden key.

## Deletion

In-app account deletion (and any required external deletion path) removes or anonymizes
associated data per [DATA_RETENTION.md](DATA_RETENTION.md), subject to legal obligations and
narrow fraud/security exceptions. Messages already delivered to other users' devices cannot
be recalled — this limitation is stated plainly in the UI.

## Telemetry

Privacy-sensitive telemetry is opt-in where practical, pseudonymized, sampled, short-lived,
access-controlled, and scrubbed **on the device before it leaves**. Correlation IDs are
random and unrelated to user-facing identifiers. Auth/key/message/media/recovery/report
endpoints do **not** record request/response bodies by default.
