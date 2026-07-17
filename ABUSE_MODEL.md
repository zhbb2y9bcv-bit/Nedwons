# Abuse Model

Distinct from [THREAT_MODEL.md](THREAT_MODEL.md) (attacks on confidentiality/integrity),
this covers **abuse of intended functionality**: spam, harassment, fraud, and
denial-of-service — where the challenge is that E2EE means the server cannot read content.

## Abuse cases

| Case | Vector | Controls |
|------|--------|----------|
| Fraudulent account creation | Automated signup | Per-IP/per-device/global rate limits, App Attest signal, proof-of-work/challenge on risk, abuse scoring. |
| Credential stuffing / brute force | Login attempts | Enumeration-resistant generic errors, constant-ish timing, dummy-hash path, layered rate limits, exponential backoff — **without** allowing indefinite victim lockout. |
| Account-recovery abuse | Take over via recovery | Trusted-device approval or recovery kit only; reauth; enrollment delay for risky cases; security notifications; rate limits (ADR-0003; R-304). |
| Spam / unsolicited messages | Mass DMs, invites | **Message requests** gate first contact; block/report; rate limits on new-conversation fanout; invite-link abuse controls. |
| Harassment | Repeated contact, groups | Block (applies across requests, groups, calls, invites, presence, notifications); leave/mute; report with user-selected evidence. |
| Impersonation | Homoglyph/lookalike usernames | Deliberate username normalization; reserved-name protection; safety numbers to verify identity; immutable internal account id separate from changeable username. |
| Group-admin abuse | Rogue admin adds/removes | Authenticated membership; epoch rotation on changes; join-approval; role management with audit. |
| Scraping / enumeration | Probe usernames | Generic responses, rate limits, no bulk directory. |
| DoS | Connection/notification/reconnect storms | Backpressure, circuit breakers, rate limits behind trusted proxies, bounded resource usage, load-tested fanout. |
| Attachment abuse | Malware, bombs, polyglots | Local pre-encryption warnings + type/size validation; server sees only ciphertext, so scanning is client-side and honest about limits. |

## Username normalization policy

- Immutable **random internal account ID** is the identity; the public **username** is
  changeable and cosmetic.
- Conservative normalization: define an allowed set (start ASCII-conservative), reject
  invisible/zero-width characters, normalize ambiguous casing, prevent homoglyph
  impersonation and reserved-name abuse, and prevent normalization collisions (two inputs
  mapping to one identity).
- Normalization is applied identically at registration, login, and lookup.

## Rate-limiting principles

- **Layered**: per-IP, per-account, per-device, and global.
- **Fail-closed but victim-safe**: an attacker must not be able to permanently lock out a
  victim; use backoff, challenges, and alerting rather than hard indefinite locks.
- **Works behind trusted proxies**: real client identification via a vetted forwarded-header
  configuration, never a spoofable client claim.
- High-risk endpoints (login, recovery, username/password change, device enrollment, key
  reset, account deletion, export) get the strictest limits + alerting.

## Moderation stance under E2EE

The server cannot and must not read message content. Abuse handling therefore relies on:
user-initiated **reporting** (with explicit, user-selected decrypted evidence), **blocking**,
local pre-send **warnings**, account/behavior signals (rate/fanout/velocity), and
device/attestation risk — **never** a hidden decryption capability or universal scanning.
This is a deliberate, stated tradeoff.
