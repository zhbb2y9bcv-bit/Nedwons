# Data Retention

Retention is minimized and documented. Timers below are **design targets** for v1; final
values require legal review (RISK_REGISTER R-403). "Purge" means deletion or irreversible
anonymization; where cryptographic erasure applies, destroying the key renders ciphertext
unrecoverable.

| Data class | Retention target | Mechanism | Notes |
|------------|------------------|-----------|-------|
| Undelivered ciphertext envelope | Until delivered, else **30-day** queue TTL (`NEDWONS_ENVELOPE_TTL_DAYS`, default 30) | Relay queue TTL job (minutely, **bounded batches** so a backlog drains without one long table-locking DELETE) | After TTL, envelope is purged; sender sees "failed". |
| Delivered ciphertext envelope | Purged from server **on delivery ack** | Relay | Server does not retain delivered message ciphertext as a store; the device is the store. |
| Ciphertext attachment (object store) | **30-day** TTL or on message deletion | Object lifecycle policy | Keys live only in the E2EE envelope; expiring the object is sufficient. |
| Disappearing-message queue copy | min(disappearing timer, queue TTL) | Relay TTL | Client-enforced too; honest limits (R-901). |
| Routing metadata | **Short** (target ≤ 30 days), minimized | DB partition drop | Enough to deliver + debug delivery, no more. |
| IP address / LB & proxy logs | **Short** (target ≤ 7–30 days) | Log rotation | Access-controlled; abuse/security exception may extend for specific investigations. |
| Abuse/rate-limit counters | Rolling window (hours–days) | Cache/DB TTL | Not retained beyond usefulness. |
| Push token | Until rotated or invalid | On APNs feedback / rotation | Removed promptly when invalid. |
| Audit / security events | **Longer** (target 1 year), tamper-evident | Append-only, access-logged | Separate from general telemetry; retention set by policy/legal. |
| Crash reports (opt-in) | Bounded (target ≤ 90 days) | Crash pipeline | Scrubbed of plaintext/usernames/tokens/paths. |
| Account record | Life of account | — | Deleted on account deletion (below). |
| Password hash | Life of account | — | Deleted on account deletion. |
| Backups (encrypted) | Per backup policy; tested restores | Encrypted backup lifecycle | A backup never restored in a test is not a valid recovery plan. |

## Deletion propagation (INV-10)

On **account deletion**:
1. Revoke all sessions and refresh-token families immediately.
2. Delete credentials, device keys (public), and account record.
3. Purge queued ciphertext for the account; drop routing metadata on the next partition cycle.
4. Trigger cryptographic erasure of any server-held encrypted-backup material tied to the
   user-controlled recovery secret (the server cannot decrypt it regardless).
5. Messages already delivered to other users remain on their devices — stated in-UI.

On **device revocation**: the device's sessions/refresh families are revoked, its push token
removed, and its public key marked revoked so future signatures fail closed. Propagation
timelines are documented and tested (Milestone 1/3).

## What we intentionally do not retain

Message/attachment/call/backup **plaintext**, decryption keys, passwords, biometric
templates, raw recovery material, full IP history, or contact books. See
[PRIVACY.md](PRIVACY.md).
