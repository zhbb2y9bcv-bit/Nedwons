# Incident runbooks

One page per alert. Each names an **owner**, a **threshold** that should page, the **first checks**,
a **rollback**, and what **evidence** to keep and for how long.

Two rules apply to every runbook here and are not repeated in each:

- **Never resolve an incident by turning off the signal.** Raising a threshold or disabling an
  alert is a change, and it goes through review like any other.
- **Never collect message content while investigating.** The relay cannot read it (INV-1) and the
  logs must not contain it (INV-8). If a diagnosis seems to require plaintext, the diagnosis is
  wrong — escalate to the crypto owner instead of reaching for the data.

Metric names below are the real ones exposed on `/metrics` (gated by `NEDWONS_METRICS_TOKEN`).

---

## 1. Authentication failure spike

**Owner:** backend lead · **Metric:** `nedwons_auth_failures_total`

**Page when** the 5-minute rate exceeds 10x the trailing 24-hour median, or when the ratio of
`nedwons_auth_failures_total` to `nedwons_auth_successes_total` exceeds 5:1 for 10 minutes.

Distinguishing the two cases this could be is the whole job:

1. Are successes still happening at a normal rate? If yes, this is **credential stuffing against
   many accounts** — the service is healthy and under attack. If successes collapsed too, it is an
   **outage**: check `nedwons_db_pool_wait_failures_total` and the database first.
2. Check whether failures concentrate on a few source networks. Per-IP limiting
   (`nedwons_rate_limited_ip_total`) should already be biting; if it is not, the client-IP source
   is probably misconfigured — a forwarded header nobody sets means every request shares one key
   (see `NEDWONS_TRUSTED_IP_HEADER`, R-306).
3. Remember what an attacker gains here: **nothing without the device key.** A correct password
   from an unenrolled device cannot create a session (INV-2). A spike is noisy, not fatal.

**Rollback:** none applicable — this is not a deploy. If a deploy correlates, roll it back.

**Evidence:** counter series for 7 days; per-IP limiter counters. **Do not** start logging
credentials or usernames to investigate.

---

## 2. Proof replays rejected

**Owner:** backend lead · **Metric:** `nedwons_proof_replays_rejected_total`

**Page when** any sustained non-zero rate appears (> 5 in 5 minutes). This counter should sit at
zero in normal operation.

A spent nonce presented again is **not** an ordinary client bug — it means someone is replaying a
captured proof. Check first whether a client release is retrying requests without minting a fresh
nonce (a bug that would show as a step change aligned to a release). If no release correlates,
treat as an attempted token replay: the access token is sender-constrained, so the replay failed,
but the presence of captured proofs implies a compromised client or a TLS-terminating middlebox.

**Rollback:** if a client release correlates, roll the client forward/back — do NOT disable
`NEDWONS_REQUIRE_PROOF` to make the alert stop, as that downgrades a stolen access token from
inert to sufficient.

**Evidence:** counter series 30 days; the correlating client version. No proofs or tokens.

---

## 3. Key-transparency append failure

**Owner:** security architect · **Metric:** `nedwons_kt_append_failures_total`

**Page immediately on any non-zero value.** This is the highest-severity alert in this document.

A failed append means a device binding was created but **not** recorded in the transparency log, so
the log now has a gap and clients auditing their own keys cannot see that binding. Users cannot
detect a maliciously added device through a log that is missing entries.

1. Confirm the log signing key is the stable one (`NEDWONS_LOG_SIGNING_KEY`). An ephemeral key
   means every previously issued proof is already invalid — this is a separate, worse incident.
2. Identify the affected bindings from `devices`/`accounts` rows created in the window with no
   corresponding leaf, and reconcile by appending them.
3. Announce, do not paper over. A silent gap is indistinguishable from tampering, which is exactly
   the property the log exists to provide.

**Rollback:** roll back the deploy that correlates. The log itself is append-only and is never
rewritten to "fix" a gap.

**Evidence:** retain indefinitely — this is an integrity incident. Log index range, affected
account/device ids (ids only; no keys), and the reconciliation commit.

---

## 4. Database pool saturation

**Owner:** ops · **Metrics:** `nedwons_db_pool_wait_failures_total`, `nedwons_db_pool_in_use`

**Page when** `nedwons_db_pool_wait_failures_total` increases at all over 5 minutes, or
`nedwons_db_pool_in_use` sits at the configured maximum for 5 minutes.

Checkouts fail after a deliberately short 5s timeout, so saturation surfaces as request failures
rather than as an unbounded queue. Check for a slow query holding connections (statement timeout is
15s), then for a traffic spike, then for a database-side problem (locks, autovacuum, failover).

Note the interaction worth knowing before it bites: proof verification and the abuse quotas both
touch the database on the request path. Under saturation, **authentication fails closed** — which is
correct, and also means saturation looks like an auth outage.

**Rollback:** scale the pool or the instance count; roll back a correlating deploy. Raising
`statement_timeout` is not a fix.

**Evidence:** pool gauges and slow-query samples for 7 days. Query text only — never parameters,
which are user data.

---

## 5. Queue depth growing

**Owner:** backend lead · **Metric:** `nedwons_queue_depth`

**Page when** depth grows monotonically for 30 minutes, or exceeds 10x the trailing weekly peak.

Envelopes accumulate when recipients are not draining. Check `nedwons_websockets_open` (live
delivery) and `nedwons_push_failures_total` (wake pushes) — a push outage looks exactly like "users
stopped using the app", which is how it hides. Confirm the retention purge is running; a stalled
purge grows the queue without any delivery problem at all.

**Rollback:** roll back a correlating deploy. Do NOT purge the queue to reduce the number —
undelivered envelopes are users' messages.

**Evidence:** depth series and delivery counters for 30 days.

---

## 6. APNs push failures

**Owner:** ops · **Metric:** `nedwons_push_failures_total`

**Page when** the failure ratio to `nedwons_push_sent_total` exceeds 20% for 15 minutes.

Push is best-effort by design — a wake push is a hint, never the delivery path — so this is a
degradation, not an outage: messages still arrive when the app is foregrounded. Check credential
expiry (`NEDWONS_APNS_*`), then whether the topic still matches the shipped bundle id, then Apple's
status. A total, sudden drop to zero success is usually a credential or topic problem, not Apple.

**Rollback:** rotate/restore the APNs key. Note that a half-configured APNs is refused at startup
in production, so a partial configuration cannot be the cause of a *running* service failing.

**Evidence:** counters 7 days; APNs response status codes. Never device tokens.

---

## 7. Abuse quota exhaustion climbing

**Owner:** product + backend lead · **Metric:** `nedwons_quota_exhausted_total`

**Page when** the 1-hour rate exceeds 20x the trailing weekly median.

Either abuse is being throttled (working as intended) or a legitimate flow is being throttled (a
product bug). Distinguish by which quota: search exhaustion at scale suggests enumeration; friend
request exhaustion suggests spam; invite exhaustion suggests group spam. A client release that
retries aggressively can also exhaust quotas and will correlate with a version.

**Rollback:** if a client release correlates, roll it back. Raising a limit is a product decision,
not an incident response — and it is the one change most likely to be regretted at 3am.

**Evidence:** counters 30 days. Aggregate only: the counters carry no account identifiers by
design, and adding them "just to investigate" would violate INV-8.

---

## 8. Attestation failures

**Owner:** iOS lead · **Metric:** `nedwons_attestation_failures_total`

**Page when** the rate exceeds 10x the trailing 24-hour median.

Usually a client or configuration problem rather than an attack: a wrong `NEDWONS_APP_ATTEST_APP_ID`,
a development-environment attestation reaching production, or a new build not yet associated with
the App ID. A genuine attack looks different — a low, steady trickle rather than a step change.

Consequence, so severity is judged correctly: a failed attestation means the device does not reach
`hardware` assurance, so it cannot approve enrollment of another device. It does not block ordinary
messaging.

**Rollback:** roll back the correlating client release or configuration change.

**Evidence:** counters 30 days; the failing client version.

---

## 9. Account deletion volume

**Owner:** product · **Metric:** `nedwons_accounts_deleted_total`

**Page when** the daily rate exceeds 10x the trailing weekly median.

Deletion is irreversible and erases across every store, so a spike is worth understanding
immediately. The two cases to separate are a **product/trust event** (people leaving) and a **bug or
abuse** (an automated path deleting accounts). Check whether deletions correlate with a release, and
confirm each deletion was preceded by the reauthentication ceremony — deletion requires BOTH the
device signature and the password, so a spike without matching auth activity would indicate
something is very wrong.

**Rollback:** if a bug is deleting accounts, take the endpoint out of service immediately (deploy a
build with the route removed). **Deleted data is not recoverable from the service** — backups are
the only path, and restoring one re-creates data users asked to have erased, which is itself a
decision requiring the privacy owner.

**Evidence:** counter series retained indefinitely; deletion audit events. No account contents.

---

## Evidence retention summary

| Class | Retention | Rationale |
|---|---|---|
| Integrity incidents (KT gaps) | Indefinite | The log's value is that it is never quietly rewritten |
| Security counters (auth, proof, attestation, quota) | 30 days | Long enough to see a slow campaign |
| Capacity/operational metrics | 7 days | Diagnosis window; no security value afterwards |
| Structured request logs | 14–30 days | Route shape, status, latency, request id — never bodies or identifiers |
| Message content | **Never collected** | The relay cannot read it and the logs must not contain it |
