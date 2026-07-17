# ADR-0006: Storage-agnostic security core with DB-enforced atomicity

- **Status:** Accepted
- **Date:** 2026-07-17
- **Deciders:** backend lead, security architect

## Context

The most security-critical logic (challenge issuance/consumption, password verification,
device-signature verification, refresh-token rotation) must be unit-testable now, but its
correctness ultimately depends on **atomicity** (a challenge is consumed exactly once; a
refresh token is swapped atomically) which only a real datastore guarantees under
concurrency.

## Decision

Split the two concerns:

1. **`services/auth-core`** contains pure, storage-agnostic security logic behind traits:
   `CredentialStore`, `DeviceStore`, `ChallengeStore`, `RefreshTokenStore`. In-memory
   implementations back the unit tests, which prove the *logic* (binding, replay rejection,
   fail-closed behavior, family revocation).
2. The **production backend** implements those traits over **PostgreSQL**, where atomicity is
   enforced by the database:
   - challenge consume: `DELETE FROM challenges WHERE id = $1 AND consumed_at IS NULL
     RETURNING ...` (or `UPDATE ... SET consumed_at = now() WHERE consumed_at IS NULL`), so a
     second consume affects zero rows and fails closed;
   - refresh rotation: compare-and-swap on a version/lineage column inside a transaction, with
     reuse of a retired token revoking the whole family;
   - unique constraints on `(account, username_normalized)` and device records.

The in-memory stores mimic these semantics (remove-on-consume returning presence) so the
tests exercise the same fail-closed paths.

## Consequences

**Positive:** security logic is testable today without a database; the seam is a clean place
to add Postgres, and the trait contract documents exactly what atomicity the DB must provide.

**Negative / risks:**
- The in-memory store's atomicity is not proof that the SQL is correct — the SQL
  implementation needs its own integration tests against a real Postgres with concurrent
  access. *(R-102)*
- Trait boundaries must not leak storage details into the security logic (guarded in review).

## Consequence for reviewers

When the Postgres implementations land, verify each trait method's SQL enforces the same
"exactly once / atomic swap / fail closed" semantics the in-memory version and the unit tests
assume. A mismatch here is a critical security bug, not a refactor.
