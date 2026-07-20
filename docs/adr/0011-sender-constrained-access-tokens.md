# ADR-0011: Sender-constrained access tokens (DPoP-style, R-308)

- **Status:** Accepted — implemented behind a deployment flag (default off during migration);
  enforce-by-default + a distributed replay cache are follow-ups (tracked in R-308).
- **Date:** 2026-07-18
- **Deciders:** backend lead, security architect

## Problem (R-308)

Refresh tokens are already **sender-constrained**: rotating a refresh token requires an ECDSA-P256
signature by the device's enrolled key over a canonical transcript (ADR-0002). **Access tokens are
not** — they are opaque bearer values. Anyone who exfiltrates a live access token (a logging leak, a
compromised TLS-terminating proxy, a mis-scoped backup, malware scraping process memory) can use it
from **any** machine until it expires (~15 min). This undercuts the whole point of hardware device
binding: the mandatory control (proof-of-possession of a non-exportable Secure Enclave key) protects
enrollment and refresh but not the requests in between.

## Options

1. **Short-lived access tokens only.** Reduce TTL to minutes. Mitigates but does not close the
   window, and shortening it further multiplies refresh traffic (each refresh is an Enclave
   signature + DB write). Bearer semantics remain.
2. **Signed short tokens (PASETO/JWT) bound to a key (`cnf`/JKT).** Standard, but introduces a JWT
   stack and a second signature scheme alongside our existing raw-P256 transcripts, and stateless
   tokens complicate revocation (which server-side opaque tokens make trivial — R-307).
3. **DPoP-style per-request proof-of-possession (RFC 9449 semantics) *(chosen)*.** Keep the opaque,
   server-side, revocable access token, and additionally require a **per-request proof**: the
   device signs a canonical transcript binding the HTTP method, path, a hash of the access token,
   a timestamp, and a unique nonce, with its **enrolled device key**. The server verifies the proof
   against the key already on file for the token's device. A stolen token is now useless without the
   non-exportable private key.

## Decision

Option 3, expressed in Nedwons's existing idiom rather than JWS: the proof is a **raw ECDSA-P256
signature over a domain-separated, length-prefixed transcript** (`auth_core::request_proof`), reusing
the exact vetted signing path as auth/refresh (no new crypto, no JWT dependency, no ad-hoc header
format). This is RFC 9449's security model — proof-of-possession bound to method+URI+token+time+nonce
— adapted to our transcript discipline.

### The proof transcript (`app.nedwons.dpop.v1`)

```
len32(DOMAIN) || DOMAIN
  || u16(PROTOCOL_VERSION)
  || len32(METHOD)  || METHOD           (e.g. "GET", "POST")
  || len32(PATH)    || PATH             (request path, no query — bound separately if needed)
  || len32(TOKEN_HASH) || TOKEN_HASH    (SHA-256 of the presented access token)
  || u64(TIMESTAMP)                     (unix seconds, client clock)
  || len32(NONCE)   || NONCE            (16 random bytes, unique per request)
```

The client sends the proof in an `X-Nedwons-Proof: v1;ts=<u64>;nonce=<16B hex>;sig=<hex>` header
alongside `Authorization: Bearer <token>`.

### Server verification (in `authed_device`, when enforcement is enabled)

1. Validate the access token as today → `(account, device)`; look up the **device's enrolled public
   key** (`AuthService::device_public_key`, fail-closed on revoked).
2. Recompute `TOKEN_HASH = SHA-256(token)` server-side (the client cannot lie about which token the
   proof covers), reconstruct the transcript from the request's method + path + the proof's ts +
   nonce, and verify the signature under the device key.
3. **Freshness:** `|now − ts| ≤ SKEW` (±60 s) — bounds replay to the window.
4. **Replay:** the `(device, nonce)` pair must be unused within the window; a `ProofReplayCache`
   (time-bucketed, self-pruning) records accepted nonces and rejects repeats. A proof is
   single-use.
5. Any failure → generic `401 denied` (no oracle on which check failed).

### Migration & compatibility

- Enforcement is **opt-in** via `NEDWONS_REQUIRE_PROOF` (wired through `build_router_cfg`), default
  **off**, so existing conversations, clients, and the whole test suite are unaffected while clients
  roll out proof generation. A dedicated test suite exercises the enabled path end to end.
- WebSocket: the upgrade request (`GET /v1/stream`) carries a proof like any authed request; the
  long-lived socket thereafter is authorized by the completed upgrade (a per-frame proof is
  unnecessary and is out of scope — documented).
- Revocation is unchanged and still trivial (opaque server-side tokens; R-307).

## Consequences

**Positive:** a stolen access token alone is inert; the mandatory hardware key now protects every
request, not just enrollment/refresh. Reuses the audited transcript+P-256 path; no JWT stack.

**Negative / residual (keeps R-308 MITIGATING until addressed):**
- The replay cache is **per-instance** (same limitation as rate limiting, R-306); multi-instance
  deployments need a shared cache (Redis) or a server-issued-nonce challenge. Until then, a proof
  could in principle be replayed against a *different* instance within the skew window.
- Enforcement is **off by default** during migration; the risk is not closed until it is on by
  default and the client always signs.
- Per-request Enclave signatures add latency and (if the key requires user presence) friction;
  the enrolled device key is configured **without** per-use biometric for this reason, so proofs
  are cheap — revisit if that policy changes.
- No external review yet (R-503).

## References
- DPoP — RFC 9449: https://www.rfc-editor.org/rfc/rfc9449
- ADR-0002 (device binding), R-307 (opaque server-side tokens), R-306 (per-instance limiter caveat).
