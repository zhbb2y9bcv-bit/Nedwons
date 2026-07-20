# Release Checklist

Nothing here is checked off yet beyond what the working copy proves. This is the gate to
calling Nedwons production-ready. Cross-references to [RISK_REGISTER.md](RISK_REGISTER.md).

## Build & toolchain

- [ ] iOS release config compiles with **iOS 26 SDK + Xcode 26** (mandatory since
      2026-04-28; we have Xcode 26.6). *(R-401)*
- [ ] Backend + migrations build cleanly.
- [x] `services/auth-core` compiles and tests pass (`cargo test`). *(this working copy)*

## Security acceptance (from the mission)

- [ ] A newly registered device can log in; a **different** device with the exact
      username/password **cannot** without trusted enrollment or recovery.
      *(logic proven in `auth-core`; end-to-end on-device pending R-101)*
- [ ] Replayed login challenges, refresh tokens, message envelopes, uploads, and state
      mutations are rejected or safely deduplicated. *(challenge/refresh replay proven in
      `auth-core`; API/envelope layer pending)*
- [ ] Two Apple devices exchange messages with offline delivery, reconnect, retries, and no
      duplicates. *(Milestone 2, R-104)*
- [ ] Server DB, object store, queues, push payloads, logs, traces, crash reports, and
      backups inspected in tests: **no** message/attachment plaintext or keys. *(Milestone 2,
      R-104)*
- [ ] Identity change, group membership change, revocation, recovery, password change,
      account deletion, lost-device — all work with security regression tests. *(R-304)*
- [ ] Local secrets are hardware/secure-storage protected; release binary contains no secret
      or debug bypass. *(R-101, R-502)*
- [ ] Accessibility, reduced-motion, large-text, screen-reader, offline, permission-denied,
      and error flows usable. *(Milestone 3/5)*
- [ ] Core messaging runs **without a GPU**; optional compute failure cannot affect auth or
      delivery. *(Milestone 6)*
- [ ] SAST/SCA/secret/container/mobile scans: no unresolved critical/high; exceptions
      explicit, owned, time-limited. *(R-501)*
- [ ] Independent **mobile**, **backend/infra**, and **cryptographic** reviews completed;
      findings remediated or formally accepted. *(R-503)*
- [ ] Store privacy disclosures match actual behavior; in-app + external deletion paths work;
      release/rollback/incident procedures rehearsed. *(R-402, R-502)*

## Store submission (Apple)

- [ ] App Store Review Guidelines re-checked (accessed date recorded in ADR).
- [ ] Privacy manifest + required-reason API declarations accurate.
- [ ] App Store privacy "nutrition label" matches PRIVACY.md and shipped behavior.
- [ ] Age-rating questionnaire updated (Apple deadline was 2026-01-31 for uninterrupted
      submission).
- [ ] Export-compliance / encryption declaration completed with counsel.
- [ ] App Attest, APNs, and signing configured with **separate prod keys**; none in repo/CI
      visible to forks.

## Operations

- [ ] Runbooks rehearsed: incident response, key compromise, signing compromise, attestation
      outage, push outage, DB incident, abusive traffic, regional failure, compromised
      dependency, queue backlog, emergency client update.
- [ ] Encrypted backups with a **tested restore** (an untested backup is not a recovery plan).
- [ ] SBOM + provenance produced for release artifacts; signed release; rollback rehearsed.

## Do-not-ship blockers (must all be false)

- [ ] Any hardcoded secret, demo credential, permissive CORS, open bucket, `trustAll` TLS,
      wildcard authz, or production debug endpoint. **→ must be NONE**
- [ ] Any production `TODO`, placeholder handler, dead button, swallowed exception, or mock
      security response in release code. **→ must be NONE**
- [ ] Any `Critical` risk in RISK_REGISTER still `OPEN` without a time-boxed, owner-signed
      acceptance. **→ must be NONE**
