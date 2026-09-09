# Content moderation: report → review → ban

Nedwons is end-to-end encrypted, so moderation has to be honest about what the operator can and
cannot see. This document is the whole pipeline: what a report contains, who reviews it, what the
standards are, what a ban does, and — stated plainly — what none of this can do.

## What the review standards are

Review is **legality-scoped**. Reviewers action content that is illegal to send, and nothing else:

| Category (wire value) | Covers |
|---|---|
| `illegal_content` | Child sexual abuse material (CSAM) and any other per-se illegal content |
| `sexual_exploitation` | Sextortion, non-consensual intimate imagery, grooming |
| `threats_violence` | Credible threats of violence, incitement |
| `spam_fraud` | Scams, phishing, fraud schemes |
| `other` | Anything the reporter couldn't classify (reviewed under the same standards) |

Disagreement, rudeness, and lawful-but-offensive speech are **not** actionable. Moderation of an
E2EE messenger is not viewpoint curation; it is the minimum a lawful operator must do.

**CSAM has extra obligations.** A US operator that obtains actual knowledge of CSAM must report it
to NCMEC's CyberTipline (18 U.S.C. § 2258A) and preserve the material as evidence per the statute
— *do not delete the report row*. Verified CSAM reports are: actioned (ban), preserved, and
reported to NCMEC by the operator. Build this into the team's runbook before launch.

## What a report contains — and what it cannot

The relay never holds message plaintext, so a report carries **only what the reporter's device
decrypted and the reporter explicitly chose to submit**:

- the reporter's words (`reason`), a category, and optionally the message text they saw
  (`evidence`);
- for a reported photo/file: the **decrypted bytes, re-uploaded from the reporter's device**
  (`evidence_media`, ≤ 5 MB) — never the E2EE blob id, which the server has no key for;
- opaque context ids (conversation, message) so repeated reports about one place group together.

Nothing else from the conversation is included, and the server derives nothing. This is the same
model Signal uses: reporting is the *recipient's* choice to show the operator what they were sent.
A malicious reporter can fabricate evidence — reviewers weigh it like any other unverified
submission, and the reporter's identity is attached to every report.

## Who reviews, and how access works

`/v1/moderation/*` exists only when the deployment sets `NEDWONS_MODERATION_TOKEN` (≥ 32 chars;
shorter values are ignored). The review team authenticates with that ops-held token
(`x-moderation-token`, constant-time compare); each action records a `reviewer` handle,
`reviewed_at`, and a `resolution_note`, so the review process itself is auditable. An unconfigured
server answers 404 — the surface does not exist.

Tooling: `scripts/review_reports.sh` (list / show — media saved to a file — / ban / dismiss /
bans / unban). Resolution is first-writer-wins: a report already resolved returns 409 to the
second reviewer.

## What a ban does

- Every authenticated request from the banned account is refused at the auth gate
  (`403 account_banned`) — held tokens keep verifying but buy nothing, immediately.
- New logins are refused with the same code, so the person sees why instead of a broken app.
- Device enrollments are **not** revoked, so an unban restores the account exactly (a wrongly
  banned person must not lose their devices).
- The ban row records who, why, when, and which report — and deliberately has no foreign key to
  `accounts`: a banned user deleting their account must not erase the record that they were banned.

## Honest limits

- **No proactive scanning.** The operator cannot scan E2EE content and does not pretend to.
  Everything starts with a report from someone who could read the message.
- **Re-registration.** With no phone numbers or identity verification, a banned person can make a
  fresh account. The ban removes the abusive account and its standing (friends, groups, history).
  Device-attestation-based gating (App Attest key ids) is future work.
- **Fabricated reports.** Evidence is reporter-submitted and unverifiable by construction;
  reviewer judgment and reporter attribution are the controls. Mass-reporting is rate-limited
  per account (`REPORTS` quota).
- **Group context.** A report identifies the sender by account or by MLS device identity (the
  server resolves the device to its account); it cannot pull surrounding messages the reporter
  did not submit.
