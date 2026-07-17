# ADR-0009: Invitation/role group membership tied to MLS commits (replaces the friend-clique rule)

- **Status:** Accepted. **First slice implemented 2026-07-17** (see below); remainder designed.
- **Date:** 2026-07-17
- **Deciders:** security architect, backend lead, crypto integrator, product
- **Supersedes:** the complete-mutual-friend-clique gate in `services/api/src/social.rs`
  (`all_mutually_friends`, `edges == C(n,2)`) and the `403 not_all_friends` response.
- **Related:** ADR-0001 (MLS), ADR-0007 (MLS binding), ADR-0008 (multi-device), R-201 (transparency),
  R-G0-5 (server↔MLS membership divergence), ABUSE_MODEL.md.
- **Sources accessed 2026-07-17:** RFC 9420 (Add/Remove/Update/Commit, epochs, Welcome); OpenMLS Book
  — discarding commits & fork resolution; Signal message-requests model (for unknown-sender UX).

## Context

Two Gate 0 findings converge here:

1. **The clique rule is impractical.** Groups today require *every* pair of members to be friends.
   Normal family/school/work/event groups cannot form. (Confirmed load-bearing in Gate 0.)
2. **Server routing membership and cryptographic membership are disconnected (R-G0-5).** The relay's
   `conversation_members` table is an independent source of truth; there is no server-side MLS group
   at all yet. A server (or a bug) could add/remove a routing member with no corresponding
   cryptographic change — the precise divergence hazard the mission forbids.

## Decision

**A. Membership model.** Replace the clique gate with an invitation/role model where members do
**not** need to be mutual friends:

- The creator is an **admin**. Admins can: invite directly (by account/QR), generate
  **revocable, expiring invite links / QR codes**, and optionally require **join-request approval**.
- **Roles & permissions** (admin / member, extensible), with a visible member list before joining.
- **Blocked-user enforcement:** a blocked user cannot be invited by, or join a group created by, the
  blocker; if a block exists between two members already in a group, define exactly what each can see
  and do — **do not promise total invisibility** (honest limitation, ABUSE_MODEL.md).
- **No silent re-add:** re-adding someone who left or was removed requires a fresh invite and emits a
  system message; blocks are re-checked.
- **System messages** record every membership, role, and security-relevant change.

**B. Cryptographic authority.** **MLS group membership is authoritative; the server's routing table
is a mirror derived from committed MLS changes, never an independent writer.** Every server-side
membership transition must be accompanied by, and validated against, an **authenticated MLS commit**
(Add/Remove/Update). The server **rejects** any membership change lacking a valid commit for the
current epoch. Concretely:

- The delivery service **serializes commits** per group (one epoch advance at a time), rejects
  **stale-epoch** commits, and handles rejected/discarded commits and forks per the OpenMLS
  discard-commit and fork-resolution guidance (documented re-add / group-reboot strategy).
- Welcome, Commit, Proposal, and application messages get **distinct handling and authorization**.
- **Removed members cannot decrypt future epochs; new members do not receive history** unless it is
  explicitly shared via a separate, documented E2EE history-transfer mechanism (out of scope here).
- Identity credentials in commits are **verified against the account/device directory** (ADR-0008 /
  R-201), not trusted because they parse.

## Alternatives considered

- **Keep the clique rule.** Rejected: impractical for real groups; also does nothing for R-G0-5.
- **Relax to "creator is friends with each member".** Rejected: still a social-graph gate that breaks
  event/community groups and conflates friendship with communication.
- **Server-authoritative membership without MLS commits (routing table is truth).** Rejected: this is
  exactly R-G0-5 — a server could add/remove members invisibly to the cryptographic group. Making MLS
  authoritative is the whole point.
- **Fully open groups (anyone with the link auto-joins, no approval option).** Rejected as a default:
  invite-link leakage → raids. Links are expiring/revocable and approval is available.

## Migration & backward compatibility

- **Remove** `all_mutually_friends` gating and the `403 not_all_friends` path from group creation.
- **Add** tables: `group_roles` (conversation, account, role), `group_invites` (token, created_by,
  expires_at, revoked, max_uses/uses), `group_join_requests` (pending/approved/denied), and reuse the
  existing block relation. Extend the routing membership with an **epoch** column and a link to the
  authorizing MLS commit so the mirror is auditable.
- **Existing clique-created groups remain valid** — they are ordinary groups after the change; no data
  loss, no re-invite required.
- **Protocol:** membership/control messages carry an explicit version (R-G0-5). Old clients must
  reject unknown membership-control versions rather than mis-handle them.

## Threats & mitigations

| Threat | Mitigation |
|--------|------------|
| Invite-link leak / raid | Expiring + revocable links, optional join approval, per-account/IP rate limits, admin removal. |
| Silent re-add of a removed/blocked user | Fresh invite required + system message + block re-check + transparency of the MLS Add. |
| Server adds/removes a member invisibly | Rejected: no routing change without a valid MLS commit; membership mirror is derived, epoch-linked, auditable. |
| Admin abuse | Role-scoped permissions; every admin action emits a system message; least-privilege server-side. |
| Stale/conflicting commits, forks | Per-group serialization, stale-epoch rejection, documented discard/fork-resolution. |
| Blocked users co-present in a group | Explicitly defined, honestly surfaced capability limits — no false invisibility promise. |

## Tests planned (before this ships as code)

- A group of **non-friends** (mixed contacts) can be created and everyone can message.
- A routing membership change **without a valid MLS commit is rejected** (R-G0-5 regression guard).
- Removed member cannot decrypt the next epoch; new member cannot read prior history.
- Blocked-user enforcement on invite/join.
- Invite-link expiry, revocation, and max-uses; join-request approve/deny.
- Concurrent commits: one epoch advances, the other is rejected/retried; fork is resolved.

## Implementation status (2026-07-17)

**Done — first slice (the clique→block swap):** the full-friend-clique gate on `POST /v1/groups` is
removed. Members no longer need to be friends; the only membership gate is `any_block_within` — a
group is refused (`403 blocked_member`) if any pair within it has blocked each other. Verified in
`services/api/tests/social.rs` (non-friend group allowed; blocked pair rejected) and end to end in
the live smoke (non-friend group succeeds; a group containing a blocked member is refused). Swift
client + UI copy updated. Blocking already severs friendships and refuses friend requests (V5).

**Done — second slice (2026-07-17, governance):** migration V7 + `groups::PgGroups` +
`tests/groups.rs`. The creator is the group's first **admin**. Admins mint/list/revoke
**invite links** (32-byte bearer tokens; expiring, use-bounded, revocable), manage **join
requests** (approve re-checks blocks; deny), **remove members** (same exit path as leave),
**promote/demote** (last-admin demotion refused), and set **join approval**. `POST
/v1/invites/accept` is the joiner's own consent; blocks bar entry at every path. **Leave-group**
cleans up roles and auto-promotes the earliest member when the last admin departs. **Direct adds
tightened:** `create_group`/`add_member` now require the adder to be an admin (for adds) and
friends with each target — closing the forced-membership spam hole that pure open groups left;
strangers join only via invite tokens. Verified end to end in the live smoke (direct non-friend
add refused; stranger joins via invite; leaves).

**Not yet done (designed above):** QR rendering of invites (client UI), group system messages,
per-invite member-list preview, and — the big one — binding routing membership to
**authenticated MLS Add/Remove commits**. That binding is inherently client-driven because the
relay is deliberately MLS-blind (it must never link the MLS library); it depends on the on-device
MLS core (ADR-0007) and key transparency (R-201). Until it lands, server routing membership and
MLS membership remain distinct (R-506), and this must not be described as fully realized.

## Consequences

Makes real-world groups possible and closes the server↔MLS divergence hazard by construction. Hard
dependencies: the MLS-Swift binding (ADR-0007) and a server-side MLS-membership representation
(R-G0-5); it also assumes the multi-device model (ADR-0008) for per-device leaves. Larger scope than
ADR-0008 — **design only**; implementation is sequenced after the client MLS core exists. Until then,
the current clique-gated groups remain in place and must not be described as the final model.
