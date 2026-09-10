-- Close R-506 for real app flows: separate membership INTENT from routing MEMBERSHIP (ADR-0010).
--
-- The V27 setup queue is routing-first — an invite-accept / join-approval / direct add inserts a
-- `conversation_members` row with `mls_added = FALSE`, and the MLS commit follows later, unsigned
-- and unverified. That is exactly the divergence ADR-0010 exists to remove: routing changed with no
-- cryptographic evidence at all.
--
-- ADR-0010 is commit-first: `conversation_members` may be written ONLY by a verified, device-signed,
-- epoch-CAS'd commit. But the deferred-add property V27 gave us is worth keeping (someone accepts an
-- invite while every existing member is offline; nobody is around to run the MLS add yet). So the
-- intent has to live SOMEWHERE that is not routing — which is this table.
--
--   authorization happens  →  membership_intents row   (the relay owes this device a join)
--   a member runs the add  →  POST /commit             (signed manifest, epoch CAS)
--   the commit is accepted →  conversation_members row (routing, and the intent is consumed)
--
-- An intent grants NOTHING on its own: no mail is routed by it, no fan-out changes, no epoch moves.
--
-- It is also the **authorization ledger**, which is what makes the reconcile model work. The V27
-- loop lets ANY set-up member perform an add, because the authorization happened earlier at a
-- consent-checked endpoint (an admin who is friends with the target, a redeemed invite token, an
-- approved join request). Re-checking "is the committing device an admin" at commit time would both
-- duplicate that decision and break the loop — an invite joiner would wait for an admin to be
-- online. So in an authoritative conversation `apply_commit` requires an INTENT for every device it
-- adds or removes, and does not re-check the actor's role: the intent carries the decision, the
-- committer is the courier, and the signature proves which courier it was.
--
--   kind = 1 (join)   minted by: direct add, invite accept, join approval, group creation, sibling
--                     linking. Consumed by an ADD commit, which creates the routing row.
--   kind = 2 (remove) minted by: admin removal, and a member leaving. Consumed by a REMOVE commit,
--                     which deletes the routing row.
--
-- Why leaving mints an intent rather than deleting routing directly: MLS will not let a member
-- commit its own removal (verified against OpenMLS — "The Commit tried to remove self from the
-- group"), so a leaver cannot produce the evidence for their own departure. Someone else has to.
-- Recording the intent keeps the invariant exact — routing in an authoritative conversation is
-- written ONLY by an accepted commit — at the cost that a departure lands when a remaining member
-- next syncs. Their queued mail is purged immediately either way, so the delivery cutoff a user
-- expects from "leave" does not wait for anyone.
--
-- Non-authoritative (legacy) conversations are untouched and keep using the `mls_added` queue; both
-- coexist during migration, which is why `setup_needed` reports which protocol each target wants.
CREATE TABLE membership_intents (
    conversation_id BYTEA NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
    account_id      BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    device_id       BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    -- 1 = join, 2 = remove. Mirrors `auth_core::membership::ControlType`'s add/remove values.
    kind            SMALLINT NOT NULL CHECK (kind IN (1, 2)),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Same claim discipline as V27's setup claims: exactly one member's device runs each change, and
    -- a claim EXPIRES rather than wedging the target forever when its claimer crashes or finds no
    -- prekey published yet.
    claimed_by      BYTEA,
    claimed_at      TIMESTAMPTZ,
    -- One pending decision per device per conversation: a device is either being brought in or put
    -- out, never both, and a repeated authorization is the same single work item.
    PRIMARY KEY (conversation_id, device_id)
);

-- The queue is scanned per conversation on every sync (join the caller's memberships), and consumed
-- per device by `apply_commit`.
CREATE INDEX membership_intents_by_device ON membership_intents (device_id);

-- Which envelope IS a membership commit, and for which epoch transition. NULL for ordinary mail.
--
-- METADATA HONESTY (PRIVACY.md): this reveals nothing new to the relay. `apply_commit` is the only
-- writer, and it is the code that CREATED these rows one statement earlier — the server already
-- knows precisely which envelope carries which commit, because it fanned it out itself. The column
-- exists so a RECIPIENT can tell a membership commit from ordinary ciphertext without trial
-- decryption, and therefore knows it must run the ADR-0010 correspondence check (fetch the signed
-- manifest for this epoch, verify the signature against the transparency-logged device key, and
-- require the staged commit's actual adds/removes to equal what the manifest claimed) BEFORE
-- merging. Without the tag a recipient cannot distinguish the two and merges commits unverified,
-- which is the recipient half of the R-506 gap.
ALTER TABLE envelopes ADD COLUMN membership_epoch BIGINT;
