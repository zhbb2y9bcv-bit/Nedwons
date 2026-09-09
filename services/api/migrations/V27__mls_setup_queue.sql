-- Real multi-device conversations + automatic/deferred MLS adds, via ONE mechanism: a routing
-- member either holds the conversation's MLS keys (`mls_added`) or is waiting for a current
-- member's device to run the add (claim a prekey, deliver a Welcome, fan out the commit).
--
-- Every path that previously left someone "in routing but not in the encryption" now lands in
-- this queue instead of in a dead end: invite-link joins, approved join requests, direct adds
-- (all of the target's devices, not just the primary), adds of a friend who has no prekeys yet
-- (deferred until they open the app and publish some), and a freshly linked sibling device
-- (inserted into all of its account's conversations when it joins the self-group).
--
-- The flag is a WORK QUEUE, not a delivery gate: fan-out still queues ciphertext for un-setup
-- devices, because messages from before a device's join epoch are cryptographically undecryptable
-- by it anyway (MLS forward secrecy) — filtering would change nothing a user can read, but would
-- complicate the proven send path.
--
-- METADATA HONESTY (PRIVACY.md): the relay already knows routing membership per device; this adds
-- only "has device X completed encryption setup for conversation Y", which is derivable from the
-- relay's own Welcome-delivery timing anyway.
ALTER TABLE conversation_members
    ADD COLUMN mls_added BOOLEAN NOT NULL DEFAULT TRUE;

-- Reconcile claims serialize the workers: exactly one member's device performs each add. A claim
-- expires (the claimer crashed, or found no prekey) rather than wedging the target forever.
ALTER TABLE conversation_members
    ADD COLUMN setup_claimed_by BYTEA,
    ADD COLUMN setup_claimed_at TIMESTAMPTZ;

-- The queue is scanned per conversation on every sync; keep that cheap.
CREATE INDEX conversation_members_needs_setup
    ON conversation_members (conversation_id) WHERE NOT mls_added;
