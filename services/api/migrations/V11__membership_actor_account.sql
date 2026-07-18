-- Recipient signature verification (ADR-0010, R-506 + R-201 composition).
--
-- A recipient verifies a membership manifest's device signature against the actor's key AS LOGGED
-- IN THE TRANSPARENCY LOG (not a server-asserted key). To find that logged key it must know the
-- actor's account. The manifest carries only the actor *device*; the account is derived at apply
-- time (while the actor is still a routed member — a self-leave removes them) and stored here so
-- the membership-event endpoint can return it even after the actor leaves.
ALTER TABLE membership_events
    ADD COLUMN actor_account BYTEA NOT NULL DEFAULT '\x00000000000000000000000000000000'
    CHECK (octet_length(actor_account) = 16);

-- Drop the placeholder default now that the column exists; new rows must supply the real account.
ALTER TABLE membership_events ALTER COLUMN actor_account DROP DEFAULT;
