-- Migrate legacy membership paths onto MLS-authoritative commits (ADR-0010, R-506).
--
-- When a conversation is `mls_authoritative`, its routing membership may change ONLY through a
-- valid MLS commit (POST /commit): the legacy direct-mutation endpoints (add_member,
-- remove_member, leave, invite-accept, join-approve) refuse with 409 `commits_required`. This is
-- the enforcement flag for the migration; it defaults FALSE so existing conversations and the
-- non-MLS test flows are unaffected, and new MLS conversations opt in at creation.
ALTER TABLE conversations ADD COLUMN mls_authoritative BOOLEAN NOT NULL DEFAULT FALSE;
