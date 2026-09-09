-- Group moderation (ADR-0009 third slice): per-member mutes and announcement-only mode.
--
-- WHAT THIS IS, EXACTLY. A mute is a **relay-enforced send permission**, not a cryptographic one.
-- The relay is MLS-blind: it cannot read a message, and a muted member still holds the group's MLS
-- keys, so it can still *encrypt* for the group and could still deliver those bytes over any
-- channel it has outside this server. What a mute removes is the server's willingness to fan that
-- ciphertext out to the group — which is the only distribution path this product provides.
-- Moderation of a group you administer is therefore an availability control, and it is honest to
-- describe it that way; PRIVACY.md already records roles and membership as server-visible
-- metadata, and mute state joins that list.
--
-- WHY ACCOUNT-SCOPED. Roles are account-level (`group_admins`), and a person with two linked
-- devices is one participant. A device-scoped mute would silence a phone and leave the tablet
-- talking.
--
-- `expires_at NULL` = indefinite ("until an admin unmutes"); a timestamp = a timed mute. Expiry is
-- evaluated at send time against `now()`, so nothing has to sweep the table for a mute to lapse,
-- and a lapsed row is harmless if it lingers.

CREATE TABLE group_mutes (
    conversation_id BYTEA NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
    account_id      BYTEA NOT NULL CHECK (octet_length(account_id) = 16)
                          REFERENCES accounts(account_id) ON DELETE CASCADE,
    -- Who applied it, for the audit line the members list shows. An admin who later leaves keeps
    -- their id here (no FK action beyond the account cascade) — the mute outlives the muter.
    muted_by        BYTEA NOT NULL CHECK (octet_length(muted_by) = 16),
    muted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ,
    PRIMARY KEY (conversation_id, account_id)
);

-- The send gate reads (conversation_id, account_id) on every message, which the primary key
-- already indexes. The reverse lookup — "every group where this account is muted" — has no caller
-- and deliberately gets no index.

-- Announcement-only mode ("mute everyone"): only admins may send. Conversation-level because it is
-- a property of the group, not of any member, so turning it off restores everyone at once without
-- touching per-member state.
ALTER TABLE conversations ADD COLUMN announcements_only BOOLEAN NOT NULL DEFAULT FALSE;

-- ---------------------------------------------------------------------------------------------
-- Cross-table invariants, in the style V22 established: the schema refuses states the application
-- would otherwise have to remember to avoid.
-- ---------------------------------------------------------------------------------------------

-- 1. A mute requires membership. Muting a non-member would leave a row that silently applies if
--    they are ever added back, which is a decision an admin never made.
CREATE OR REPLACE FUNCTION group_mutes_require_membership() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM conversation_members m
                    WHERE m.conversation_id = NEW.conversation_id
                      AND m.account_id = NEW.account_id) THEN
        RAISE EXCEPTION 'group_mutes: % is not a member of conversation %',
            encode(NEW.account_id, 'hex'), encode(NEW.conversation_id, 'hex');
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER group_mutes_require_membership_trg
    BEFORE INSERT OR UPDATE ON group_mutes
    FOR EACH ROW EXECUTE FUNCTION group_mutes_require_membership();

-- 2. Leaving (or being removed) clears the mute, exactly as it clears adminship. Otherwise a
--    rejoin — by invite, which is the joiner's own consent — would silently land them muted from
--    a decision made about a previous membership.
CREATE OR REPLACE FUNCTION drop_mute_when_membership_ends() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM conversation_members m
                    WHERE m.conversation_id = OLD.conversation_id
                      AND m.account_id = OLD.account_id) THEN
        DELETE FROM group_mutes
         WHERE conversation_id = OLD.conversation_id AND account_id = OLD.account_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER drop_mute_when_membership_ends_trg
    AFTER DELETE ON conversation_members
    FOR EACH ROW EXECUTE FUNCTION drop_mute_when_membership_ends();

-- 3. An admin is never muted, enforced from both sides, so the two role tables can never assert
--    contradictory things about one person. Muting an admin is refused (the API answers 409
--    `target_is_admin`: demote first, deliberately, rather than silently stripping a role), and
--    promoting a muted member lifts the mute as part of the promotion.
CREATE OR REPLACE FUNCTION group_mutes_reject_admins() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM group_admins a
                WHERE a.conversation_id = NEW.conversation_id
                  AND a.account_id = NEW.account_id) THEN
        RAISE EXCEPTION 'group_mutes: % is an admin of conversation %',
            encode(NEW.account_id, 'hex'), encode(NEW.conversation_id, 'hex');
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER group_mutes_reject_admins_trg
    BEFORE INSERT OR UPDATE ON group_mutes
    FOR EACH ROW EXECUTE FUNCTION group_mutes_reject_admins();

CREATE OR REPLACE FUNCTION clear_mute_on_promotion() RETURNS trigger AS $$
BEGIN
    DELETE FROM group_mutes
     WHERE conversation_id = NEW.conversation_id AND account_id = NEW.account_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER clear_mute_on_promotion_trg
    BEFORE INSERT ON group_admins
    FOR EACH ROW EXECUTE FUNCTION clear_mute_on_promotion();
