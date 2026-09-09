-- Data-integrity hardening: referential integrity, unique push-token ownership, and database-level
-- guards for two cross-table invariants that no single-table constraint can express.
--
-- MOTIVATION. Before this migration only TWO tables cascaded from `accounts` (`devices` and
-- `profiles`). Every other table holding account or device data carried no foreign key at all, so
-- the database happily stored tokens, social edges, group roles, key packages and queued mail
-- referring to accounts that no longer existed. Account deletion had to enumerate those tables by
-- hand, and any path that missed one left silent orphans. Measured on a working database before
-- this ran: 880 orphaned conversation_members, 723 orphaned blocks, 421 orphaned group_admins,
-- 287 orphaned challenges, 37 orphaned refresh_families.
--
-- DELIBERATE EXCLUSIONS — each of these is intentionally left WITHOUT a foreign key:
--
--   * `challenges.account_id` — registration reserves ids BEFORE the account row exists (see
--     V1__init.sql). A foreign key here would make registration impossible. Orphans are bounded
--     instead by the expiry purge.
--   * `envelopes.sender_device` — a cascade here would delete messages the sender already sent to
--     other people the moment their account was deleted, silently rewriting other users' history.
--     Deleting an account is not an unsend (see src/account_deletion.rs). Only `recipient_device`
--     cascades, because mail addressed to a device that no longer exists can never be decrypted.
--   * `reports.reporter` / `reports.reported` — retained deliberately and anonymized to sentinels
--     on deletion, so abuse history cannot be laundered by deleting and re-registering. A cascade
--     would destroy exactly the record that must survive.
--   * `transparency_log.*` — append-only. Deleting leaves would invalidate other users' inclusion
--     proofs and turn an auditable log into an unauditable one.
--   * `membership_events.actor_account` / `actor_device` — MLS protocol history other members'
--     clients still validate against. It already cascades with its conversation.

-- ---------------------------------------------------------------------------------------------
-- 1. Remove pre-existing orphans. A production database will have them for the same reason this
--    one does: nothing ever stopped them being written.
-- ---------------------------------------------------------------------------------------------
DELETE FROM refresh_families f WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = f.account_id);
DELETE FROM access_tokens t WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = t.account_id);
DELETE FROM key_packages k WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = k.account_id)
   OR NOT EXISTS (SELECT 1 FROM devices d WHERE d.device_id = k.device_id);
DELETE FROM delivery_access_keys x WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = x.account_id);
DELETE FROM self_group_members s WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = s.account_id)
   OR NOT EXISTS (SELECT 1 FROM devices d WHERE d.device_id = s.device_id);
DELETE FROM conversation_members m WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = m.account_id)
   OR NOT EXISTS (SELECT 1 FROM devices d WHERE d.device_id = m.device_id);
DELETE FROM group_admins g WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = g.account_id);
DELETE FROM group_join_requests r WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = r.account_id);
DELETE FROM group_invites i WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = i.created_by);
DELETE FROM friendships f WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = f.account_lo)
   OR NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = f.account_hi);
DELETE FROM friend_requests r WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = r.from_account)
   OR NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = r.to_account);
DELETE FROM blocks b WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = b.blocker)
   OR NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = b.blocked);
DELETE FROM device_push_tokens p WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.device_id = p.device_id);
DELETE FROM app_attest_keys k WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.device_id = k.device_id);
DELETE FROM app_attest_challenges c WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.device_id = c.device_id);
DELETE FROM envelopes e WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.device_id = e.recipient_device);
DELETE FROM sealed_envelopes e WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.device_id = e.recipient_device);
DELETE FROM self_group_envelopes e WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.device_id = e.recipient_device);

-- Conversations whose members were all orphans are unreachable: `list_conversations` joins through
-- conversation_members, so nothing can ever surface or purge them.
DELETE FROM envelopes e WHERE NOT EXISTS (SELECT 1 FROM conversation_members m WHERE m.conversation_id = e.conversation_id);
DELETE FROM conversations c WHERE NOT EXISTS (SELECT 1 FROM conversation_members m WHERE m.conversation_id = c.conversation_id);

-- Orphaned admin rows left behind by the membership cleanup above.
DELETE FROM group_admins g
 WHERE NOT EXISTS (SELECT 1 FROM conversation_members m
                    WHERE m.conversation_id = g.conversation_id AND m.account_id = g.account_id);

-- ---------------------------------------------------------------------------------------------
-- 2. Referential integrity. Deletion can now lean on the schema instead of an exhaustive list.
-- ---------------------------------------------------------------------------------------------
ALTER TABLE access_tokens       ADD CONSTRAINT access_tokens_account_fk       FOREIGN KEY (account_id)   REFERENCES accounts(account_id) ON DELETE CASCADE;
ALTER TABLE refresh_families    ADD CONSTRAINT refresh_families_account_fk    FOREIGN KEY (account_id)   REFERENCES accounts(account_id) ON DELETE CASCADE;
ALTER TABLE delivery_access_keys ADD CONSTRAINT delivery_access_keys_account_fk FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE;
ALTER TABLE key_packages        ADD CONSTRAINT key_packages_account_fk        FOREIGN KEY (account_id)   REFERENCES accounts(account_id) ON DELETE CASCADE;
ALTER TABLE key_packages        ADD CONSTRAINT key_packages_device_fk         FOREIGN KEY (device_id)    REFERENCES devices(device_id)   ON DELETE CASCADE;
ALTER TABLE self_group_members  ADD CONSTRAINT self_group_members_account_fk  FOREIGN KEY (account_id)   REFERENCES accounts(account_id) ON DELETE CASCADE;
ALTER TABLE self_group_members  ADD CONSTRAINT self_group_members_device_fk   FOREIGN KEY (device_id)    REFERENCES devices(device_id)   ON DELETE CASCADE;
ALTER TABLE conversation_members ADD CONSTRAINT conversation_members_account_fk FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE;
ALTER TABLE conversation_members ADD CONSTRAINT conversation_members_device_fk  FOREIGN KEY (device_id)  REFERENCES devices(device_id)   ON DELETE CASCADE;
ALTER TABLE group_admins        ADD CONSTRAINT group_admins_account_fk        FOREIGN KEY (account_id)   REFERENCES accounts(account_id) ON DELETE CASCADE;
ALTER TABLE group_join_requests ADD CONSTRAINT group_join_requests_account_fk  FOREIGN KEY (account_id)   REFERENCES accounts(account_id) ON DELETE CASCADE;
ALTER TABLE group_invites       ADD CONSTRAINT group_invites_creator_fk       FOREIGN KEY (created_by)   REFERENCES accounts(account_id) ON DELETE CASCADE;
ALTER TABLE friendships         ADD CONSTRAINT friendships_lo_fk              FOREIGN KEY (account_lo)   REFERENCES accounts(account_id) ON DELETE CASCADE;
ALTER TABLE friendships         ADD CONSTRAINT friendships_hi_fk              FOREIGN KEY (account_hi)   REFERENCES accounts(account_id) ON DELETE CASCADE;
ALTER TABLE friend_requests     ADD CONSTRAINT friend_requests_from_fk        FOREIGN KEY (from_account) REFERENCES accounts(account_id) ON DELETE CASCADE;
ALTER TABLE friend_requests     ADD CONSTRAINT friend_requests_to_fk          FOREIGN KEY (to_account)   REFERENCES accounts(account_id) ON DELETE CASCADE;
ALTER TABLE blocks              ADD CONSTRAINT blocks_blocker_fk              FOREIGN KEY (blocker)      REFERENCES accounts(account_id) ON DELETE CASCADE;
ALTER TABLE blocks              ADD CONSTRAINT blocks_blocked_fk              FOREIGN KEY (blocked)      REFERENCES accounts(account_id) ON DELETE CASCADE;
ALTER TABLE device_push_tokens  ADD CONSTRAINT device_push_tokens_device_fk   FOREIGN KEY (device_id)    REFERENCES devices(device_id)   ON DELETE CASCADE;
ALTER TABLE app_attest_keys     ADD CONSTRAINT app_attest_keys_device_fk      FOREIGN KEY (device_id)    REFERENCES devices(device_id)   ON DELETE CASCADE;
ALTER TABLE app_attest_challenges ADD CONSTRAINT app_attest_challenges_device_fk FOREIGN KEY (device_id) REFERENCES devices(device_id)   ON DELETE CASCADE;
ALTER TABLE envelopes           ADD CONSTRAINT envelopes_recipient_fk         FOREIGN KEY (recipient_device) REFERENCES devices(device_id) ON DELETE CASCADE;
ALTER TABLE sealed_envelopes    ADD CONSTRAINT sealed_envelopes_recipient_fk  FOREIGN KEY (recipient_device) REFERENCES devices(device_id) ON DELETE CASCADE;
ALTER TABLE self_group_envelopes ADD CONSTRAINT self_group_envelopes_recipient_fk FOREIGN KEY (recipient_device) REFERENCES devices(device_id) ON DELETE CASCADE;

-- ---------------------------------------------------------------------------------------------
-- 3. One push token belongs to exactly ONE device.
--
-- The upsert was keyed on (device_id, platform), so two devices could hold the same APNs token —
-- which really happens, because APNs reassigns a token to a reinstalled app. The stale owner then
-- receives wake pushes meant for the new one, leaking "this other account has mail" to whoever
-- now holds the token. Keep the newest claim and enforce single ownership from here on.
-- ---------------------------------------------------------------------------------------------
DELETE FROM device_push_tokens p
 WHERE EXISTS (SELECT 1 FROM device_push_tokens q
                WHERE q.platform = p.platform AND q.token = p.token
                  AND (q.updated_at, q.device_id) > (p.updated_at, p.device_id));
CREATE UNIQUE INDEX device_push_tokens_one_owner ON device_push_tokens (platform, token);

-- ---------------------------------------------------------------------------------------------
-- 4. Cross-table invariants.
--
-- These cannot be CHECK constraints (a CHECK sees one row) and cannot be foreign keys either: an
-- admin references (conversation_id, account_id), but conversation_members is keyed per DEVICE, so
-- one account legitimately has several rows per conversation and there is no unique target to
-- reference. Triggers are the only mechanism left, so they are kept small and total.
-- ---------------------------------------------------------------------------------------------

-- 4a. An admin must be a member. Enforced on the way in...
CREATE OR REPLACE FUNCTION group_admins_require_membership() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM conversation_members m
                    WHERE m.conversation_id = NEW.conversation_id
                      AND m.account_id = NEW.account_id) THEN
        RAISE EXCEPTION 'group_admins: % is not a member of conversation %',
            encode(NEW.account_id, 'hex'), encode(NEW.conversation_id, 'hex');
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER group_admins_require_membership_trg
    BEFORE INSERT OR UPDATE ON group_admins
    FOR EACH ROW EXECUTE FUNCTION group_admins_require_membership();

-- ...and on the way out: when an account's LAST device leaves a conversation, its admin row goes
-- with it. `leave_conversation` already did this by hand, but removal by device (the MLS commit
-- path) did not, which is how an admin could outlive its own membership.
CREATE OR REPLACE FUNCTION drop_admin_when_membership_ends() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM conversation_members m
                    WHERE m.conversation_id = OLD.conversation_id
                      AND m.account_id = OLD.account_id) THEN
        DELETE FROM group_admins
         WHERE conversation_id = OLD.conversation_id AND account_id = OLD.account_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER drop_admin_when_membership_ends_trg
    AFTER DELETE ON conversation_members
    FOR EACH ROW EXECUTE FUNCTION drop_admin_when_membership_ends();

-- 4b. A blocked pair must never become friends. The application already serializes this on a
-- per-pair advisory lock, but a friendship is a live authorization credential (`are_friends` gates
-- adding someone to a group), so it is worth a second, unconditional line of defence that no
-- future code path can forget.
CREATE OR REPLACE FUNCTION friendships_reject_when_blocked() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM blocks b
                WHERE (b.blocker = NEW.account_lo AND b.blocked = NEW.account_hi)
                   OR (b.blocker = NEW.account_hi AND b.blocked = NEW.account_lo)) THEN
        RAISE EXCEPTION 'friendships: pair is blocked';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER friendships_reject_when_blocked_trg
    BEFORE INSERT OR UPDATE ON friendships
    FOR EACH ROW EXECUTE FUNCTION friendships_reject_when_blocked();
