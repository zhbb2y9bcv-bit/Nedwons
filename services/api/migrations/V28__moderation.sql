-- Report → review → ban pipeline (docs/MODERATION.md). The relay cannot read E2EE content, so a
-- report carries ONLY what the reporter explicitly chose to submit: the decrypted text they saw,
-- and (for a reported photo/file) the decrypted bytes, re-uploaded from their device. Nothing is
-- ever server-derived, and nothing else from the conversation is included.
--
-- Review is legality-scoped: the standards in docs/MODERATION.md concern content that is illegal
-- to send (child sexual abuse material, credible threats of violence, sexual exploitation,
-- trafficking, fraud) — not viewpoint moderation. Every review action records who did it, when,
-- and why, so the process itself is auditable.

ALTER TABLE reports
    -- What kind of violation the reporter is alleging. 'other' keeps the old free-text-only
    -- reports valid; the reason field still carries the reporter's words.
    ADD COLUMN category TEXT NOT NULL DEFAULT 'other'
        CHECK (category IN
            ('illegal_content', 'sexual_exploitation', 'threats_violence', 'spam_fraud', 'other')),
    -- Where it happened, when the reporter chose to say (ids are opaque to reviewers but let
    -- repeated reports about one conversation be grouped).
    ADD COLUMN conversation_id BYTEA
        CHECK (conversation_id IS NULL OR octet_length(conversation_id) = 16),
    ADD COLUMN message_id BYTEA
        CHECK (message_id IS NULL OR octet_length(message_id) = 16),
    -- Reporter-submitted media evidence (the decrypted photo/file as THEY decrypted it), capped.
    ADD COLUMN evidence_media BYTEA
        CHECK (evidence_media IS NULL OR octet_length(evidence_media) <= 5242880),
    ADD COLUMN evidence_media_mime TEXT
        CHECK (evidence_media_mime IS NULL OR char_length(evidence_media_mime) <= 100),
    -- Review lifecycle + audit trail.
    ADD COLUMN status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'actioned', 'dismissed')),
    ADD COLUMN reviewed_by TEXT CHECK (reviewed_by IS NULL OR char_length(reviewed_by) <= 100),
    ADD COLUMN reviewed_at TIMESTAMPTZ,
    ADD COLUMN resolution_note TEXT
        CHECK (resolution_note IS NULL OR char_length(resolution_note) <= 2000);

-- The review queue is read oldest-first among open reports.
CREATE INDEX reports_open_queue ON reports (created_at) WHERE status = 'open';

-- Account bans. No FK to accounts: a ban must survive the account deleting itself (a banned user
-- erasing their account must not erase the record that they were banned). Enforcement happens at
-- the authentication gate: every authenticated request from a banned account is refused, and no
-- new session can be issued for it.
--
-- HONEST LIMIT (documented in MODERATION.md): with no phone numbers or identity verification, a
-- banned person can register a fresh account. The ban removes the abusive account and its
-- standing (friends, groups, history); device-attestation-based gating is future work.
CREATE TABLE bans (
    account_id BYTEA PRIMARY KEY CHECK (octet_length(account_id) = 16),
    reason     TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 500),
    banned_by  TEXT NOT NULL CHECK (char_length(banned_by) BETWEEN 1 AND 100),
    -- Provenance: which report led to this ban, when there was one.
    report_id  BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
