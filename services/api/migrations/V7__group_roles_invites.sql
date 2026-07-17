-- Group roles, invite links, and join requests (ADR-0009). All social/routing metadata —
-- never message content.

-- Whether joining this conversation via an invite needs admin approval.
ALTER TABLE conversations ADD COLUMN join_approval BOOLEAN NOT NULL DEFAULT FALSE;

-- Admins (presence = admin; absence = ordinary member). Account-level: roles follow the person,
-- not one device. Kept separate from conversation_members (device-level routing) so the two
-- cannot diverge on shape.
CREATE TABLE group_admins (
    conversation_id BYTEA NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
    account_id      BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, account_id)
);

-- Invite links: high-entropy bearer tokens (32 random bytes) with expiry, bounded uses, and
-- revocation. A token is consent-by-the-joiner: whoever presents it joins themselves.
CREATE TABLE group_invites (
    token           BYTEA PRIMARY KEY CHECK (octet_length(token) = 32),
    conversation_id BYTEA NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
    created_by      BYTEA NOT NULL CHECK (octet_length(created_by) = 16),
    expires_at      TIMESTAMPTZ NOT NULL,
    max_uses        INTEGER NOT NULL CHECK (max_uses > 0),
    uses            INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX group_invites_by_conversation ON group_invites (conversation_id);

-- Pending join requests (for conversations with join_approval). One per (conversation, account).
CREATE TABLE group_join_requests (
    conversation_id BYTEA NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
    account_id      BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, account_id)
);
