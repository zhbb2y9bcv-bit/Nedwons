-- User blocking (abuse control, ABUSE_MODEL.md). Directional: `blocker` has blocked `blocked`.
-- A block between two accounts (in EITHER direction) prevents new friend requests and, on block,
-- removes any existing friendship and pending requests — enforced atomically in social.rs.
CREATE TABLE blocks (
    blocker    BYTEA NOT NULL CHECK (octet_length(blocker) = 16),
    blocked    BYTEA NOT NULL CHECK (octet_length(blocked) = 16),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (blocker, blocked),
    CHECK (blocker <> blocked)
);

-- Reverse lookup ("who has blocked me?") and either-direction block checks.
CREATE INDEX blocks_blocked ON blocks (blocked);
