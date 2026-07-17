-- Profiles, the friendship graph, and friend requests. These are routing/social metadata
-- (never message content). Profile discovery is username-prefix search — deliberate,
-- rate-limited, min-length — never a bulk directory dump (ABUSE_MODEL.md, PRIVACY.md).

CREATE TABLE profiles (
    account_id   BYTEA PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
    display_name TEXT NOT NULL DEFAULT '' CHECK (char_length(display_name) <= 64),
    bio          TEXT NOT NULL DEFAULT '' CHECK (char_length(bio) <= 256),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Accepted friendships, stored once per pair in canonical (lo < hi) order so membership is
-- symmetric and a single lookup answers "are A and B friends?".
CREATE TABLE friendships (
    account_lo BYTEA NOT NULL CHECK (octet_length(account_lo) = 16),
    account_hi BYTEA NOT NULL CHECK (octet_length(account_hi) = 16),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_lo, account_hi),
    CHECK (account_lo < account_hi)
);
-- Reverse lookup so listing a person's friends is indexed from either side.
CREATE INDEX friendships_hi ON friendships (account_hi);

-- Pending friend requests (directional). Accepting turns a request into a friendship;
-- a reverse request that meets a pending one auto-accepts ("both added each other").
CREATE TABLE friend_requests (
    from_account BYTEA NOT NULL CHECK (octet_length(from_account) = 16),
    to_account   BYTEA NOT NULL CHECK (octet_length(to_account) = 16),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (from_account, to_account),
    CHECK (from_account <> to_account)
);
CREATE INDEX friend_requests_to ON friend_requests (to_account);
