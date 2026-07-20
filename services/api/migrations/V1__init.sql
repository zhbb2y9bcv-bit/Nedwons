-- Nedwons auth schema v1. The database is the enforcement point for the atomicity
-- contracts documented on auth-core's store traits (ADR-0006):
--   * single-use challenges  -> DELETE ... RETURNING
--   * refresh rotation       -> SELECT ... FOR UPDATE + generation compare-and-swap
--   * single active device   -> partial unique index
--   * unique usernames       -> unique constraint
-- The server stores only public keys and token HASHES — never private keys, passwords,
-- plaintext tokens, or message content (THREAT_MODEL.md INV-3/INV-8).

CREATE TABLE accounts (
    account_id          BYTEA PRIMARY KEY CHECK (octet_length(account_id) = 16),
    username_normalized TEXT NOT NULL UNIQUE CHECK (char_length(username_normalized) BETWEEN 3 AND 32),
    password_phc        TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    device_id  BYTEA PRIMARY KEY CHECK (octet_length(device_id) = 16),
    account_id BYTEA NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 65),
    revoked    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- v1 is single-active-device (ADR-0002): at most one non-revoked device per account,
-- enforced by the database, not by application discipline.
CREATE UNIQUE INDEX devices_one_active_per_account ON devices (account_id) WHERE NOT revoked;

-- Challenges reference ids reserved before the account exists (registration), so no FK.
CREATE TABLE challenges (
    txn_id     BYTEA PRIMARY KEY CHECK (octet_length(txn_id) = 16),
    account_id BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    device_id  BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    action     SMALLINT NOT NULL CHECK (action BETWEEN 1 AND 6),
    nonce      BYTEA NOT NULL CHECK (octet_length(nonce) = 32),
    expires_at BIGINT NOT NULL
);

CREATE INDEX challenges_expiry ON challenges (expires_at);

CREATE TABLE refresh_families (
    family_id   BYTEA PRIMARY KEY CHECK (octet_length(family_id) = 16),
    account_id  BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    device_id   BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    current_gen BIGINT NOT NULL DEFAULT 0,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at  BIGINT NOT NULL
);

CREATE INDEX refresh_families_device ON refresh_families (device_id);

-- Every generation ever issued stays present (until family cleanup) so REUSE of a retired
-- token is detectable rather than merely unknown.
CREATE TABLE refresh_tokens (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    family_id  BYTEA NOT NULL REFERENCES refresh_families(family_id) ON DELETE CASCADE,
    gen        BIGINT NOT NULL
);

CREATE TABLE access_tokens (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    account_id BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    device_id  BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    expires_at BIGINT NOT NULL
);

CREATE INDEX access_tokens_device ON access_tokens (device_id);
CREATE INDEX access_tokens_expiry ON access_tokens (expires_at);
