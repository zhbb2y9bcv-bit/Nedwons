-- Key-transparency append-only log (R-201). Each row is one RFC 6962 leaf: a binding of an
-- account to a device public key. `leaf_index` is 0-based, gapless, and assigned under an advisory
-- transaction lock so the Merkle leaf ordering is well-defined. `entry` is the canonical leaf INPUT
-- (pre-hash) so the server can recompute proofs and clients can reconstruct their own leaf hash.
-- This is routing/identity metadata (already server-visible), never message content.
CREATE TABLE transparency_log (
    leaf_index BIGINT PRIMARY KEY CHECK (leaf_index >= 0),
    account_id BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    device_id  BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    public_key BYTEA NOT NULL,
    entry      BYTEA NOT NULL,
    logged_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Self-monitoring: a client fetches every binding logged under its own account.
CREATE INDEX transparency_log_by_account ON transparency_log (account_id, leaf_index);
