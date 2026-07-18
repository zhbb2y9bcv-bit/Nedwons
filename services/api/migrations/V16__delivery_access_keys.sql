-- Sealed-sender delivery access keys (ADR-0014 Slice 2a, R-204). A recipient account registers the
-- VERIFIER of its delivery access key -- V_r = SHA-256(K_r) -- so a future sealed-delivery endpoint
-- can check a presented K_r without the recipient ever revealing K_r to the relay at rest. Only the
-- 32-byte hash is stored (never K_r); one row per account, replaced on rotation. No delivery path
-- exists yet (that is Slice 2b, gated on ADR-0014 review) -- this table just holds the gate value.
CREATE TABLE delivery_access_keys (
    account_id BYTEA PRIMARY KEY CHECK (octet_length(account_id) = 16),
    verifier   BYTEA NOT NULL CHECK (octet_length(verifier) = 32),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
