-- Sealed-sender delivery (ADR-0014 Slice 2b, R-204). A SEPARATE table from `envelopes` so the
-- proven identified-delivery constraints (sender_device NOT NULL, the (sender,recipient,idem)
-- idempotency index) are untouched. A sealed envelope stores NO sender_device and NO
-- conversation_id -- only who to deliver to, the opaque ciphertext, and a sender-chosen random
-- idempotency key. The relay never learns who sent it (the sender authenticated only with the
-- recipient's delivery access key, ADR-0014 Slice 2a).
CREATE TABLE sealed_envelopes (
    id               BIGSERIAL PRIMARY KEY,
    recipient_device BYTEA NOT NULL CHECK (octet_length(recipient_device) = 16),
    ciphertext       BYTEA NOT NULL,
    idempotency_key  BYTEA NOT NULL CHECK (octet_length(idempotency_key) = 16),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered        BOOLEAN NOT NULL DEFAULT FALSE
);

-- Idempotency is re-scoped to (recipient_device, idempotency_key): there is no sender to key on.
-- The key is a 128-bit sender-chosen random, so a cross-sender collision (which silently no-ops one
-- insert) has probability ~2^-128.
CREATE UNIQUE INDEX sealed_envelopes_idem
    ON sealed_envelopes (recipient_device, idempotency_key);

-- Inbox peek + retention purge both scan by recipient/age.
CREATE INDEX sealed_envelopes_recipient ON sealed_envelopes (recipient_device) WHERE NOT delivered;
CREATE INDEX sealed_envelopes_created_at ON sealed_envelopes (created_at);
