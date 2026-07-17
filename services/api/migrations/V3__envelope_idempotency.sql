-- Messaging efficiency + reliability (no schema change to what is stored: still only opaque
-- ciphertext). Adds an idempotency key so a client can retry a send after a network blip
-- without creating duplicate envelopes — which lets clients retry aggressively (faster
-- perceived delivery) instead of backing off conservatively.

ALTER TABLE envelopes
    ADD COLUMN idempotency_key BYTEA
    CHECK (idempotency_key IS NULL OR octet_length(idempotency_key) = 16);

-- A given (sender device, recipient device, idempotency key) can exist at most once.
-- Server-side fanout inserts one row per recipient under a single idempotency key, so the
-- key spans the whole fanout and a retry is a no-op per recipient.
CREATE UNIQUE INDEX envelopes_idem
    ON envelopes (sender_device, recipient_device, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
