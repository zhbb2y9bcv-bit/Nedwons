-- Attachment metadata. The BYTES are not here: they live in the blob store as ciphertext the relay
-- has no key for (see `services/api/src/blobs.rs` and `core/mls-core/src/attachment.rs`). This
-- table exists to answer one question — "may this device fetch this blob?" — and to give retention
-- something to sweep.
--
-- WHAT THE SERVER LEARNS, precisely, so it is not overclaimed: that an account uploaded an object
-- of a given ciphertext size to a given conversation at a given time. Not the file, not its name,
-- not its media type, not whether it is a photo or a PDF — all of that travels inside the MLS
-- message that references the blob.
--
-- Deliberately NOT content-addressed: two identical files uploaded by two people get two ids and
-- two objects. Deduplicating by hash would let the server (or anyone who can time uploads) learn
-- that two users hold the same file, which is exactly the kind of cross-user inference this design
-- otherwise refuses.
CREATE TABLE attachments (
    blob_id         BYTEA PRIMARY KEY CHECK (octet_length(blob_id) = 16),
    -- Authorization is conversation membership, the same rule the envelope path uses. Cascades, so
    -- a deleted conversation cannot leave a fetchable object behind.
    conversation_id BYTEA NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
    uploader_device BYTEA NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    -- Ciphertext length, for quota accounting and a cheap sanity check before serving.
    size_bytes      BIGINT NOT NULL CHECK (size_bytes > 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Retention sweeps oldest-first (DATA_RETENTION.md gives attachments the same TTL as queued mail).
CREATE INDEX attachments_created_at ON attachments (created_at);
