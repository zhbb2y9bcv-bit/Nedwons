-- MLS-commit-authoritative membership (ADR-0010, R-506).
--
-- `conversations.epoch` is the compare-and-swap anchor that linearizes membership history: a
-- commit is accepted only if its manifest's prev_epoch equals the stored epoch, and exactly one
-- commit wins each epoch transition. The server remains MLS-blind — it stores hashes, signatures,
-- and ids, never MLS structures.
ALTER TABLE conversations ADD COLUMN epoch BIGINT NOT NULL DEFAULT 0;

-- Append-only audit log of applied membership manifests. One row per accepted commit; the
-- uniqueness constraints are load-bearing:
--   (conversation_id, next_epoch)  — at most one commit per epoch transition (no forks),
--   (actor_device, idempotency_key) — idempotent retry detection with mismatch refusal.
CREATE TABLE membership_events (
    id              BIGSERIAL PRIMARY KEY,
    conversation_id BYTEA NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
    prev_epoch      BIGINT NOT NULL,
    next_epoch      BIGINT NOT NULL CHECK (next_epoch = prev_epoch + 1),
    control_type    SMALLINT NOT NULL CHECK (control_type IN (1, 2, 3)),
    actor_device    BYTEA NOT NULL CHECK (octet_length(actor_device) = 16),
    commit_hash     BYTEA NOT NULL CHECK (octet_length(commit_hash) = 32),
    manifest_hash   BYTEA NOT NULL CHECK (octet_length(manifest_hash) = 32),
    -- The exact canonical manifest bytes + device signature: auditable evidence of who claimed
    -- what. Contains only ids/hashes/epochs — no message content, no keys.
    manifest        BYTEA NOT NULL,
    signature       BYTEA NOT NULL,
    idempotency_key BYTEA NOT NULL CHECK (octet_length(idempotency_key) = 16),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (conversation_id, next_epoch),
    UNIQUE (actor_device, idempotency_key)
);
