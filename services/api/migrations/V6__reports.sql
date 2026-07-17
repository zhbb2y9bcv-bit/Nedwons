-- User reports (abuse control, ABUSE_MODEL.md). The server cannot read E2EE content, so `evidence`
-- holds ONLY what the reporter explicitly chose to submit (a client-rendered excerpt) — never
-- anything server-derived. No foreign keys: reports are moderation records that must persist
-- independently of account lifecycle.
CREATE TABLE reports (
    id         BIGSERIAL PRIMARY KEY,
    reporter   BYTEA NOT NULL CHECK (octet_length(reporter) = 16),
    reported   BYTEA NOT NULL CHECK (octet_length(reported) = 16),
    reason     TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 500),
    evidence   TEXT CHECK (evidence IS NULL OR char_length(evidence) <= 16384),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (reporter <> reported)
);

CREATE INDEX reports_reported ON reports (reported);
