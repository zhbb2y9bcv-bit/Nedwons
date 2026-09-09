-- Opt-in crash/hang diagnostics (docs/OBSERVABILITY: client side). Rows arrive ONLY from users
-- who flipped the Settings toggle; the payload is MetricKit's diagnostic JSON — stack traces and
-- OS/app versions, never message content — submitted UNAUTHENTICATED and stored without any
-- account linkage, because a crash report must not become a tracking record. Size-capped and
-- swept by the retention task like every other transient table.
CREATE TABLE diagnostics (
    id         BIGSERIAL PRIMARY KEY,
    payload    TEXT NOT NULL CHECK (char_length(payload) <= 262144),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX diagnostics_created_at ON diagnostics (created_at);
