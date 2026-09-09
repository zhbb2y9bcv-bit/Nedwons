-- Distributed abuse quotas (R-306).
--
-- Rate limiting was per-IP and per-process. Both halves are inadequate for abuse control:
--
--   * PER-PROCESS — a `governor` limiter lives in one instance's memory, so behind a load balancer
--     the effective limit is (limit x instances), and it resets on every deploy.
--   * PER-IP — simultaneously too coarse and too weak. Too coarse because a university, office or
--     carrier NAT shares one address, so one abuser throttles thousands of bystanders. Too weak
--     because addresses are cheap: rotating through a residential proxy pool resets the counter,
--     while the ACCOUNT doing the spamming is untouched.
--
-- Abuse is committed by accounts, so the quota that matters is keyed by account. This table holds
-- fixed-window counters shared by every instance.
--
-- `window_start` is the unix second at which the window opened (floor(now / window)), so a counter
-- is addressed without reading anything first: the increment is a single
-- `INSERT ... ON CONFLICT DO UPDATE ... RETURNING count`, which takes the row lock and returns the
-- post-increment value. Concurrent racers on any instance serialize on that one row, so the count
-- cannot drift.
--
-- Fixed windows (rather than a sliding log) are chosen deliberately: one row per subject per
-- window instead of one row per event, which is what keeps this cheap enough to sit on request
-- paths. The known cost is burst tolerance at a window boundary — up to 2x the limit across two
-- adjacent windows. That is acceptable for abuse control, where the goal is bounding sustained
-- volume, not policing microbursts.
CREATE TABLE rate_counters (
    scope        TEXT   NOT NULL CHECK (char_length(scope) BETWEEN 1 AND 64),
    subject      BYTEA  NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 64),
    window_start BIGINT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, subject, window_start)
);

-- Old windows are dead weight; the retention purge sweeps them by this index.
CREATE INDEX rate_counters_window_start ON rate_counters (window_start);
