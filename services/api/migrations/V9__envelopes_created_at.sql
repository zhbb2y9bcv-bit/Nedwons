-- Retention purge support: the TTL purge scans envelopes by age in bounded batches
-- (relay::purge_stale_envelopes). Without this index each batch is a sequential scan, which
-- under an undelivered-mail backlog turns the minutely purge into repeated full-table reads.
CREATE INDEX envelopes_created_at ON envelopes (created_at);
