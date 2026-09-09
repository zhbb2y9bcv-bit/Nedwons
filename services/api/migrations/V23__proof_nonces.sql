-- Distributed single-use nonces for DPoP-style request proofs (ADR-0011, R-308).
--
-- The replay cache was a process-local HashMap, which is correct for exactly one API instance and
-- silently wrong for more than one: a captured proof replayed against a DIFFERENT instance inside
-- the freshness window would be accepted, because that instance had never seen the nonce. The
-- module said so honestly; this is the fix.
--
-- The primary key IS the guarantee. Recording a nonce is a plain
-- `INSERT ... ON CONFLICT DO NOTHING`, so the first writer wins and every concurrent racer — on any
-- instance — sees zero rows affected and is refused. No lock, no read-then-write, nothing to race.
--
-- Keyed by (device_id, nonce) so one device cannot burn another's nonce. Rows are tiny and
-- short-lived: they expire after the proof's freshness window and are swept by the retention purge.
--
-- Deliberately NO foreign key to `devices`: this table is written on the authentication path, and a
-- proof from a device that was revoked mid-request must be refused by the auth check rather than by
-- a constraint violation surfacing as a 500. Expiry bounds the rows instead.
CREATE TABLE proof_nonces (
    device_id  BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    nonce      BYTEA NOT NULL CHECK (octet_length(nonce) = 16),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (device_id, nonce)
);

-- Supports the expiry sweep without scanning the whole table.
CREATE INDEX proof_nonces_expires_at ON proof_nonces (expires_at);
