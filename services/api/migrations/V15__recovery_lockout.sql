-- Recovery-attempt lockout (ADR-0003, R-304 residual): throttle brute-force of the recovery
-- secret. A per-account failure counter locks recovery for a cooldown after too many misses.
ALTER TABLE accounts ADD COLUMN recovery_failed_count INT NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN recovery_locked_until BIGINT;  -- unix seconds; NULL = not locked
