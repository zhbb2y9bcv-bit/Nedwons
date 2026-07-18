-- Account recovery (ADR-0003, R-304): a high-entropy recovery secret authorizes enrolling a new
-- device when no other device is available. Stored ONLY as an Argon2id PHC hash (never plaintext),
-- exactly like the password. NULL until the user opts in (while they still hold a device).
ALTER TABLE accounts ADD COLUMN recovery_phc TEXT;
