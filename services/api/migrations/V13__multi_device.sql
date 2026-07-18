-- Controlled multi-device (ADR-0008, R-903): replace the strict single-active-device rule.
--
-- v1 enforced at most one non-revoked device per account via a partial unique index — the correct
-- security default, but not a viable product (phone + tablet, upgrades). ADR-0008 allows several
-- non-revoked devices, added ONLY through the authenticated trusted-device enrollment ceremony
-- (never username+password alone — that prohibition stays absolute). The application enforces a
-- per-account cap (AuthService::MAX_ACTIVE_DEVICES) atomically; the database no longer forbids a
-- second active device.
DROP INDEX devices_one_active_per_account;

-- Keep efficient lookups of an account's active devices (primary resolution + the device list).
CREATE INDEX devices_active_by_account ON devices (account_id, created_at) WHERE NOT revoked;
