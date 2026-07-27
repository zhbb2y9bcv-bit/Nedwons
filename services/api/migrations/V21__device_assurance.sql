-- Device assurance class (ADR-0008 "Migration & backward compatibility", pinned down by ADR-0017).
--
-- ADR-0008 allowed several non-revoked devices per account and reserved a distinction the schema
-- never actually carried: "Software-signer devices (R-G0-2 fallback) are a distinct LOWER-ASSURANCE
-- class and are ineligible to APPROVE new enrollments." Until now every enrolled device was
-- indistinguishable, so that rule could not be enforced — it was documentation, not a control.
--
-- ADR-0017 adds a web client whose device key is a non-extractable WebCrypto P-256 key. That key is
-- protected by browser policy, not by hardware: it cannot be exfiltrated, but script running in the
-- origin (XSS) can USE it as a signing oracle for as long as the page is open. That is a genuinely
-- weaker custody story than the Secure Enclave, so the two must stop being interchangeable before a
-- browser can enroll. This migration makes the class explicit and durable.
--
-- The security control this enables (enforced in auth-core, NOT by this schema): a `software` device
-- may hold a session and read its own conversations, but may NOT authorize enrollment of another
-- device. Otherwise a single XSS becomes account-wide device injection, which is exactly the
-- "Downgrade via software-signer device" threat ADR-0008 lists.

ALTER TABLE devices
    ADD COLUMN assurance TEXT NOT NULL DEFAULT 'software'
        CHECK (assurance IN ('hardware', 'software'));

-- Backfill: every device enrolled before this migration is an iOS client that went through
-- `DeviceIdentity`'s fail-closed Secure Enclave selection (R-G0-2), so it is genuinely hardware-
-- backed. Done explicitly rather than by choosing a permissive column default — see below.
UPDATE devices SET assurance = 'hardware';

-- Why the default is 'software' and not 'hardware':
--
-- `add_active_device` / the recovery path both `INSERT INTO devices (device_id, account_id,
-- public_key, revoked)` WITHOUT naming this column, so the default decides what an un-migrated
-- caller produces. 'hardware' would FAIL OPEN — a web enrollment that forgets to declare its class
-- would silently become a hardware-assurance device that can approve further enrollments, which is
-- the precise downgrade this column exists to prevent. 'software' fails CLOSED: the worst case is a
-- genuinely hardware-backed device under-classified and therefore unable to approve enrollments —
-- visible and annoying, never a silent privilege gain.
--
-- CONSEQUENCE, deliberately accepted (ADR-0017): until the iOS enrollment path is updated to declare
-- `assurance = 'hardware'` explicitly, NEWLY enrolled iOS devices land as 'software' and cannot
-- approve enrollments. Existing devices are unaffected (backfilled above), so no session breaks and
-- no user is locked out — the primary device keeps working. Wiring the declaration through
-- `DeviceRecord` is the immediate follow-up.

-- Support "which of this account's devices may approve an enrollment?" without scanning, and keep it
-- aligned with the existing active-device lookup (devices_active_by_account, V13).
CREATE INDEX devices_approvers_by_account
    ON devices (account_id)
    WHERE NOT revoked AND assurance = 'hardware';
