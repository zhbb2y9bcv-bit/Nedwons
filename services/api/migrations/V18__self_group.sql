-- Device self-group (ADR-0015 option 3): the account-internal MLS group of only an account's OWN
-- devices, over which view-once "consumed" control messages are synced so the conversation's other
-- party never learns a secret was opened. The relay stays MLS-blind — it routes opaque ciphertext by
-- account/device and never sees the self-group's MLS group id or contents.
--
-- Two concerns, two tables, mirroring the existing conversation-membership + envelope split:

-- (1) Self-group MEMBERSHIP: which of an account's devices have JOINED its self-group. This is a
-- subset of the account's enrolled devices (a device is enrolled first, then linked into the
-- self-group via the MLS add/welcome handshake). Fan-out targets only joined members, so a device
-- that is enrolled but not yet linked never receives a self-group message it cannot decrypt.
-- Authorization is the account boundary itself: a device may only ever be a member of its OWN
-- account's self-group (no cross-account membership is representable — account_id is the caller's).
CREATE TABLE self_group_members (
    account_id BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    device_id  BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, device_id)
);
CREATE INDEX self_group_members_by_account ON self_group_members (account_id);

-- (2) Self-group ENVELOPES: opaque ciphertext queued for one of the account's devices — an MLS
-- Welcome/commit during linking, or a `SecretConsumed` control message. A SEPARATE table from
-- `envelopes` (identified conversation mail) and `sealed_envelopes` (sealed-sender), so none of their
-- proven invariants are perturbed. `sender_device` is recorded (unlike sealed-sender): both endpoints
-- of a self-group message are the SAME account's authenticated devices, so there is no sender to hide
-- from — the privacy property is that the *other conversation party* is not in this channel at all.
CREATE TABLE self_group_envelopes (
    id               BIGSERIAL PRIMARY KEY,
    recipient_device BYTEA NOT NULL CHECK (octet_length(recipient_device) = 16),
    sender_device    BYTEA NOT NULL CHECK (octet_length(sender_device) = 16),
    ciphertext       BYTEA NOT NULL,
    idempotency_key  BYTEA NOT NULL CHECK (octet_length(idempotency_key) = 16),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered        BOOLEAN NOT NULL DEFAULT FALSE
);

-- Idempotency scoped to (recipient, sender, key), matching the identified-envelope model: a retry of
-- the same logical send is a no-op, and one fan-out key legitimately inserts one row per recipient.
CREATE UNIQUE INDEX self_group_envelopes_idem
    ON self_group_envelopes (recipient_device, sender_device, idempotency_key);

-- Inbox peek + retention purge scan by recipient/age.
CREATE INDEX self_group_envelopes_recipient ON self_group_envelopes (recipient_device) WHERE NOT delivered;
CREATE INDEX self_group_envelopes_created_at ON self_group_envelopes (created_at);
