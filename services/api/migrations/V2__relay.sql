-- Message relay schema. The server stores ONLY opaque ciphertext and the minimum routing
-- metadata needed to deliver it (ARCHITECTURE.md §3, THREAT_MODEL.md INV-1). There is no
-- column that could hold plaintext, and the server never links the MLS library.

-- Published key packages ("prekeys"): let a member be added to a group while offline.
-- Claimed one at a time and deleted (last-resort reuse is a future refinement).
CREATE TABLE key_packages (
    id          BIGSERIAL PRIMARY KEY,
    account_id  BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    device_id   BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    key_package BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX key_packages_by_account ON key_packages (account_id, id);

CREATE TABLE conversations (
    conversation_id BYTEA PRIMARY KEY CHECK (octet_length(conversation_id) = 16),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Coarse routing membership (which devices should receive envelopes). Cryptographic group
-- membership is enforced by MLS on the clients; this is only for delivery.
CREATE TABLE conversation_members (
    conversation_id BYTEA NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
    account_id      BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    device_id       BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, device_id)
);

-- Opaque encrypted envelopes queued per recipient device. `ciphertext` is the only payload
-- column and holds MLS ciphertext the server cannot read.
CREATE TABLE envelopes (
    id               BIGSERIAL PRIMARY KEY,
    conversation_id  BYTEA NOT NULL CHECK (octet_length(conversation_id) = 16),
    sender_device    BYTEA NOT NULL CHECK (octet_length(sender_device) = 16),
    recipient_device BYTEA NOT NULL CHECK (octet_length(recipient_device) = 16),
    ciphertext       BYTEA NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered        BOOLEAN NOT NULL DEFAULT FALSE
);
-- Fetch a device's undelivered mail in order.
CREATE INDEX envelopes_inbox ON envelopes (recipient_device, id) WHERE NOT delivered;
