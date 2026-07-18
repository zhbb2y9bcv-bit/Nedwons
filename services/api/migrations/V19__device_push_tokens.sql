-- Push notification tokens (#4): so a backgrounded/killed device can be woken to fetch its inbox.
-- The token is an opaque per-device APNs (later FCM) registration token — NOT message content. The
-- relay stays E2EE-blind; a push carries only a contentless "you have mail" signal (see src/push.rs).
--
-- One token per (device, platform); re-registration upserts (tokens rotate). Rows are removed when
-- the device is revoked (the revoke handler calls delete_push_tokens).
CREATE TABLE device_push_tokens (
    device_id  BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    platform   TEXT NOT NULL,        -- 'apns' (future: 'fcm')
    token      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, platform)
);
