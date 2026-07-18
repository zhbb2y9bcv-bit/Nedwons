-- App Attest (#10, R-101): the server issues a short-lived challenge the client folds into its
-- attestation object (anti-replay), then stores the submitted attestation bound to the device. The
-- CRYPTOGRAPHIC verification of the attestation object against Apple's App Attest root — and live
-- testing — are HARDWARE-GATED (a physical device + the app's entitlement); see docs/APP_ATTEST.md.
-- This schema holds the challenge and the submitted attestation (with a `verified` flag the future
-- verifier flips).
CREATE TABLE app_attest_challenges (
    device_id  BYTEA PRIMARY KEY CHECK (octet_length(device_id) = 16),
    challenge  BYTEA NOT NULL CHECK (octet_length(challenge) = 32),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE app_attest_keys (
    device_id   BYTEA PRIMARY KEY CHECK (octet_length(device_id) = 16),
    key_id      TEXT NOT NULL,
    attestation BYTEA NOT NULL,
    verified    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
