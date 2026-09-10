-- Message requests (the "someone new wants to reach you" folder). Until now a conversation could
-- only exist between friends (friendship = consent; ADR-0009). A message request is the controlled
-- exception: a NON-friend may open one 1:1 conversation with you, but it is quarantined on your
-- side — it lands in a Requests folder, never your main inbox, until you accept.
--
-- This table is routing/social metadata only (account ids + a status), never message content: the
-- conversation itself is ordinary MLS, so the relay still cannot read a word of it. One row per
-- request conversation, keyed by the conversation it created.
CREATE TABLE message_requests (
    conversation_id BYTEA PRIMARY KEY CHECK (octet_length(conversation_id) = 16),
    from_account    BYTEA NOT NULL CHECK (octet_length(from_account) = 16),
    to_account      BYTEA NOT NULL CHECK (octet_length(to_account) = 16),
    -- pending: awaiting the recipient's decision. accepted: became an ordinary conversation (and a
    -- friendship). declined: the recipient said no (and may have blocked the sender).
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'accepted', 'declined')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (from_account <> to_account)
);

-- The recipient's folder: list my pending incoming requests.
CREATE INDEX message_requests_to_pending ON message_requests (to_account) WHERE status = 'pending';
-- Anti-spam: cap and dedup a sender's outstanding requests.
CREATE INDEX message_requests_from_pending ON message_requests (from_account) WHERE status = 'pending';
