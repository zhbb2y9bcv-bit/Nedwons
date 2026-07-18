# ADR-0012: Sealed sender & metadata minimization (R-204)

- **Status:** Accepted — **the sender-certificate primitive is implemented and cross-language
  tested** (`auth_core::sender_cert` + the Swift verifier, byte-identical golden). The server
  **issuance endpoint** and sealed-sender **delivery** (the relay stops learning the sender) +
  abuse controls are the remaining slices, specified below.
- **Date:** 2026-07-18
- **Deciders:** crypto integrator, backend lead, security architect
- **Sources:** Signal "Technology preview: Sealed sender" (design pattern for sender-anonymous
  delivery + server-issued sender certificates).

## Problem (R-204)

Message *content* is E2EE (INV-1, proven). But the relay still sees **routing metadata**: for every
message it stores `(sender_device, recipient_device, conversation_id, timing, size)`. A compromised
or compelled relay can therefore build the social graph and communication timeline even though it
never reads a word. For "the most secure messenger" that is a real gap.

## Goal

The relay should be able to *deliver* a message to a recipient **without learning who sent it**. The
recipient still cryptographically verifies the sender (no spoofing). Content secrecy is unchanged.

## Design (Signal-style sealed sender)

1. **Sender certificate (this slice).** The server issues each device a short-lived, signed
   certificate binding `{account, device, sender public key, expires_at}` under a dedicated
   **sender-certificate signing key** (ECDSA-P256, KMS/HSM in production — distinct from the auth
   and transparency keys). A device fetches one periodically while authenticated. The certificate
   proves "the server vouched that this key belongs to this account at issuance time" — the same
   trust the recipient would otherwise get from the key directory, but capturable in one token the
   sender can present *later, anonymously*.

2. **Sealed-sender delivery (next slice).** To send anonymously, the sender:
   - encrypts the message with MLS as usual, and *inside* the E2EE payload includes its sender
     certificate (so only the recipient learns the sender);
   - delivers to a new endpoint that authenticates the sender only weakly or not at all — the relay
     stores the envelope with **no `sender_device`** (NULL), only `recipient_device` + opaque bytes.
   The recipient decrypts, extracts the certificate, verifies its signature under the **pinned**
   sender-cert public key and that it has not expired, and checks the certificate's key matches the
   MLS sender — learning the sender that the relay never saw.

3. **Abuse control for unauthenticated delivery (next slice).** Anonymous delivery is a spam vector.
   Mitigations, layered: per-recipient **delivery access keys** (the recipient shares a rotating key
   with contacts; the relay checks a keyed token without learning the sender — as Signal does), the
   existing **block** enforcement moved recipient-side, **message requests** for non-contacts, and
   per-recipient rate limits. Content is still E2EE, so the relay gates on the recipient + token, not
   the sender.

## What this does NOT hide (honest limits — do not overclaim)

- **Recipient, timing, size, and volume** are still visible to the relay. Sealed sender hides the
  *sender*, not the recipient or traffic-analysis signals. Padding + cover traffic are separate,
  unbuilt work.
- A relay that colludes with the recipient, or does IP-level correlation, can still deanonymize.
  Network-layer anonymity (onion routing) is out of scope.
- The sender certificate is only as trustworthy as the sender-cert key + the key directory /
  transparency log (R-201); logging cert-key rotation in the transparency record is future work.

## Alternatives considered

- **Do nothing / accept metadata.** Rejected: it is the largest remaining privacy gap.
- **Per-message anonymous credentials (blind signatures / VOPRF).** Stronger unlinkability than
  server-issued certs, but a heavier, less-reviewed construction; revisit if the certificate model
  proves insufficient.
- **Drop `sender_device` from all envelopes immediately.** Rejected as a first step: fan-out,
  idempotency, and the membership/commit paths currently rely on the authenticated sender; sealing
  must be an *additional* delivery mode, migrated carefully, not a rip-out.

## Decision & rollout

Adopt Signal-style sealed sender. **Slice 1a (this change):** the sender-certificate primitive
(`auth_core::sender_cert` — canonical encode + verify with expiry) and the client-side verifier
(`SentinelKit.SenderCertificate`, byte-identical + golden-tested cross-language). **Slice 1b
(landed 2026-07-18):** a dedicated server sender-certificate key (`SENTINEL_SENDER_CERT_KEY`,
ephemeral fallback in dev; distinct from the auth/transparency keys) and `GET
/v1/sender-certificate`, which issues a short-lived (`SENDER_CERT_TTL_SECS`, 24h) signed certificate
for the authenticated device. The response includes the cert public key so clients can pin it out of
band and verify without the relay ever seeing the sender; the relay stays MLS-blind (it only signs
`{account, device, device pubkey, expiry}` bytes). Integration-tested: the signature verifies under
the returned key, binds the device's own public key, and a tampered key fails. The **client half**
also landed: `SentinelClient.fetchSenderCertificate` decodes the issuance response into an
`IssuedSenderCertificate` (certificate + signature + echoed cert key) with
`verify(pinnedCertPublicKeyX963:now:)`, unit-tested via a stub transport (verifies under the pinned
key, rejects a substituted key, rejects once expired). **Slice 2:** the sealed-sender delivery
endpoint (NULL sender, recipient-token abuse control) + recipient extraction/verification wired
through the MLS payload + `PRIVACY.md` updates. R-204 stays **OPEN/MITIGATING** until Slice 2 ships
and the relay demonstrably stores no sender for sealed messages.
