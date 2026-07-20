# Push notifications (#4)

A backgrounded or killed iOS app is not reachable by the in-process delivery notifier (which only
wakes a *connected* long-poll/WebSocket client). Push notifications wake it to fetch its inbox.

## Privacy: contentless wake, relay stays E2EE-blind

The relay never has message content (THREAT_MODEL.md INV-1), so a push carries **none**. The backend
sends only a generic wake: `{"aps":{"alert":"New message","mutable-content":1,"sound":"default"}}`.
The app's Notification Service Extension receives it, fetches the ciphertext over the normal inbox
path, decrypts it locally, and rewrites the notification (`mutable-content`). No token, sender,
conversation, or body is ever placed in the push payload (asserted by
`services/api/tests/push.rs`).

## What is built (and tested)

- **Token registration.** `POST /v1/push/register {platform:"apns", token}` (authenticated) upserts
  one token per (device, platform). Migration `V19__device_push_tokens.sql`. A revoked device's
  tokens are purged on `/v1/devices/revoke`.
- **APNs protocol logic** (`services/api/src/push.rs`): the ES256 **provider JWT**
  (`{alg:ES256,kid}.{iss:team,iat}.sig`, signed with the existing `p256`), the
  `/3/device/<token>` request, and the `apns-topic` / `apns-push-type` headers. Unit-tested
  (base64url vectors, JWT structure, contentless payload).
- **Dispatch on delivery.** `DeliveryNotifier.wake` fires an optional hook; when APNs is configured
  the hook dispatches a contentless wake to the recipient device's tokens, off the request path
  (best-effort — a push failure never touches the durable queue). Proven end-to-end with an injected
  recording transport in `push.rs`.
- **Injected transport** (mirrors the HIBP breach provider): `trait PushTransport` decouples the
  socket. Tests use a recording transport; the mechanism is fully exercised without a network.

## The real transport — wired and proven

`HttpPushTransport` (`services/api/src/push.rs`) is the production `PushTransport`: HTTP/2 via
`reqwest` + rustls (no OpenSSL), wired as the default in the router. An `https://` base uses TLS
with ALPN (Apple negotiates h2); an `http://` base uses HTTP/2 prior knowledge for local/dev
servers. `NEDWONS_APNS_URL` overrides the host (`https://api.sandbox.push.apple.com` for sandbox);
default is production APNs. No socket is ever opened unless credentials are configured.

**Proven** by `services/api/tests/apns_transport.rs`: a local mock APNs asserts the connection
**actually negotiated HTTP/2** (the APNs contract), the `/3/device/<token>` path, the
`authorization`/`apns-topic`/`apns-push-type` headers, and the contentless body; a `410 Unregistered`
status surfaces to the caller; and the provider key loads **verbatim from Apple's `.p8` file**
(PKCS#8 PEM, escaped-newline env-file form included; garbage fails closed).

## Configuration (the only remaining input is Apple credentials)

Supplied via env (`PushService::from_env`; any missing ⇒ the service is disabled, wake path no-ops):

- `NEDWONS_APNS_KEY_P8` — the contents of the `.p8` from the Apple Developer portal, verbatim
  (preferred), or `NEDWONS_APNS_KEY_HEX` — the raw P-256 scalar in hex.
- `NEDWONS_APNS_KEY_ID`, `NEDWONS_APNS_TEAM_ID`, `NEDWONS_APNS_TOPIC` (bundle id).
- `NEDWONS_APNS_URL` — optional host override (sandbox/dev).

## What still needs hardware (cannot be closed without it)

**A physical device + Apple Developer provisioning** to obtain real device tokens and observe
delivery — the simulator cannot receive remote pushes. Everything software-side is built and tested;
with credentials in env and a device in hand, the path is turn-key.
