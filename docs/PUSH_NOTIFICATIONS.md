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

## What live deployment still needs (blocked on credentials + one dependency)

1. **A real HTTP/2 transport** to `api.push.apple.com` implementing `PushTransport` (needs an HTTP/2
   client dependency — e.g. `reqwest` with rustls — deliberately not added yet). Until one is wired,
   `PushService` uses `NullTransport`: the mechanism runs but sends nothing.
2. **Apple credentials**, supplied via env (`from_env` reads them; absent ⇒ the service is disabled):
   - `SENTINEL_APNS_KEY_HEX` — the APNs auth key's P-256 private scalar (hex; operator extracts it
     from the `.p8`),
   - `SENTINEL_APNS_KEY_ID`, `SENTINEL_APNS_TEAM_ID`, `SENTINEL_APNS_TOPIC` (bundle id).
3. **A physical device + Apple Developer provisioning** to obtain real device tokens and observe
   delivery (the simulator cannot receive remote pushes). This is the same hardware gate as the
   Secure Enclave / App Attest work.
