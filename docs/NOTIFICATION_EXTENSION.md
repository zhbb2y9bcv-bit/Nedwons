# Notification Service Extension (BN-2)

The contentless-push design (see `PUSH_NOTIFICATIONS.md`) relies on a Notification Service Extension
(NSE) that turns a generic "New message" wake into the real, locally-decrypted notification. This is
that extension.

## What's built (and how it's tested)

- **`PushInboxDecoder`** (`apps/ios/SentinelApp/Sources/SentinelPush`) — the extension-safe decode
  logic: given a freshly-`open`ed `MlsClient` and the fetched inbox, it processes the new envelopes
  through the **real MLS core** and returns what to show (the newest normal message's body; a
  generic "Secret message" for a view-once, whose plaintext is NEVER put in the notification; control
  / duplicate messages surface nothing). Unit-tested against the real core in
  `PushInboxDecoderTests` (normal body, secret-generic-without-leak, newest-wins, control-only → nil).
- **`SentinelPush`** is a **leaf module** depending only on `SentinelKit` (HTTP) + `MlsFfi` (MLS) —
  NOT `SentinelUI` — because app extensions forbid app-only API / SwiftUI `App` types. The app and
  the NSE both link it.
- **`NotificationService`** (`apps/ios/Sentinel/NotificationService`) — the NSE shell:
  synchronously (an NSE may block for its ~30s budget) it fetches the inbox, decodes via
  `PushInboxDecoder`, acks, and rewrites the alert; the two async client calls are bridged to
  blocking, crossing only `Sendable` results, so the non-`Sendable` notification content stays on one
  thread (no structured-concurrency data races). The app + NSE **build** together for the simulator.

## Single-writer coordination (ADR-0007) — the load-bearing design point

Decrypting **advances and durably commits the MLS ratchet**, and a given MLS group must live in
exactly one client at a time. So the NSE and the app must never open the store simultaneously:

1. The NSE takes an exclusive **`flock`** on an app-group file (held across the blocking fetch).
2. It `open`s the shared, atomically-committed MLS store, processes + acks, and releases the lock.
3. The app, suspended in the background, holds no client; on next foreground it re-`open`s to pick up
   the NSE's committed advance (the durable layer's crash-safe reopen makes this exact).

Everything is **fail-safe**: any error or missing state falls back to the generic wake — a push never
crashes or blocks the system.

## What device provisioning still needs (your side)

`SharedNotificationContext.current()` returns `nil` until these exist, so today the NSE safely shows
the generic wake:

- An **App Group** (`group.app.sentinel...`) shared between the app and the NSE, holding the MLS
  store + the `flock` file (`FileManager.containerURL(forSecurityApplicationGroupIdentifier:)`).
- A **shared Keychain access group** (stubbed in `Sentinel.entitlements`) so the NSE reads the same
  session token + at-rest root the app enrolled.
- The push capability + the NSE embedded in the signed app (already wired in `project.yml`).

Once provisioned, fill in `SharedNotificationContext.current()` to read those, and the tested decode
path runs unchanged on device.
