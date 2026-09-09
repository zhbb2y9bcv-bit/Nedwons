# Notification Service Extension (BN-2)

The contentless-push design (see `PUSH_NOTIFICATIONS.md`) relies on a Notification Service Extension
(NSE) that turns a generic "New message" wake into the real, locally-decrypted notification. This is
that extension.

## What's built (and how it's tested)

- **`PushInboxDecoder`** (`apps/ios/NedwonsApp/Sources/NedwonsPush`) — the extension-safe decode
  logic: given a freshly-`open`ed `MlsClient` and the fetched inbox, it processes the new envelopes
  through the **real MLS core** and returns what to show (the newest normal message's body; a
  generic "Secret message" for a view-once, whose plaintext is NEVER put in the notification; control
  / duplicate messages surface nothing). Unit-tested against the real core in
  `PushInboxDecoderTests` (normal body, secret-generic-without-leak, newest-wins, control-only → nil).
- **`NedwonsPush`** is a **leaf module** depending only on `NedwonsKit` (HTTP) + `MlsFfi` (MLS) —
  NOT `NedwonsUI` — because app extensions forbid app-only API / SwiftUI `App` types. The app and
  the NSE both link it.
- **`NotificationService`** (`apps/ios/Nedwons/NotificationService`) — the NSE shell:
  synchronously (an NSE may block for its ~30s budget) it fetches the inbox, decodes via
  `PushInboxDecoder`, acks, and rewrites the alert; the two async client calls are bridged to
  blocking, crossing only `Sendable` results, so the non-`Sendable` notification content stays on one
  thread (no structured-concurrency data races). The app + NSE **build** together for the simulator.

## Single-writer coordination (ADR-0007) — the load-bearing design point

Decrypting **advances and durably commits the MLS ratchet**, and a given MLS group must live in
exactly one client at a time. Implemented (2026-09-09) as a cross-process handoff over
`NedwonsPush.StoreLock` (a plain `flock`, OS-released if a holder dies):

1. The **app** holds the lock from `ConversationCoordinator.start()` to `stop()`. Entering the
   background (`scenePhase`) calls `stop()`: every open store is closed and the lock released, so
   a push arriving while the app is away finds the stores free. Foregrounding calls `start()`,
   which (on a background thread) waits for a finishing extension, re-reads the shared
   `MlsStoreIndex`, and re-`open`s to pick up whatever the extension committed.
2. The **NSE** takes the lock **non-blockingly** — if the app holds it, the app is running and
   will show the message itself, so the extension falls back to the generic wake instead of
   fighting for the store.

## The shared layout (`NedwonsPush.SharedStoreLayout`)

The app's real store layout is **one encrypted store per conversation** behind `index.json`
(`MlsStoreIndex`, moved into the extension-safe `NedwonsPush` module), all under
`<app-group container>/mls/`. `AppComposition.standard()` roots the stores there whenever the
`NedwonsAppGroup` Info.plist key names a provisioned group (migrating an existing app-private tree
once), and the NSE resolves each envelope's conversation to its store through the same index —
`PushInboxDecoder.decode(envelopes:clientFor:)`, unit-tested against the real core in
`SharedPushStoreTests`.

**Ack discipline:** the extension acks ONLY the envelope ids it durably processed (ratchet
advanced + committed, duplicates included). Sealed and self-group envelopes, conversations whose
store it cannot open, and failed decrypts are left queued — acking them would delete mail nothing
ever decrypted (at-least-once delivery).

Everything is **fail-safe**: any error or missing state falls back to the generic wake — a push
never crashes or blocks the system.

## What device provisioning still needs (your side)

`SharedNotificationContext.current()` returns `nil` until these exist, so today the NSE safely shows
the generic wake. The software on both sides is complete; flipping these turns it on:

- Register an **App Group** (e.g. `group.app.nedwons.demo`) for both App IDs, add the
  `com.apple.security.application-groups` entitlement to BOTH targets, and set the
  **`NedwonsAppGroup`** Info.plist key (both targets, `project.yml`) to the group id.
- Enable the **shared Keychain access group** (stubbed in `Nedwons.entitlements`) on both targets
  — first in each list, so the app's `SessionStore` + at-rest root land where the NSE reads them.
- The push capability + the NSE embedded in the signed app (already wired in `project.yml`), plus
  APNs credentials server-side (`PUSH_NOTIFICATIONS.md`) and a physical device.
