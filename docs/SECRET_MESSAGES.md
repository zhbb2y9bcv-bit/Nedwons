# Secret Messages — what they protect, and what they do not

Secret Messages ("view-once") let a sender share a short text that the recipient can open **once**,
for a fixed viewing window, after which NEDWONS cannot show it again. This document is deliberately
honest about the boundary of that promise. **Do not represent Secret Messages as doing more than
this list.**

## What a Secret Message is

- A normal NEDWONS message in every cryptographic respect: end-to-end encrypted with the same MLS
  ciphersuite, the same sender authentication, group-membership enforcement, replay protection, and
  crash-safe delivery as any other message. There is **no** second, weaker path.
- Classified and carried **inside** the MLS ciphertext (an application-content envelope). The relay
  never learns that a message is secret, nor its contents — it forwards the same opaque bytes as for
  any message. There is no server route that says "this is secret".
- Governed by a one-way, crash-safe state machine enforced in the Rust core:
  `Sealed → Countdown (3s) → Visible (10s) → Consumed (tombstone)`.

## What "can never be seen again" means (precisely)

It means: **once consumed, the message cannot be reopened through NEDWONS.** The plaintext is
scrubbed from on-device storage, the state is durably `Consumed`, and:

- Tapping again does nothing — there is no second viewing opportunity.
- Backgrounding, locking, rotating, app-switching, or **changing the system clock** cannot extend or
  restart the window (the timer is monotonic elapsed time, not wall-clock).
- If the app crashes or is killed after a reveal begins, it **fails closed** on relaunch: the
  message is marked consumed and is not reopened.
- A replayed or duplicated delivery does not grant a new viewing opportunity.

## What it does NOT protect against — no exceptions

These are outside what any messaging app can prevent, and NEDWONS does not claim otherwise:

- **Screenshots.** iOS reports a screenshot only *as or after* it is taken. NEDWONS reacts to
  `UIApplication.userDidTakeScreenshotNotification` by immediately expiring the view and removing the
  plaintext, and uses the task-switcher privacy cover — but a screenshot already captured is out of
  our hands. This is **detection and fast reaction, not prevention.**
- **Screen recording / mirroring / AirPlay.** If `UIScreen.isCaptured` is (or becomes) true while a
  secret is open, NEDWONS obscures/expires it. A recording that started before, or a capture path
  we cannot observe, is not prevented.
- **An external camera** photographing the screen. Impossible to prevent by any software.
- **A compromised device or OS.** Jailbreak, malware, a hostile keyboard/screen-reader, or a
  modified OS can read anything the legitimate app can. E2EE protects data in transit and at rest on
  the server, **not** a device already under an attacker's control.
- **Forensic recovery from flash storage.** Scrubbing is best-effort at the language/OS level;
  wear-levelling and controller caches mean deleted bytes may physically persist. We do not promise
  cryptographic erasure of consumed plaintext from the flash medium.
- **The recipient's intent.** A determined recipient who is meant to see the message once can
  memorise, transcribe, or photograph it. View-once raises friction; it is not DRM.

## Multi-device

Account-wide single-consumption **is implemented** ([ADR-0015](adr/0015-secret-message-multidevice.md)):
when one of your devices opens a secret, it sends an **end-to-end-encrypted, relay-blind**
"consumed" control message to your other devices, which then consume their copy too — so opening on
your phone also consumes it on your tablet. The relay never learns a message is secret or that it
was consumed.

That "consumed" message travels over your account's **device self-group** — a separate MLS group of
only your own devices. Because the person who sent you the secret is **not** a member of that group,
they never receive, and cannot decrypt, the signal that you opened it: opening a view-once message
is **not** a read receipt to the sender. (An earlier design routed it through the conversation, which
did disclose the open to the sender; the self-group upgrade closes that. A single-device or not-yet-
linked account falls back to the conversation route until a second device is linked.)

Establishing that self-group across your devices runs over the relay, which stays **MLS-blind** — it
routes opaque ciphertext among your own authenticated devices only, never seeing the self-group or
its contents (`services/api`, ADR-0015 "Backend transport"). A device is linked into the self-group
only through the authenticated trusted-device enrollment ceremony (ADR-0008) followed by the MLS
add/Welcome handshake; a stranger can neither claim your device's key package nor deliver into your
self-group.

Two honest caveats, inherent to keeping this relay-blind (not hidden):

- **Concurrency:** if two of your devices open the *same* secret within the brief window before the
  consumed message propagates, both may show it once. Neither can ever re-open it afterward — there
  is never a *second* viewing, only a possible sub-second overlap.
- **Offline devices:** a device that is offline when the consumed message is sent applies it on next
  sync. Until it syncs, that offline device could still open its own copy once. Account-wide
  consumption is **eventually consistent**, not instantaneous.

## Where the enforcement lives (for reviewers)

The security-critical logic is in Rust (`core/mls-core/src/content.rs`, `secret.rs`, `durable.rs`),
reached over the UniFFI `MlsClient` surface (`core/mls-ffi`). The SwiftUI overlay
(`apps/ios/NedwonsKit/Sources/NedwonsUI/SecretMessage*.swift`) is presentation only — it never
enforces a deadline or holds plaintext beyond a frame, and it forwards every decision to the Rust
core. Tests: `core/mls-core/tests/secret.rs`, `core/mls-ffi/tests/secret.rs`, the fake-clock
view-model tests, and the real-core view-model tests in `apps/ios/NedwonsApp`. The reveal state
machine is continuously fuzzed (`core/mls-ffi/fuzz/fuzz_targets/secret_state.rs`).
