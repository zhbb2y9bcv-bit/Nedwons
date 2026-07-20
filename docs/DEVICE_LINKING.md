# In-app device linking (BN-4)

Linking a second (third, …) device into an account means adding it to that account's **self-group** —
the private MLS group of the account's own devices (ADR-0015, option 3) over which view-once
consumption and history sync fan out. This is the in-app coordinator for that link, plus the Devices
screen affordance that drives it.

## The coordinator: `SelfGroupLinker`

`apps/ios/NedwonsApp/Sources/NedwonsAppKit/SelfGroupLinker.swift` — a small, stateless value over
`NedwonsClient` (HTTP) + `MlsClient` (the real Rust MLS core). Two roles, one per side of a link:

- **Primary** (`linkPendingSiblings`): the device that holds — or here first establishes — the
  self-group. It creates + registers the self-group if absent, then for every device the relay lists
  as *pending* it claims a key package, `addSelfDevice`s it (producing a **real MLS Welcome**), and
  delivers that Welcome to the sibling over `/v1/self-group/deliver`. Returns which siblings were
  linked; idempotent — a re-run only adds devices still pending, and a sibling with no key package
  yet is skipped (left pending), never fatal.
- **Joiner** (`joinSelfGroupFromInbox`): the freshly-enrolled device. It pulls the Welcome waiting on
  its self-group channel, `joinSelfGroup`s it, registers as a member, and acks. Idempotent: once it
  holds the self-group it returns `true` without touching the relay.

The relay stays **MLS-blind** throughout — only opaque Welcome/commit bytes cross it.

### It's the *tested* path

`SelfGroupLiveRun` (the live end-to-end harness, `scripts/self_group_live_run.sh`) drives this exact
type against a booted `nedwons-api` + PostgreSQL: primary establishes the group and links the
tablet, the tablet joins from its inbox, both `hasSelfGroup()`, and a second primary pass is a proven
no-op. So the app's linking code is exercised live with real MLS bytes crossing the real relay
(`LIVE_OK`), not mocked.

## The UI: Devices screen

`DevicesScreen` (NedwonsUI) shows a **"Waiting to link"** section when the relay reports pending
siblings, with a **"Link N device(s)"** button (a spinner + disabled state while running, then a
"Linked N device(s)" / "No devices were waiting to link" banner). The button calls
`AppModel.linkPendingDevices()`.

### Layering: why the link action is injected

`NedwonsUI` is pure Swift and **cannot import `MlsFfi`** (the MLS core) — that's what keeps it
macOS-buildable and the NSE-safe modules clean. So `AppModel` can't itself run the linker. Instead it
exposes an injection point:

```swift
public var linkDevicesAction: (() async throws -> [String])?   // set by the composition layer
```

`NedwonsAppKit` — the one layer that links both `NedwonsUI` and `MlsFfi` — is where this gets wired
to a `SelfGroupLinker` over the app's session `MlsClient`. Until it's wired, the hook is `nil` and the
button honestly reports *"Device linking isn't available in this build."* — fail-safe, never a fake
success.

## What remains (with device provisioning)

Wiring `linkDevicesAction` to a real `SelfGroupLinker` needs the app to hold a **durable, per-session
`MlsClient`** for the signed-in account. That session lifecycle is coupled to the same app-group +
shared-Keychain provisioning the Notification Service Extension needs (see
`docs/NOTIFICATION_EXTENSION.md`) — the app and NSE must open one shared MLS store under the
single-writer invariant (ADR-0007). Once that session exists, binding is a one-liner:

```swift
model.linkDevicesAction = {
    try await SelfGroupLinker(client: client)
        .linkPendingSiblings(mls: sessionMls, accessToken: token).linked
}
```

The coordinator and the UI are done and tested now; only that final binding waits on device-side
provisioning.
