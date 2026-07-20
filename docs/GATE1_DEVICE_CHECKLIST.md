# Gate 1 — physical-device verification checklist (BLOCKED in this environment)

**Status:** BLOCKED — no Xcode app target committed and no physical iPhone available here
(RISK_REGISTER R-101). This checklist is the hand-off for the part of Gate 1 that can only be
proven on hardware. Do not mark Gate 1 passed until every box below has captured evidence.

## What is already done in code (verified headlessly)

- **Signer selection + fail-closed policy** — `NedwonsKit/DeviceIdentity.swift`. Prefers the
  Secure Enclave; `requireHardware` refuses to enroll without it (no silent software key);
  `allowSoftwareFallback` is an explicit, acknowledged lower-assurance path.
- **Key persistence** — the enrolled key (Enclave `dataRepresentation` or software raw) is stored
  in the Keychain (`ThisDeviceOnly`) and reloaded for login, so login signs the **same** key
  (INV-2). Proven by `DeviceIdentityTests` (enroll→reload same public key; signature verifies).
- **App wiring** — `AppModel.register()` provisions+persists; `AppModel.signIn()` reloads. The app
  no longer hardcodes a software signer (Gate 0 finding R-G0-2, resolved at the app layer).
- **Enclave signer** — `SecureEnclaveDeviceSigner` (CryptoKit) compiles; possession key carries **no**
  biometric/user-presence ACL so background refresh works (local unlock is a separate layer).

## What is NOT written yet (implement before or alongside device testing)

- **The Xcode app target** (`@main`, entitlements, provisioning). The SwiftPM package builds, but the
  app target that runs on a device is not committed.
- **App Attest** — only referenced, not implemented. The DeviceCheck/`DCAppAttestService` flow, its
  server-side validation (app id, environment, counter/freshness, challenge+request binding, replay),
  and its dev/simulator/TestFlight/prod policy must be built (see the matrix rows tagged *[Attest]*).
- **Secure Enclave availability UX** for the `allowSoftwareFallback` opt-in (a Settings toggle with a
  clear explanation of the reduced assurance).

## Prerequisites

- Xcode 26 (iOS 26 SDK; Apple mandate 2026-04-28, R-401). `xcodebuild -version`.
- A paid Apple Developer team; App ID with the **App Attest** capability; a provisioning profile.
- Keychain entitlement / access group configured; privacy manifest present.
- Devices for the matrix below; a second device to prove cross-device denial.

## Build & run (once the Xcode project lands)

```
# From repo root, after the app target is committed under apps/ios/Nedwons:
xcodebuild -scheme Nedwons -destination 'platform=iOS,name=<device>' build
# Install on device via Xcode Run; for CI smoke on simulator (no Enclave, expect fail-closed):
xcodebuild -scheme Nedwons -destination 'platform=iOS Simulator,name=iPhone 16' build test
```

## Acceptance assertions (capture evidence, never expose secrets)

- [ ] A real iPhone **registers and logs in through the real Secure Enclave path** (`deviceAssurance == .hardware`).
- [ ] Correct **username + password from a *different* device cannot authenticate** (INV-2 on hardware) → server returns `401 denied`.
- [ ] **Replayed** signature (reuse a prior challenge) → denied.
- [ ] **Expired** challenge signature → denied.
- [ ] **Cross-action** signature (register transcript used for login, or vice-versa) → denied.
- [ ] **Cross-account / cross-device** signature (valid sig, wrong account/device id) → denied.
- [ ] Key is **non-exportable**: copying the Keychain blob to another device and calling `SecureEnclaveDeviceSigner(dataRepresentation:)` fails (blob is device-bound).
- [ ] Keychain item is **excluded from backup** (`ThisDeviceOnly`): confirm it is absent from an encrypted iTunes/Finder backup and from iCloud Keychain.
- [ ] **Background refresh works without a biometric prompt** (possession key has no user-presence ACL).
- [ ] Fail-closed: on a device/simulator **without a usable Secure Enclave**, `requireHardware` shows the clear explanation and **enrolls no key** (no silent software fallback).
- [ ] Software fallback, when explicitly enabled, is labeled **lower assurance** in the UI and recorded as such.
- [ ] *[Attest]* App Attest assertion is **bound to a server nonce and a hash of the exact request**; the server validates app id, environment, counter/freshness, challenge binding; a **replayed** assertion is rejected.
- [ ] *[Attest]* Production **never** accepts a development/simulator attestation; Apple-outage/key-loss/reinstall/suspected-clone policies behave as specified.

## Physical-device test matrix (run the assertions above under each condition)

| Condition | Notes |
|-----------|-------|
| Oldest supported iPhone + iOS | Confirm Enclave present or fail-closed path. |
| Current iPhone + iOS | Primary happy path. |
| Face ID device / Touch ID device | Local-unlock layer only; must not gate background refresh. |
| Device locked / unlocked | Refresh under lock; Keychain accessibility behaves. |
| Reboot **before first unlock** | Key/Keychain unavailable until first unlock — app degrades gracefully. |
| App background / foreground / **force-kill** | Session + enrolled key survive; login reloads same key. |
| Network change / **airplane mode** | Transport errors handled; no key loss. |
| **Passcode removed** then re-added | `ThisDeviceOnly` items may be purged when passcode is removed — verify the recovery path, not a crash. |
| **Biometric enrollment changed** | Possession key unaffected (no biometric ACL); local-unlock layer re-prompts. |
| App **uninstall / reinstall** | Keychain item policy on reinstall documented; expect re-register/recover. |
| **Backup / restore** or device migration | Enclave key does **not** transfer; user must re-enroll (ADR-0008 linked-device / recovery). |
| **TestFlight-signed** build + **production** App Attest env | *[Attest]* prod environment accepted; dev bypass rejected. |

## References

R-101 (on-device verification), R-301 (App Attest is advisory), R-G0-2 (app-layer signer wiring —
resolved), ADR-0002 (device binding), ADR-0008 (multi-device / recovery for legitimate device change).
