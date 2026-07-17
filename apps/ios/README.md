# Sentinel iOS app

Native SwiftUI app for iPhone/iPad. **Requires Xcode 26 + iOS 26 SDK** — Apple's mandated
minimum for App Store uploads since 2026-04-28 (verified 2026-07-17). This machine has
Xcode 26.6.

## What is verified vs. what needs Xcode

| Part | How it builds/tests | Status |
|------|---------------------|--------|
| `SentinelKit/` (crypto/protocol, Keychain, device signer) | `swift build` / `swift test` (macOS) | ✅ builds + 6 tests pass here |
| `SentinelUI/` (design tokens, components, app screens) | `swift build` (macOS) | ✅ builds here |
| Cross-language transcript vector + signature | `swift test` + Rust pipeline | ✅ INTEROP_OK |
| `Sentinel/` app target (`@main`, App Attest, APNs, entitlements) | Xcode app target | ⚠️ requires Xcode; not built in this environment (RISK_REGISTER R-101) |

The app target is intentionally **not** shipped as a hand-written `.xcodeproj` (an unverified
project file is worse than none). Create it in Xcode as below; all source and config it needs
is here.

## Creating the app target in Xcode

1. **File ▸ New ▸ Project ▸ iOS ▸ App.** Name `Sentinel`, bundle id `app.sentinel.ios`,
   interface **SwiftUI**, language **Swift**. Set the deployment target and build against the
   **iOS 26 SDK**.
2. Delete the generated `ContentView.swift`/`App.swift`; add `apps/ios/Sentinel/SentinelApp.swift`.
3. **Add the local package:** File ▸ Add Package Dependencies ▸ Add Local ▸ select
   `apps/ios/SentinelKit`. Link the **SentinelKit** and **SentinelUI** library products to
   the app target.
4. Add `PrivacyInfo.xcprivacy` to the app target (Copy Bundle Resources).
5. Set the app's **entitlements** file to `Sentinel.entitlements`. Enable the **App Attest**
   and **Push Notifications** capabilities. Keep App Attest as defense-in-depth only.
6. Add the permission purpose strings from `Info-additions.plist` to the target's Info.plist.
7. Build to a simulator/device. Enable the iOS build+test step in `.github/workflows/ci.yml`.

## Security integration points (Milestone 1 completion)

- `SecureEnclaveDeviceSigner` (in SentinelKit) generates the non-exportable P-256 device key.
  Persist only its encrypted `dataRepresentation` via `KeychainStore`
  (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`).
- Build register/login/refresh transcripts with `ClientTranscripts`, sign with the enclave
  signer, and send to the backend. Byte-compatibility with the server is enforced by the
  shared vectors (`contracts/test-vectors/`).
- App Attest assertions accompany enrollment as a risk signal only — the mandatory control is
  the device-key signature.

## What is deliberately not here yet

Real networking, App Attest wiring, notification handling, and the post-enrollment message
UI are Milestone 1–2 work. Network-dependent controls in the scaffold are **disabled with an
explanation** (see `FeatureFlags`), never shown as dead buttons.
