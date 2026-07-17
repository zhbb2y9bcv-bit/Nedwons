# Sentinel iOS app

Native SwiftUI app for iPhone/iPad. **Requires Xcode 26 + iOS 26 SDK** — Apple's mandated
minimum for App Store uploads since 2026-04-28 (verified 2026-07-17). This machine has
Xcode 26.6.

## What is verified vs. what needs Xcode

| Part | How it builds/tests | Status |
|------|---------------------|--------|
| `SentinelKit/` (crypto/protocol, Keychain, device signer, HTTP client) | `swift build` / `swift test` (macOS) | ✅ builds + 7 tests pass here |
| `SentinelUI/` (design tokens, components, app screens) | `swift build` (macOS) | ✅ builds here |
| Cross-language transcript vector + signature | `swift test` + Rust pipeline | ✅ INTEROP_OK |
| **`SentinelClient` ↔ live backend** (register/login/whoami over HTTP) | `scripts/swift_backend_smoke.sh` | ✅ **SMOKE_OK** against the real Rust server + Postgres, incl. INV-2 negative check |
| `Sentinel/` app target (`@main`, App Attest, APNs, entitlements) | Xcode app target | ⚠️ requires Xcode; not built in this environment (RISK_REGISTER R-101) |
| On-device MLS (UniFFI binding of `mls-core`) | Xcode + rust ios targets | ⚠️ planned (ADR-0007, R-101) |

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

## Talking to the backend (already wired and verified)

`SentinelClient` (in SentinelKit) performs the full auth flow over HTTP. It is verified
end-to-end against the real Rust server by `scripts/swift_backend_smoke.sh` (register → whoami
→ login → whoami, plus the INV-2 check that a *different* device cannot log in). On device you
pass a `SecureEnclaveDeviceSigner` instead of the software signer:

```swift
// First run: enroll this device with a non-exportable Secure Enclave key.
let signer = try SecureEnclaveDeviceSigner()            // generates the P-256 key in the Enclave
let client = SentinelClient(baseURL: backendURL)
let session = try await client.register(username: name, password: pass, signer: signer)

// Persist ONLY the encrypted key blob + tokens (never the private key, never the password):
let keychain = KeychainStore(service: "app.sentinel.ios")
try keychain.save(signer.dataRepresentation, account: "device-key")   // ThisDeviceOnly
try keychain.save(Data(session.refreshToken.utf8), account: "refresh-token")

// Later launches: reload the same Enclave key and log in.
let blob = try keychain.load(account: "device-key")!
let signer2 = try SecureEnclaveDeviceSigner(dataRepresentation: blob)
let s = try await client.login(username: name, password: pass, signer: signer2)
```

- Transcripts are built with `ClientTranscripts` and are byte-compatible with the server
  (enforced by the shared vectors in `contracts/test-vectors/`).
- App Attest assertions accompany enrollment as a **risk signal only** — the mandatory control
  is the device-key signature.
- For messaging, the app calls the relay endpoints (contracts/API.md) with envelopes produced
  by the MLS core via its UniFFI binding (ADR-0007).

## What is deliberately not here yet

Real networking, App Attest wiring, notification handling, and the post-enrollment message
UI are Milestone 1–2 work. Network-dependent controls in the scaffold are **disabled with an
explanation** (see `FeatureFlags`), never shown as dead buttons.
