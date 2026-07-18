# Secure Enclave + App Attest (#10, R-101 / R-G0-2)

Two independent hardware protections, and what is built vs. hardware-gated.

## Secure Enclave device key — DONE (software + real API)

`SecureEnclaveDeviceSigner` (`apps/ios/SentinelKit/Sources/SentinelKit/DeviceSigner.swift`) generates
a **non-exportable** P-256 key inside the Secure Enclave (`SecureEnclave.P256.Signing.PrivateKey`);
only an encrypted, device-bound blob is persisted (Keychain, `ThisDeviceOnly`). `DeviceIdentity`
provisions it and **fails closed** — a device without a usable Enclave does not silently downgrade;
the software fallback is a distinct, recorded, lower assurance level. This is the enrolled
proof-of-possession key (INV-2/INV-3). The remaining hardware upgrade is binding the **at-rest root
key** (#5) to the Enclave so it cannot be extracted even with an unlocked Keychain.

## App Attest — built + wired; verification + live path hardware-gated

App Attest proves the running client is a **genuine, unmodified build of this app on real Apple
hardware** — distinct from the device key (which proves key possession). It defends against
emulators and tampered builds.

**Built and tested:**

- Client: `AppAttestation` (`AppAttest.swift`) wraps `DCAppAttestService` —
  `isSupported` / `generateKey` / `attestKey(challenge)` / `generateAssertion`. It **fails closed**
  off real hardware (`.unsupported` on Simulator / macOS / a compromised device), asserted by
  `AppAttestTests`. Client methods `SentinelClient.attestChallenge` / `submitAttestation`.
- Server: `GET /v1/attest/challenge` issues a single-use 32-byte challenge (5-min TTL);
  `POST /v1/attest/key` consumes it (anti-replay) and stores the submitted attestation bound to the
  device. Migration `V20`; proven by `services/api/tests/app_attest.rs` (challenge → submit →
  stored-unverified; a consumed or wrong challenge is refused).

**Hardware-gated (honest limits):**

1. **Cryptographic verification** of the attestation object — CBOR decode, the X.509 chain to
   Apple's App Attest root, the nonce (`clientDataHash`) and app-id / counter checks — is not yet
   implemented; the stored row's `verified` flag stays `false` until it is. (It is a self-contained
   backend task; it does not need hardware to *write*, but is untestable end-to-end without a real
   attestation from a device.)
2. **Live attestation** requires a **physical iOS device** + the app's App Attest entitlement +
   Apple Developer provisioning. The Simulator cannot produce attestations. This is the same
   hardware gate as observing real Secure Enclave key custody.
