# Secure Enclave + App Attest (#10, R-101 / R-G0-2)

Two independent hardware protections, and what is built vs. hardware-gated.

## Secure Enclave device key — DONE (software + real API)

`SecureEnclaveDeviceSigner` (`apps/ios/NedwonsKit/Sources/NedwonsKit/DeviceSigner.swift`) generates
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
  `AppAttestTests`. Client methods `NedwonsClient.attestChallenge` / `submitAttestation`.
- Server: `GET /v1/attest/challenge` issues a single-use 32-byte challenge (5-min TTL);
  `POST /v1/attest/key` consumes it (anti-replay) and stores the submitted attestation bound to the
  device. Migration `V20`; proven by `services/api/tests/app_attest.rs` (challenge → submit →
  stored-unverified; a consumed or wrong challenge is refused).

**Cryptographic verification — DONE (`services/api/src/attest.rs`).** A submitted attestation object
is fully verified server-side per Apple's spec:

1. **Certificate chain** — the `x5c` chain (credential cert → intermediate) verifies up to the
   **pinned Apple App Attestation Root CA** (fetched from Apple's CA page and embedded as
   `apple_app_attest_root.pem`; SHA-256 fingerprint `1CB9823B…42C932`, valid to 2045), with
   validity-window checks. ECDSA P-256/P-384 (SHA-256/384) via vetted RustCrypto crates
   (`x509-cert`, `p256`, `p384`, `ciborium`, `sha2`).
2. **Nonce** — `SHA-256(authData ‖ clientDataHash)` must equal the credential cert's Apple nonce
   extension (OID `1.2.840.113635.100.8.2`), binding the attestation to the server's single-use
   challenge. (`clientDataHash = SHA-256(challenge)`, matching the client's `attestKey`.)
3. **Key id** = `SHA-256(credential public key)` and the authData `credentialId`.
4. **authData** — RP ID hash = `SHA-256(app_id)`, counter `0`, aaguid = `appattest` (production;
   `appattestdevelop` only when explicitly allowed).

Wired into `POST /v1/attest/key`: when `NEDWONS_APP_ATTEST_APP_ID` is set, a failed verification is
**rejected** and a passing one stores `verified=true`; unconfigured deployments store `verified=false`
(bootstrap). Config: `NEDWONS_APP_ATTEST_APP_ID` (`TeamID.bundle-id`), optional
`NEDWONS_APP_ATTEST_ROOT_PEM` override, `NEDWONS_APP_ATTEST_DEV` to accept development builds.

**Proven without hardware:** `services/api/tests/attest_verify.rs` mints a synthetic chain (test
root → intermediate → credential cert with the real Apple nonce-extension shape) via `rcgen` and a
well-formed CBOR object, then checks the happy path **and** every tamper — wrong/spliced nonce, wrong
challenge, wrong key id, wrong app id, non-zero counter, development aaguid, a chain to a *different*
root, garbage/wrong-format CBOR — each rejected with the right typed error. An in-module test asserts
the embedded pin really is Apple's P-384 root.

**Still hardware-gated (honest limit):** *producing* an attestation requires a **physical iOS
device** + the App Attest entitlement + Apple provisioning — the Simulator cannot. The verifier is
complete and tested; feed it a real device attestation and it runs unchanged against the Apple root.
