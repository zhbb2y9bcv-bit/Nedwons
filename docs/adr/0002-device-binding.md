# ADR-0002: Hardware-backed device binding replaces MAC-address login

- **Status:** Accepted
- **Date:** 2026-07-17
- **Deciders:** security architect, iOS lead
- **Sources accessed 2026-07-17:** Apple Secure Enclave key protection docs; Apple App Attest
  docs; Android unique-identifier guidance (for the general principle that platforms randomize
  MAC and restrict hardware IDs).

## Context

The original product idea was to lock an account to the creator's **MAC address**. This is
invalid:

- Normal third-party iOS apps cannot reliably read the physical Wi-Fi/Bluetooth MAC address.
- Modern platforms **randomize** MAC addresses for privacy; the value changes by network.
- A MAC address is **not a secret** — it can be observed and spoofed where visible.
- Persistent hardware identifiers create tracking and App Store policy risk.

We must not collect, fingerprint, hash, transmit, or use a MAC address, IMEI, advertising ID,
serial number, or any persistent hardware identifier for login.

## Decision

Bind accounts to a **non-exportable P-256 key generated in the Secure Enclave** and prove
device possession with a **challenge–response signature over a canonical, domain-separated
transcript** (see CRYPTOGRAPHY.md §4). Concretely:

- **Registration:** server issues a single-use, short-lived, transaction/action/version-bound
  challenge; the device generates the Enclave key and signs the enrollment transcript; the
  server stores only the **public** key + metadata; App Attest is attached as defense-in-depth.
- **Login (two-stage):** username/password verification (enumeration-resistant) **and** a
  fresh challenge signed by the enrolled private key. Username + password alone never create
  a session.
- **Sessions** are proof-of-possession: short-lived access token + rotating opaque refresh
  token (server stores only hashes); refresh and sensitive ops require a device-key signature
  so a stolen bearer token is insufficient.

## Consequences

**Positive:** the authentication factor is a real hardware-protected secret, not an
observable identifier; no tracking/policy risk; achieves the original intent ("only the
enrolling device") *correctly*.

**Negative / handled elsewhere:**
- A second device with the correct password is **intentionally denied** — legitimate device
  change needs the recovery model (ADR-0003) so users are not silently locked out.
- Devices without the required hardware need a documented fallback/denial policy — never a
  silent downgrade. *(R-101 verifies on-device behavior.)*
- App Attest is a bypassable **risk signal only**, never a substitute for the device-key
  signature. *(R-301)*

## Tested today

`services/auth-core` proves the core invariant in software: a valid credential pair with no
valid device-key signature cannot produce a session, and challenges are single-use,
expiring, and action/account/device-bound. On-device Secure Enclave behavior is pending an
Xcode/device run (R-101).
