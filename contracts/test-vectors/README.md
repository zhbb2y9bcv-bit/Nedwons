# Shared test vectors

These vectors pin the wire-level encodings that MUST be identical across the Rust backend
(`services/auth-core`) and the iOS Swift client (`apps/ios/NedwonsKit`). They exist so a
divergence — which would silently break signature verification — is caught by a failing
test on both sides rather than in production.

## `auth-transcript-login.hex`

The canonical authentication transcript (CRYPTOGRAPHY.md §4) for a fixed `Login` input:

| Field | Value |
|-------|-------|
| domain | `app.nedwons.auth.v1` |
| protocol version | 1 |
| action | Login (2) |
| account_id | `00112233445566778899aabbccddeeff` |
| device_id | `0102030405060708090a0b0c0d0e0f10` |
| public_key | `04` ‖ bytes `00..3f` (65 bytes) |
| challenge | bytes `00..1f` (32 bytes) |
| expires_at | 1_000_000_000 |
| txn_id | `f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff` |

Pinned by:
- Rust: `services/auth-core` → `transcript::tests::login_transcript_golden_vector`.
- Swift: `apps/ios/NedwonsKit` → `AuthTranscriptTests.matchesSharedVector`.

Regenerate with `cargo run -p auth-core --example transcript_vector`. Any change here is a
wire-breaking change and requires a protocol-version bump.
