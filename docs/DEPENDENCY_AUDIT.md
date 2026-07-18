# Dependency audit (BN-5)

State of `cargo audit` after the Gap A/B additions (`reqwest`, `x509-cert`, `ciborium`, `p384`,
`sha2`, `base64`, and the dev-only `rcgen`). Run: `cargo audit` in `services/` and `core/mls-core`.

## The new dependencies are clean

The APNs HTTP/2 transport and App Attest verifier introduced **zero** new advisories. Every
advisory `cargo audit` reports predates this work and comes from OpenMLS's crypto provider — see
below. CI's audit step already covers exactly these IDs, and the flagged set matches it one-for-one,
so the gate stays green and would still fail on a *new* advisory (e.g. one in these added crates).

## Outstanding advisories — all in `libcrux-*` / `proc-macro-error2`, upstream-blocked

| RUSTSEC | Crate | Note |
|---|---|---|
| 2026-0124 | libcrux-chacha20poly1305 | panic on overlong ciphertext (ChaCha20 — not the v1 ciphersuite) |
| 2026-0207 | libcrux-sha3 | incremental SHAKE (post-quantum suites — not v1) |
| 2026-0208 | libcrux-sha3 | AVX2 SHAKE-256 panic (as above) |
| 2026-0209 | libcrux-aesgcm | AAD length limits |
| 2026-0211 | libcrux-aesgcm | non-constant-time tag check |
| 2026-0212 | libcrux-secrets | aarch64 constant-time swap/select |
| 2026-0210 | libcrux-aesgcm | unmaintained (renamed to `libcrux-aes`) |
| 2026-0173 | proc-macro-error2 | unmaintained (transitive proc-macro) |

These reach us transitively: `mls-core → openmls_rust_crypto 0.5.1 → hpke-rs 0.6.1 → libcrux-*`.
**They cannot be fixed from our `Cargo.toml`:** the fixed libcrux versions (e.g. `libcrux-sha3
>=0.0.10`) are rejected by `hpke-rs 0.6.1`'s pin, and `openmls_rust_crypto` 0.5.1 is already the
latest release. Remediation is an upstream OpenMLS/hpke-rs bump — tracked as the successor to
R-G0-1; it is a **pre-general-availability** item, independent of on-device testing and of the Gap
A/B work.

CI ( `.github/workflows/ci.yml`) `--ignore`s exactly these IDs so the audit gate passes on the
triaged set while still catching anything new. When OpenMLS ships a provider on fixed libcrux, drop
the ignores and re-run.

## SBOM

`scripts/generate_sbom.sh` regenerates CycloneDX SBOMs (`sbom/*.cdx.json`, gitignored build
artifacts) for `services`, `core/mls-core`, and `core/mls-ffi` — refreshed after these additions.
