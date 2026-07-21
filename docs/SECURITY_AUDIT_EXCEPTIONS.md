# SCA advisory exceptions (cargo audit)

`cargo audit` scans **`Cargo.lock`**, which lists every crate the resolver *could* select —
including optional and other-target dependencies that are **not compiled** for our build. This
file documents every advisory we suppress in CI (`--ignore`), why, and when to revisit. Nothing
here is a silent dismissal: each entry states target-reachability and a removal trigger, and the
residual is tracked as **RISK_REGISTER R-505**.

**Build under assessment:** `aarch64-apple-darwin` (Apple Silicon), default features.
**Active MLS crypto provider:** the vendored `openmls_rust_crypto 0.5.1`
(`core/vendor/openmls_rust_crypto`, see its README) → HPKE via `hpke-rs-rust-crypto 0.7.0`
(RustCrypto backend, `experimental` feature). Application-message AEAD is RustCrypto
**`chacha20poly1305 0.10`**; the post-quantum KEM is **X-Wing** (X25519 + ML-KEM-768) via
RustCrypto's pure-Rust `x-wing` + `ml-kem 0.3` crates. Ciphersuite:
`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (ADR-0016 — hybrid post-quantum).

**Re-verify each entry with:** `cargo tree -i <crate>` (empty output ⇒ not compiled for this
target) and `cargo audit`. Review by **2027-01-20** or whenever `proc-macro-error2` gains a
maintained replacement upstream.

## Status: the libcrux advisories are RESOLVED (2026-07-20, ADR-0016)

The seven libcrux advisories previously listed here were **cleared by the post-quantum provider
upgrade**, not merely re-justified. Moving the HPKE stack to `hpke-rs 0.7.0` (to enable the X-Wing
hybrid KEM) advanced the entire transitive libcrux chain to advisory-fixed releases and dropped the
worst crate outright:

| Former advisory | Crate | How it was resolved |
|-----------------|-------|---------------------|
| RUSTSEC-2026-0207 | `libcrux-sha3` | Now **0.0.10** (was 0.0.8) — the fixed release. |
| RUSTSEC-2026-0208 | `libcrux-sha3` | Same — resolved by 0.0.10. |
| RUSTSEC-2026-0212 | `libcrux-secrets` | Now **0.0.6** (was 0.0.5) — the fixed release. |
| RUSTSEC-2026-0124 | `libcrux-chacha20poly1305` | Now **0.0.9** (was 0.0.7) — past the fixed version. |
| RUSTSEC-2026-0209 | `libcrux-aesgcm` | **Crate no longer in the graph** — `hpke-rs 0.7` does not pull it (`grep libcrux-aesgcm */Cargo.lock` ⇒ none). |
| RUSTSEC-2026-0210 | `libcrux-aesgcm` | Same — crate gone. |
| RUSTSEC-2026-0211 | `libcrux-aesgcm` | Same — crate gone. |

All three workspaces (`services`, `core/mls-core`, `core/mls-ffi`) now resolve the **same** libcrux
versions via the vendored provider patch, so `cargo audit` is clean of libcrux issues everywhere.
Verified by the full test matrix + fuzz smoke on the new provider (see ADR-0016).

> Note on method: this was done by upgrading to the **released** `hpke-rs 0.7.0` stack (which is
> written against the new libcrux chain and adds X-Wing), *not* by force-`[patch]`-bumping libcrux
> under the old `hpke-rs 0.6.1` — that mismatch was the hazard the previous version of this doc
> warned against, and it was avoided.

## Remaining exception — build-time only

| Advisory | Crate | Why suppressed |
|----------|-------|----------------|
| RUSTSEC-2026-0173 | `proc-macro-error2` 2.0.1 | Unmaintained **proc-macro** (compile-time) dependency, pulled transitively via the UniFFI/derive macro chain. No runtime code, no data path. Track for a maintained replacement upstream. |

## CI enforcement

`.github/workflows/ci.yml` runs `cargo audit` for **all three** workspaces (`services`,
`core/mls-core`, `core/mls-ffi`) with exactly one ignore (`RUSTSEC-2026-0173`). CI **fails on any
new advisory** not listed here — the exception set is deliberately explicit so a newly disclosed
issue is never swallowed. Keep this file and the CI ignore list identical.
