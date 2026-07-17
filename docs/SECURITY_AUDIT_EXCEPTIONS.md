# SCA advisory exceptions (cargo audit)

`cargo audit` scans **`Cargo.lock`**, which lists every crate the resolver *could* select —
including optional and other-target dependencies that are **not compiled** for our build. This
file documents every advisory we suppress in CI (`--ignore`), why, and when to revisit. Nothing
here is a silent dismissal: each entry states target-reachability and a removal trigger, and the
residual is tracked as **RISK_REGISTER R-505**.

**Build under assessment:** `aarch64-apple-darwin` (Apple Silicon), default features.
**Active MLS crypto provider:** `openmls_rust_crypto 0.5.1` → HPKE via `hpke-rs-rust-crypto 0.6.1`
(RustCrypto backend). Application-message AEAD is RustCrypto **`aes-gcm 0.10.3`** — verified with
`cargo tree -i aes-gcm`. Ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
(AES-128-GCM, HKDF-SHA256, X25519, Ed25519 — **no SHAKE/SHA-3, no ChaCha20, no libcrux AES-GCM**).

**Re-verify each entry with:** `cargo tree -i <crate>` (empty output ⇒ not compiled for this
target) and `cargo audit`. Review by **2026-10-17** or whenever `openmls_rust_crypto` / `hpke-rs`
publish a release that moves off the pinned libcrux `0.0.8`.

## Category A — not compiled for our target (false positives)

`hpke-rs` exposes `libcrux` and `rustcrypto` HPKE backends as **optional** features; our provider
selects `rustcrypto`. The libcrux AEAD crates below are therefore in `Cargo.lock` but **not built**
(`cargo tree -i` returns "nothing to print").

| Advisory | Crate | Why suppressed |
|----------|-------|----------------|
| RUSTSEC-2026-0211 | `libcrux-aesgcm` 0.0.7 | Non-constant-time AES-GCM tag check. **Not compiled** — our AES-GCM is RustCrypto `aes-gcm`, not libcrux. HPKE AEAD is `hpke-rs-rust-crypto`. |
| RUSTSEC-2026-0209 | `libcrux-aesgcm` 0.0.7 | AES-GCM AAD-length limit. Same: `libcrux-aesgcm` not in the build graph. |
| RUSTSEC-2026-0210 | `libcrux-aesgcm` 0.0.7 | Crate renamed/unmaintained. Not compiled. |
| RUSTSEC-2026-0124 | `libcrux-chacha20poly1305` 0.0.7 | Overlong-ciphertext panic. Not compiled; our ciphersuite has no ChaCha20-Poly1305 and the libcrux AEAD backend is disabled. |

> If a future ciphersuite selects ChaCha20-Poly1305, or a provider change enables `hpke-rs`'s
> `libcrux` backend, **remove these three ignores** and re-assess — they would then be reachable.

## Category B — compiled, but vulnerable code path not invoked; no upstream fix reachable (ACCEPTED, tracked R-505)

`hpke-rs 0.6.1` depends on `libcrux-sha3 0.0.8` **unconditionally** (which pulls
`libcrux-secrets 0.0.5`). These crates *are* compiled. The fixes exist upstream
(`libcrux-sha3 ≥ 0.0.10`, `libcrux-secrets ≥ 0.0.6`) but are **unreachable**: `hpke-rs 0.6.1` pins
`libcrux-sha3 = "^0.0.8"` (a `0.0.x` bump is semver-breaking under Cargo), and `openmls_rust_crypto
0.5.1` is the latest release and requires `hpke = "^0.6.0"`. There is no released dependency
combination that clears them today.

| Advisory | Crate | Reachability on our path | Removal trigger |
|----------|-------|--------------------------|-----------------|
| RUSTSEC-2026-0207 | `libcrux-sha3` 0.0.8 | Incorrect **incremental SHAKE** output on multiple squeezes. Our ciphersuite uses **SHA-256/HKDF-SHA256**, not SHAKE — the incremental SHAKE API is never called. | `hpke-rs`/`openmls_rust_crypto` release depending on `libcrux-sha3 ≥ 0.0.10`. |
| RUSTSEC-2026-0208 | `libcrux-sha3` 0.0.8 | Panic in **AVX2 SHAKE-256**. Same: no SHAKE on our path. | same as above |
| RUSTSEC-2026-0212 | `libcrux-secrets` 0.0.5 | Incorrect constant-time swap/select on **Aarch64**. Pulled transitively by `libcrux-sha3`; exercised only by libcrux SHA-3/SHAKE routines, which we do not invoke. | `libcrux-secrets ≥ 0.0.6` reachable via an updated `hpke-rs`. |

> These are **accepted, not dismissed**: they are compiled into the binary. The reachability
> argument (no SHAKE on the active ciphersuite) is the mitigation, and R-505 stays OPEN until the
> upstream pin is lifted. Do **not** add a `[patch.crates-io]` override to force-bump libcrux —
> `0.0.8 → 0.0.10` is an API-breaking change `hpke-rs 0.6.1` was not written against, so it would
> not compile and could silently alter crypto behavior.

## Category C — build-time only

| Advisory | Crate | Why suppressed |
|----------|-------|----------------|
| RUSTSEC-2026-0173 | `proc-macro-error2` 2.0.1 | Unmaintained **proc-macro** (compile-time) dependency. No runtime code, no data path. Track for a maintained replacement upstream. |

## CI enforcement

`.github/workflows/ci.yml` runs `cargo audit` for **both** workspaces (`services`, `core/mls-core`)
with exactly the ignores above. CI **fails on any new advisory** not listed here — the exception
set is deliberately explicit so a newly disclosed issue is never swallowed.
