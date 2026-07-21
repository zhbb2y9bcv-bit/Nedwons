# Rust Crypto Backend (vendored + PQ-patched)

> **Nedwons vendoring notice.** This is `openmls_rust_crypto 0.5.1` from crates.io
> (github.com/openmls/openmls, MIT), vendored via `[patch.crates-io]` in the `core/mls-core` and
> `core/mls-ffi` workspaces with exactly three deliberate changes — nothing else is modified:
>
> 1. **`src/provider.rs` `kem_mode`**: the `HpkeKemType::XWingKemDraft6` arm, left
>    `unimplemented!()` upstream, now maps to `KemAlgorithm::XWingDraft06` (code point 0x647a) —
>    the X-Wing hybrid post-quantum KEM (X25519 + ML-KEM-768).
> 2. **`src/provider.rs` `supports`/`supported_ciphersuites`**: advertise
>    `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (0x004D).
> 3. **`Cargo.toml`**: `hpke-rs*` lifted 0.6.0 → 0.7.0 with the backend's `experimental` feature,
>    whose rust-crypto backend implements X-Wing via RustCrypto's pure-Rust `x-wing` + `ml-kem`
>    crates (libcrux stays off the executed KEM path). Side effect: the transitively pinned
>    `libcrux-sha3`/`libcrux-secrets` move to their RUSTSEC-fixed releases (0.0.10 / 0.0.6),
>    clearing every libcrux advisory from the build graph (see docs/SECURITY_AUDIT_EXCEPTIONS.md).
>
> Every change is marked with a `PQ patch (Nedwons)` comment. To re-verify this diff:
> `diff -r <crates.io 0.5.1 source> .` — expected drift is the three items above plus this notice.
> Retire this vendored copy when an upstream provider release supports X-Wing directly.

This crate implements the [OpenMLS traits](../traits/README.md) using the following rust crates: [hkdf], [hpke-rs], [sha2], [p256], [p384], [x25519-dalek], [ed25519-dalek] [chacha20poly1305], [aes-gcm].

[hkdf]: https://docs.rs/hkdf
[hpke-rs]: https://docs.rs/hpke-rs
[sha2]: https://docs.rs/sha2
[p256]: https://docs.rs/p256
[p384]: https://docs.rs/p384
[x25519-dalek]: https://docs.rs/x25519-dalek
[ed25519-dalek]: https://docs.rs/ed25519-dalek
[chacha20poly1305]: https://docs.rs/chacha20poly1305
[aes-gcm]: https://docs.rs/aes-gcm
