# mls-ffi fuzzing

Continuous fuzzing of the FFI's inbound-envelope decode boundary — the primary place hostile bytes
from the network reach the MLS core (ADR-0007 Phase 4).

## Targets

- **`envelope`** — feeds arbitrary bytes to `MlsClient::process_inbound` on a real joined client.
  **Invariant:** it must only ever return a typed `MlsClientError`; a panic/abort/ASAN report is a
  finding.
- **`content_decode`** — fuzzes `mls_core::content::Content::decode` (the application-content
  envelope inside the MLS plaintext, incl. secret-message classification). **Invariant:** never
  panics, and any accepted input round-trips (`encode∘decode == identity`). Last run: **4,360,999
  runs / ~41 s, no crashes.**
- **`secret_state`** — structure-aware (`arbitrary`-derived) fuzzer of the secret-message reveal
  **state machine**: arbitrary sequences of begin/poll/visible/remaining/consume with hostile
  `now_ms` values. **Invariants:** no panic; the clock never rewinds; plaintext only while
  `Visible`; `Consumed` is terminal + body scrubbed. **Found a real bug** — a `now_ms` near
  `u64::MAX` overflow-panicked in `begin_reveal`; fixed with saturating arithmetic (regression:
  `secret::tests::extreme_now_does_not_overflow_and_fails_closed`). Last run after the fix:
  **4,242,791 runs / ~56 s, no crashes.**

## Running (requires nightly + libFuzzer)

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run envelope -- -max_total_time=60
```

`fuzz/corpus/envelope/` holds a small committed seed corpus; libFuzzer grows a local corpus as it
runs (that growth is gitignored — only curated seeds are committed).

## Status

Last local smoke: **1,359,509 runs / ~31 s, no crashes** (Apple Silicon, nightly 1.99). This is a
bounded smoke, not exhaustive fuzzing — wire this target into a scheduled nightly CI job for real
coverage. On stable (no libFuzzer), the deterministic sibling test
`tests/adversarial.rs::malformed_envelopes_yield_typed_errors_never_panic` provides a fixed 4000+
input smoke of the same invariant.

## Not yet fuzzed (follow-ups)

- `add_member` (key-package decode) and `join_group` (Welcome decode) boundaries — add sibling
  targets.
- Structure-aware fuzzing (an `arbitrary`-derived envelope grammar) to reach deeper past the TLS
  decode.
