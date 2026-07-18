# mls-ffi fuzzing

Continuous fuzzing of the FFI's inbound-envelope decode boundary — the primary place hostile bytes
from the network reach the MLS core (ADR-0007 Phase 4).

## Target

- **`envelope`** — feeds arbitrary bytes to `MlsClient::process_inbound` on a real joined client.
  **Invariant:** it must only ever return a typed `MlsClientError`; a panic/abort/ASAN report is a
  finding.

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
