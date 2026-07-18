// Library-mode UniFFI binding generator (ADR-0007). Invoked as:
//   cargo run --bin uniffi-bindgen generate --library <path-to-libmls_ffi> --language swift ...
// Generating from the built library (not a UDL file) means the bindings can only ever describe the
// surface the library actually exports — they cannot drift out of sync with the Rust code.
fn main() {
    uniffi::uniffi_bindgen_main()
}
