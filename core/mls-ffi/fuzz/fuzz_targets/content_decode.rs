#![no_main]
//! Fuzz the **content-envelope decode** boundary (Secret Message feature).
//!
//! After MLS decrypts an application message, its plaintext is a `Content` envelope decoded from
//! attacker-influenceable bytes (a hostile group member controls what it encrypts). `Content::decode`
//! must therefore treat its input as untrusted: the invariant is that it **never panics** and only
//! ever returns a typed, redacted `ContentError`. A crash/abort here is a finding. The deterministic
//! sibling `content::tests::decode_never_panics_on_arbitrary_prefixes` runs on stable CI.

use libfuzzer_sys::fuzz_target;
use mls_core::content::Content;

fuzz_target!(|data: &[u8]| {
    // Never panics; a successful decode must round-trip back to the same bytes.
    if let Ok(content) = Content::decode(data) {
        let re = content.encode();
        assert_eq!(re, data, "decode∘encode must be the identity on accepted input");
    }
});
