#![no_main]
//! Fuzz the inbound-envelope decode boundary of the FFI surface (ADR-0007 Phase 4).
//!
//! `process_inbound` is the primary place hostile bytes enter the MLS core from the network. This
//! target feeds arbitrary bytes as an envelope to a real joined client; the invariant is that it
//! **never panics** — it may only ever return a typed `MlsClientError`. A crash/abort here is a
//! finding. (The bounded, deterministic sibling `malformed_envelopes_yield_typed_errors_never_panic`
//! test runs on stable CI; this target is for continuous fuzzing on a nightly runner.)

use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use std::sync::Arc;

use mls_ffi::MlsClient;

/// One real, joined client, built once and reused. Failing inputs never advance its state, so id 0
/// can be reused indefinitely without unbounded growth.
static BOB: Lazy<Arc<MlsClient>> = Lazy::new(|| {
    let key = vec![3u8; 32];
    let dir = std::env::temp_dir();
    let apath = dir
        .join(format!("mls-fuzz-alice-{}", std::process::id()))
        .to_string_lossy()
        .into_owned();
    let bpath = dir
        .join(format!("mls-fuzz-bob-{}", std::process::id()))
        .to_string_lossy()
        .into_owned();
    let alice = MlsClient::create_group(b"alice".to_vec(), apath, key.clone()).unwrap();
    let bob = MlsClient::new_joiner(b"bob".to_vec(), bpath, key).unwrap();
    let add = alice.add_member(bob.key_package().unwrap()).unwrap();
    bob.join_group(add.welcome).unwrap();
    bob
});

fuzz_target!(|data: &[u8]| {
    // Must return a typed Result and never panic across the (would-be) FFI boundary.
    let _ = BOB.process_inbound(0, data.to_vec());
});
