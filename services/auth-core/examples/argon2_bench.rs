//! Argon2id cost benchmark (R-302). Run this ON PRODUCTION-CLASS HARDWARE to measure the real
//! per-hash time of the configured parameters, then tune `password::{MEMORY_KIB, ITERATIONS,
//! PARALLELISM}` so a hash costs the target (~0.25–0.5 s per OWASP) and record the chosen values.
//!
//!   cargo run --release -p auth-core --example argon2_bench [samples]
//!
//! It reports the configured params and the mean/min/max wall-clock per hash. Do NOT trust a
//! debug build's numbers — always use `--release`.

use std::time::Instant;

use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, PasswordHasher, Version};

fn main() {
    let samples: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);

    let params = auth_core::password::argon2_params();
    println!(
        "Argon2id params: memory = {} KiB ({:.1} MiB), iterations = {}, parallelism = {}",
        auth_core::password::MEMORY_KIB,
        auth_core::password::MEMORY_KIB as f64 / 1024.0,
        auth_core::password::ITERATIONS,
        auth_core::password::PARALLELISM,
    );
    if cfg!(debug_assertions) {
        eprintln!("WARNING: debug build — rerun with --release for meaningful numbers.");
    }

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let password = b"benchmark-passphrase-correct-horse";

    // Warm up (allocator / caches).
    let salt = SaltString::encode_b64(&[0u8; 16]).unwrap();
    let _ = argon2.hash_password(password, &salt).unwrap();

    let mut total = 0f64;
    let mut min = f64::MAX;
    let mut max = 0f64;
    for i in 0..samples {
        let salt = SaltString::encode_b64(&(i as u128).to_le_bytes()[..16]).unwrap();
        let start = Instant::now();
        let _ = argon2.hash_password(password, &salt).unwrap();
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        total += ms;
        min = min.min(ms);
        max = max.max(ms);
    }
    let mean = total / samples as f64;
    println!("samples: {samples}");
    println!("per hash: mean {mean:.1} ms  (min {min:.1} ms, max {max:.1} ms)");
    println!("target:   ~250–500 ms on production hardware; raise MEMORY_KIB/ITERATIONS if below.");
}
