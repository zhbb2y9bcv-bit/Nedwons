//! Reads three hex lines (public key, message, signature) from stdin and verifies the
//! signature with the backend's own `verify_p256`. Paired with the Swift `InteropEmit`
//! tool, this proves the iOS client's ECDSA-P256 signatures over the canonical transcript
//! are accepted by the server. Prints `INTEROP_OK` (exit 0) or `INTEROP_FAIL` (exit 1).

use std::io::Read;

use auth_core::crypto::verify_p256;

fn main() {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        eprintln!("verify_interop: failed to read stdin");
        std::process::exit(2);
    }
    let lines: Vec<&str> = input
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.len() < 3 {
        eprintln!(
            "verify_interop: expected 3 non-empty hex lines, got {}",
            lines.len()
        );
        std::process::exit(2);
    }

    let public_key = hex_decode(lines[0]).expect("valid hex public key");
    let message = hex_decode(lines[1]).expect("valid hex message");
    let signature = hex_decode(lines[2]).expect("valid hex signature");

    if verify_p256(&public_key, &message, &signature) {
        println!("INTEROP_OK");
    } else {
        println!("INTEROP_FAIL");
        std::process::exit(1);
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)? as u8;
        let lo = (bytes[i + 1] as char).to_digit(16)? as u8;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}
