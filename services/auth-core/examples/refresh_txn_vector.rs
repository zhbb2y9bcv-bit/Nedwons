//! Prints the deterministic refresh transaction id for a fixed token, so the iOS client's
//! `ClientTranscripts.refreshTxnID` can be pinned to the same value.
//! Run: `cargo run -p auth-core --example refresh_txn_vector`.

use auth_core::crypto::sha256;
use auth_core::refresh_txn_id;

fn main() {
    let token: Vec<u8> = (0xA0u8..0xC0).collect(); // 32 bytes 0xA0..0xBF
    let token_hash = sha256(&token);
    let txn = refresh_txn_id(&token_hash);
    let hex: String = txn.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    println!("{hex}");
}
