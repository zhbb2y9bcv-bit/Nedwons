//! Prints the canonical auth-transcript for a fixed input as hex. This is the shared
//! cross-platform test vector: the iOS Swift client must produce byte-identical output.
//! Regenerate with: `cargo run -p auth-core --example transcript_vector`.

use auth_core::ids::{AccountId, DeviceId, TxnId};
use auth_core::transcript::{Action, Transcript};

fn main() {
    let account_id = AccountId([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ]);
    let device_id = DeviceId([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ]);
    let txn_id = TxnId([
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
        0xff,
    ]);
    // Fixed 65-byte uncompressed-SEC1-shaped public key (0x04 || 64 bytes 0x00..0x3f).
    let mut public_key = vec![0x04u8];
    public_key.extend(0u8..64);
    // Fixed 32-byte challenge 0x00..0x1f.
    let challenge: Vec<u8> = (0u8..32).collect();

    let transcript = Transcript {
        action: Action::Login,
        account_id: &account_id,
        device_id: &device_id,
        public_key: &public_key,
        challenge: &challenge,
        expires_at: 1_000_000_000,
        txn_id: &txn_id,
    };

    let bytes = transcript.encode();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    println!("{hex}");
}
