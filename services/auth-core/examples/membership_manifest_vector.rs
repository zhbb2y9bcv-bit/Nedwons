use auth_core::ids::{AccountId, DeviceId};
use auth_core::membership::{ControlType, Manifest};
fn main() {
    let added = [(AccountId([0xAAu8; 16]), DeviceId([0xBBu8; 16]))];
    let bytes = Manifest {
        control: ControlType::Add,
        group_id: &[7u8; 16],
        prev_epoch: 4,
        next_epoch: 5,
        commit_hash: &[9u8; 32],
        actor_device: &DeviceId([1u8; 16]),
        added: &added,
        removed: &[],
        idempotency_key: &[2u8; 16],
        expires_at: 1000,
    }
    .encode();
    println!(
        "{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
}
