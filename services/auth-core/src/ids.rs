//! Typed identifiers. Internal identity is a random 16-byte value that is *never* derived
//! from a hardware identifier (ADR-0002) and is separate from the changeable public
//! username (ABUSE_MODEL.md).

use crate::crypto::random_bytes;

macro_rules! byte_id {
    ($(#[$m:meta])* $name:ident, $len:literal) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            /// Generate a fresh random id from the platform CSPRNG.
            pub fn random() -> Self {
                Self(random_bytes::<$len>())
            }
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                // Show only a short prefix in debug output; ids are not secrets but we avoid
                // dumping full identifiers into logs by habit.
                write!(f, "{}({:02x}{:02x}…)", stringify!($name), self.0[0], self.0[1])
            }
        }
    };
}

byte_id!(
    /// Immutable random internal account identifier.
    AccountId, 16
);
byte_id!(
    /// Random device-record identifier assigned at enrollment.
    DeviceId, 16
);
byte_id!(
    /// Per-transaction identifier that also keys a challenge.
    TxnId, 16
);
byte_id!(
    /// Refresh-token family identifier (reuse-detection lineage).
    FamilyId, 16
);
