import Foundation

/// The kind of membership change a manifest describes (ADR-0010). Raw values match
/// `auth_core::membership::ControlType`.
public enum MembershipControl: UInt8, Sendable {
    case add = 1
    case remove = 2
    case leave = 3
}

/// The canonical, domain-separated **membership manifest** (ADR-0010, R-506) — the Swift encoder
/// that must reproduce `auth_core::membership::Manifest::encode` **byte-for-byte** (proven against
/// the shared vector `contracts/test-vectors/membership-manifest-add.hex`). The device signs these
/// bytes; the MLS-blind relay verifies the signature; recipients verify commit↔manifest
/// correspondence.
public struct MembershipManifest: Sendable {
    public let control: MembershipControl
    public let groupID: Data  // 16 bytes
    public let prevEpoch: UInt64
    public let nextEpoch: UInt64
    public let commitHash: Data  // 32 bytes (SHA-256 of the opaque commit)
    public let actorDevice: Data  // 16 bytes
    /// Sorted, duplicate-free (account, device) pairs; empty unless `.add`.
    public let added: [(account: Data, device: Data)]
    /// Sorted, duplicate-free device ids; empty unless `.remove`/`.leave`.
    public let removed: [Data]
    public let idempotencyKey: Data  // 16 bytes
    public let expiresAt: UInt64

    public init(
        control: MembershipControl,
        groupID: Data,
        prevEpoch: UInt64,
        nextEpoch: UInt64,
        commitHash: Data,
        actorDevice: Data,
        added: [(account: Data, device: Data)],
        removed: [Data],
        idempotencyKey: Data,
        expiresAt: UInt64
    ) {
        self.control = control
        self.groupID = groupID
        self.prevEpoch = prevEpoch
        self.nextEpoch = nextEpoch
        self.commitHash = commitHash
        self.actorDevice = actorDevice
        self.added = added
        self.removed = removed
        self.idempotencyKey = idempotencyKey
        self.expiresAt = expiresAt
    }

    /// Domain-separation tag (versioned). Matches `auth_core::membership::DOMAIN`.
    static let domain = Data("app.nedwons.membership.v1".utf8)

    /// The canonical byte string that is signed and hashed. Injective: every variable field is
    /// length-prefixed (u32 BE) and lists are count-prefixed, so distinct field vectors never
    /// collide — identical to the Rust encoder.
    public func canonicalBytes() -> Data {
        var out = Data()
        Self.putLengthPrefixed(&out, Self.domain)
        out.append(control.rawValue)
        Self.putLengthPrefixed(&out, groupID)
        Self.putUInt64(&out, prevEpoch)
        Self.putUInt64(&out, nextEpoch)
        Self.putLengthPrefixed(&out, commitHash)
        Self.putLengthPrefixed(&out, actorDevice)
        Self.putUInt32(&out, UInt32(added.count))
        for pair in added {
            Self.putLengthPrefixed(&out, pair.account)
            Self.putLengthPrefixed(&out, pair.device)
        }
        Self.putUInt32(&out, UInt32(removed.count))
        for device in removed {
            Self.putLengthPrefixed(&out, device)
        }
        Self.putLengthPrefixed(&out, idempotencyKey)
        Self.putUInt64(&out, expiresAt)
        return out
    }

    private static func putLengthPrefixed(_ out: inout Data, _ field: Data) {
        putUInt32(&out, UInt32(field.count))
        out.append(field)
    }

    private static func putUInt32(_ out: inout Data, _ value: UInt32) {
        withUnsafeBytes(of: value.bigEndian) { out.append(contentsOf: $0) }
    }

    private static func putUInt64(_ out: inout Data, _ value: UInt64) {
        withUnsafeBytes(of: value.bigEndian) { out.append(contentsOf: $0) }
    }

    /// The exact input behind `contracts/test-vectors/membership-manifest-add.hex` (mirrors the
    /// Rust golden test), so cross-platform byte-identity is unit-tested.
    public static func sampleAddVectorInput() -> MembershipManifest {
        MembershipManifest(
            control: .add,
            groupID: Data(repeating: 0x07, count: 16),
            prevEpoch: 4,
            nextEpoch: 5,
            commitHash: Data(repeating: 0x09, count: 32),
            actorDevice: Data(repeating: 0x01, count: 16),
            added: [(account: Data(repeating: 0xAA, count: 16), device: Data(repeating: 0xBB, count: 16))],
            removed: [],
            idempotencyKey: Data(repeating: 0x02, count: 16),
            expiresAt: 1000
        )
    }
}
