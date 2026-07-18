import CryptoKit
import Foundation

/// Client-side key-transparency verification (R-201). The whole point of transparency is that the
/// client does **not** trust the server to report keys honestly — it verifies. This mirrors
/// `auth_core::transparency` (RFC 6962) byte for byte, so the Swift client and Rust server agree.
///
/// A client self-monitors its own account: it verifies the Signed Tree Head's signature under the
/// **pinned** log public key, that its enrolled device key is the one logged (no substitution),
/// and that the key is included under the signed root. See `docs/KEY_TRANSPARENCY.md` for what this
/// does and does not guarantee.
public enum Transparency {
    /// Leaf hash: H(0x00 || entry).
    public static func hashLeaf(_ entry: Data) -> Data {
        var buf = Data([0x00])
        buf.append(entry)
        return Data(SHA256.hash(data: buf))
    }

    /// Interior node hash: H(0x01 || left || right).
    static func hashNode(_ left: Data, _ right: Data) -> Data {
        var buf = Data([0x01])
        buf.append(left)
        buf.append(right)
        return Data(SHA256.hash(data: buf))
    }

    /// Verify an RFC 6962 inclusion proof (reconstruct the root from the leaf + audit path).
    public static func verifyInclusion(
        leaf: Data,
        index: Int,
        treeSize: Int,
        proof: [Data],
        root: Data
    ) -> Bool {
        if index >= treeSize { return false }
        var fn = index
        var sn = treeSize - 1
        var r = leaf
        var it = proof.makeIterator()
        while sn > 0 {
            guard let p = it.next() else { return false }
            if fn & 1 == 1 || fn == sn {
                r = hashNode(p, r)
                if fn & 1 == 0 {
                    while fn & 1 == 0 && fn != 0 {
                        fn >>= 1
                        sn >>= 1
                    }
                }
            } else {
                r = hashNode(r, p)
            }
            fn >>= 1
            sn >>= 1
        }
        return it.next() == nil && r == root
    }

    /// Canonical Signed-Tree-Head bytes (must match `auth_core::transparency::encode_sth`).
    public static func encodeSTH(treeSize: UInt64, root: Data, timestamp: UInt64) -> Data {
        let domain = Data("sentinel-transparency-sth-v1".utf8)
        var out = Data()
        out.append(be64(UInt64(domain.count)))
        out.append(domain)
        out.append(be64(treeSize))
        out.append(root)
        out.append(be64(timestamp))
        return out
    }

    /// Verify the STH's ECDSA-P256 signature under a SEC1 (x9.63) log public key.
    public static func verifySTHSignature(
        treeSize: UInt64,
        root: Data,
        timestamp: UInt64,
        signature: Data,
        logPublicKeyX963: Data
    ) -> Bool {
        guard let key = try? P256.Signing.PublicKey(x963Representation: logPublicKeyX963),
            let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
        else { return false }
        return key.isValidSignature(sig, for: encodeSTH(treeSize: treeSize, root: root, timestamp: timestamp))
    }

    private static func be64(_ v: UInt64) -> Data {
        var b = v.bigEndian
        return withUnsafeBytes(of: &b) { Data($0) }
    }
}

/// Result of a key-transparency self-monitor check.
public enum SelfMonitorResult: Sendable, Equatable {
    /// The enrolled device key is logged, unmodified, and included under a validly signed root.
    case ok
    /// The STH signature did not verify under the pinned log key (wrong/forged log key).
    case badSignature
    /// The log advertised a public key different from the one pinned (possible key-directory swap).
    case logKeyChanged
    /// No binding for this device is in the log (the server never published it — a red flag).
    case notIncluded
    /// A binding for this device is logged, but with a DIFFERENT public key (substitution attack).
    case keyMismatch
    /// A binding's inclusion proof did not verify against the signed root.
    case badProof
}

/// Result of an **account-level** device-set audit (#8): does the set of devices the transparency
/// log proves are bound to this account match the set the user knowingly enrolled? An *unexpected*
/// logged device is the alarm — it means a device was bound that the user never added (e.g. a
/// server-injected key), which no per-device self-check would catch.
public enum AccountDeviceAudit: Sendable, Equatable {
    /// The logged (non-revoked) device set exactly matches the expected set.
    case ok
    /// **ALARM:** devices are bound in the log that the user did not enroll.
    case unexpectedDevices([String])
    /// Expected devices are not yet in the log (e.g. an enrollment not yet propagated) — softer.
    case missingDevices([String])
    /// Both discrepancies at once.
    case discrepancy(unexpected: [String], missing: [String])
    /// The STH signature did not verify under the pinned log key.
    case badSignature
    /// The log advertised a different public key than the one pinned.
    case logKeyChanged
    /// A binding's inclusion proof did not verify against the signed root.
    case badProof
}

public enum KeyTransparencyAudit {
    /// Pure set-comparison of the (proof-verified) logged active devices against the expected set.
    /// Separated from the network + proof checks so the alarm logic is trivially testable.
    public static func classify(loggedActive: Set<String>, expected: Set<String>) -> AccountDeviceAudit
    {
        let unexpected = loggedActive.subtracting(expected).sorted()
        let missing = expected.subtracting(loggedActive).sorted()
        switch (unexpected.isEmpty, missing.isEmpty) {
        case (true, true): return .ok
        case (false, true): return .unexpectedDevices(unexpected)
        case (true, false): return .missingDevices(missing)
        case (false, false): return .discrepancy(unexpected: unexpected, missing: missing)
        }
    }
}
