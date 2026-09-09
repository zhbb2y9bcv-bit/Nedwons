import CryptoKit
import Foundation

/// Safety numbers — the human-comparable fingerprint of two accounts' identity keys.
///
/// This is the trust feature the docs keep pointing at: key transparency narrows what the server
/// can get away with, but *manual verification remains primary* (KEY_TRANSPARENCY.md). A safety
/// number gives two people something they can actually compare in person or over a call, and a QR
/// payload that compares it for them exactly.
///
/// What goes in: each side's **account id** and the X9.63 public keys of the account's active
/// devices **as this client verified them against the transparency log** (STH under the pinned log
/// key + inclusion proofs — `NedwonsClient.verifiedAccountKeys`). So a matching number means both
/// phones were served the *same* logged key set; a mismatch is exactly the alarm the design wants a
/// user to be able to raise without trusting the server's word.
///
/// Honest scope, same as everywhere else in this repo: the number covers the *device key sets at
/// the moment of comparison*. It changes when either side adds or removes a device — that is a
/// feature (re-verify), not drift. It does not prove the person you're talking to is who they say
/// they are; it proves your two clients agree on the keys.
///
/// The construction is deliberately Signal-shaped: each side contributes an order-independent
/// "half" — an iterated hash over a domain tag, the account id, and the sorted key set — rendered
/// as 30 digits; the two halves are sorted and concatenated, so both parties see the same 60
/// digits without agreeing on who is "first".
public enum SafetyNumber {
    /// Domain separation, versioned like every other Nedwons transcript.
    static let domain = "app.nedwons.safety-number.v1"
    /// Iterated-hash work factor (Signal uses 5200 over SHA-512; the point is to make brute-forcing
    /// a *partial* fingerprint collision annoying, not to be a KDF).
    static let iterations = 5200
    /// 6 groups of 5 digits per half → 60 digits total.
    static let groupsPerHalf = 6

    /// One party's half: an iterated SHA-256 over the domain, their account id, and their key set.
    /// Key order must not matter (devices enumerate in unspecified order), so keys are sorted by
    /// their raw bytes before hashing.
    static func half(accountID: String, keysX963: [Data]) -> Data {
        var transcript = Data(domain.utf8)
        transcript.append(0)
        transcript.append(Data(accountID.utf8))
        transcript.append(0)
        for key in keysX963.sorted(by: { $0.lexicographicallyPrecedes($1) }) {
            var len = UInt16(clamping: key.count).bigEndian
            withUnsafeBytes(of: &len) { transcript.append(contentsOf: $0) }
            transcript.append(key)
        }
        var digest = Data(SHA256.hash(data: transcript))
        for _ in 0..<iterations {
            digest = Data(SHA256.hash(data: digest + transcript))
        }
        return digest
    }

    /// A half rendered as 30 decimal digits: 6 groups, each 5 bytes of the digest reduced mod
    /// 100000. (A 32-byte digest covers the 30 bytes consumed.)
    static func digits(for half: Data) -> [String] {
        (0..<groupsPerHalf).map { group in
            var value: UInt64 = 0
            for i in 0..<5 { value = value << 8 | UInt64(half[group * 5 + i]) }
            return String(format: "%05d", value % 100_000)
        }
    }

    /// The 60-digit display number as 12 groups of 5. Symmetric: both parties compute the same
    /// groups regardless of which side is "local".
    public static func displayGroups(
        accountID: String, keysX963: [Data],
        peerAccountID: String, peerKeysX963: [Data]
    ) -> [String] {
        let mine = digits(for: half(accountID: accountID, keysX963: keysX963))
        let theirs = digits(for: half(accountID: peerAccountID, keysX963: peerKeysX963))
        let a = mine.joined()
        let b = theirs.joined()
        return a <= b ? mine + theirs : theirs + mine
    }

    /// The QR payload: the two halves' full digests (not the reduced digits) in a fixed
    /// (lexicographic) order, so a scan compares 512 bits exactly while humans compare 60 digits.
    public static func qrPayload(
        accountID: String, keysX963: [Data],
        peerAccountID: String, peerKeysX963: [Data]
    ) -> String {
        let mine = Hex.encode(half(accountID: accountID, keysX963: keysX963))
        let theirs = Hex.encode(half(accountID: peerAccountID, keysX963: peerKeysX963))
        let (lo, hi) = mine <= theirs ? (mine, theirs) : (theirs, mine)
        return "nedwons-verify:1:\(lo):\(hi)"
    }

    /// Whether a scanned payload matches this pair. Exact string equality — the payload is already
    /// order-independent — with the version prefix checked so a future v2 scans as "doesn't match"
    /// rather than crashing or silently passing.
    public static func payloadMatches(
        _ scanned: String,
        accountID: String, keysX963: [Data],
        peerAccountID: String, peerKeysX963: [Data]
    ) -> Bool {
        guard scanned.hasPrefix("nedwons-verify:1:") else { return false }
        return scanned
            == qrPayload(
                accountID: accountID, keysX963: keysX963,
                peerAccountID: peerAccountID, peerKeysX963: peerKeysX963)
    }
}

/// Invite-link QR payloads. The token itself is the bearer credential (ADR-0009); the payload is
/// just a self-identifying wrapper so a scanner can tell an invite from a safety-number code.
public enum InviteCode {
    static let prefix = "nedwons-invite:1:"

    /// Wrap a minted invite token (hex) for display as a QR code.
    public static func payload(token: String) -> String { prefix + token }

    /// Extract the token from a scanned/pasted string. Accepts the QR payload or a bare pasted
    /// token, requires the token to be well-formed (64 hex chars — the 32-byte invite tokens the
    /// server mints), and refuses anything else — a scanner pointed at the wrong QR must not send
    /// arbitrary bytes to the join endpoint.
    public static func parse(_ raw: String) -> String? {
        var candidate = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if candidate.hasPrefix(prefix) { candidate = String(candidate.dropFirst(prefix.count)) }
        let lowered = candidate.lowercased()
        guard lowered.count == 64, lowered.allSatisfy({ $0.isHexDigit }) else { return nil }
        return lowered
    }
}
