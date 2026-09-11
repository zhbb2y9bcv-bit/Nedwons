import Foundation
import Security

/// A generated, high-entropy account recovery code (ADR-0003, R-304).
///
/// ## Why this is generated and not typed
///
/// The recovery secret is the ONLY way back into an account when every enrolled device is lost, and
/// a password alone can never enroll a device (INV-2). It is therefore the single credential whose
/// strength decides whether a lost-phone account is recoverable by its owner or by an attacker who
/// guesses.
///
/// `auth-core` says so directly — `MIN_RECOVERY_SECRET_CHARS` is documented as "a sanity floor, not
/// policy", on the assumption that clients generate codes. The app was not: its setup screen
/// accepted any 12-character string the user typed. Two problems, one of them silent:
///
///   * 12 characters of human-chosen text is guessable, and this credential is offline-attackable
///     once the hash is obtained;
///   * the server floor is TWENTY, so anything between 12 and 19 characters passed every check the
///     screen made and was then refused by the backend after the user had written it down.
///
/// Generating removes both. The user's job becomes storing a code, not inventing one.
public enum RecoverySecret {
    /// Crockford base32: no `I`, `L`, `O` or `U`, so a handwritten code cannot be misread as a
    /// digit and no group can accidentally spell a word.
    static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    /// Characters of entropy. 32 × 5 bits = **160 bits**, which is beyond brute force and stays
    /// comfortably above the server's 20-character floor even before grouping.
    static let dataLength = 32
    /// Characters per dash-separated group, for transcription.
    static let groupSize = 4

    /// A fresh recovery code, e.g. `K7QD-2M9X-...`. Uses the system CSPRNG.
    public static func generate() -> String {
        generate(randomBytes: secureRandomBytes)
    }

    /// Seam for tests: a deterministic byte source proves the grouping and alphabet mapping without
    /// depending on randomness.
    static func generate(randomBytes: (Int) -> [UInt8]) -> String {
        let bytes = randomBytes(dataLength)
        // One character per byte via modulo. The alphabet is 32 long and 256 is a whole multiple of
        // it, so this mapping is uniform — no modulo bias.
        let characters = bytes.map { alphabet[Int($0) % alphabet.count] }
        return stride(from: 0, to: characters.count, by: groupSize)
            .map { String(characters[$0 ..< min($0 + groupSize, characters.count)]) }
            .joined(separator: "-")
    }

    /// The canonical form that is hashed: upper-cased, with separators and whitespace removed.
    ///
    /// Normalisation has to happen on BOTH the set and the verify path, or a user who types the
    /// code back with different spacing is told their correct code is wrong. The server hashes the
    /// string it is given, so the client must send the normalised form every time.
    public static func normalize(_ input: String) -> String {
        input.uppercased().filter { alphabet.contains($0) }
    }

    /// Whether a code is acceptable to submit. Mirrors the server's floor so the screen never
    /// accepts something the backend will refuse.
    public static func isAcceptable(_ input: String) -> Bool {
        normalize(input).count >= minimumNormalizedLength
    }

    /// `auth-core`'s `MIN_RECOVERY_SECRET_CHARS`. Duplicated deliberately, with this note: the two
    /// must move together, and the tests assert a generated code clears it with margin.
    public static let minimumNormalizedLength = 20

    /// Approximate entropy of a generated code, for display ("160 bits").
    public static var entropyBits: Int {
        Int(Double(dataLength) * log2(Double(alphabet.count)))
    }

    /// `SecRandomCopyBytes` explicitly rather than `SystemRandomNumberGenerator`. The latter is
    /// cryptographically secure on Apple platforms, but this is the credential that stands between
    /// a lost phone and a stolen account — the source of its randomness should be stated in the
    /// code, not inferred from a platform guarantee, and a failure here must be fatal rather than
    /// silently producing a predictable code.
    static func secureRandomBytes(_ count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        precondition(status == errSecSuccess, "the system CSPRNG failed (\(status))")
        return bytes
    }
}
