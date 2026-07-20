import Foundation

/// The operation a transcript authorizes. Raw values MUST match the Rust `Action` enum in
/// `services/auth-core/src/transcript.rs`.
public enum AuthAction: UInt8 {
    case register = 1
    case login = 2
    case refresh = 3
    case passwordChange = 4
    case deviceEnroll = 5
    case accountDelete = 6
}

/// Swift port of the canonical, domain-separated authentication transcript
/// (CRYPTOGRAPHY.md §4). This MUST produce byte-identical output to the Rust
/// implementation; the shared vector in `contracts/test-vectors/auth-transcript-login.hex`
/// pins it and `AuthTranscriptTests` enforces it. A divergence would silently break
/// signature verification, so treat any change here as wire-breaking.
public enum AuthTranscript {
    /// ASCII domain-separation tag; versioned.
    public static let domain = Data("app.nedwons.auth.v1".utf8)
    /// Protocol version carried in the transcript (INV-9: bumping it is non-silent).
    public static let protocolVersion: UInt16 = 1

    public struct Input {
        public var action: AuthAction
        public var accountID: Data // 16 bytes
        public var deviceID: Data // 16 bytes
        public var publicKey: Data // SEC1 (x963) public key
        public var challenge: Data // 32 bytes (or SHA-256(refresh token) for refresh)
        public var expiresAt: UInt64
        public var txnID: Data // 16 bytes

        public init(
            action: AuthAction,
            accountID: Data,
            deviceID: Data,
            publicKey: Data,
            challenge: Data,
            expiresAt: UInt64,
            txnID: Data
        ) {
            self.action = action
            self.accountID = accountID
            self.deviceID = deviceID
            self.publicKey = publicKey
            self.challenge = challenge
            self.expiresAt = expiresAt
            self.txnID = txnID
        }
    }

    /// Produce the canonical byte string to sign/verify.
    public static func encode(_ input: Input) -> Data {
        var out = Data()
        appendLengthPrefixed(&out, domain)
        appendBigEndian(&out, protocolVersion)
        out.append(input.action.rawValue)
        appendLengthPrefixed(&out, input.accountID)
        appendLengthPrefixed(&out, input.deviceID)
        appendLengthPrefixed(&out, input.publicKey)
        appendLengthPrefixed(&out, input.challenge)
        appendBigEndian(&out, input.expiresAt)
        appendLengthPrefixed(&out, input.txnID)
        return out
    }

    /// The shared test-vector input, parameterized by public key so the interop tool can
    /// sign with a real device key while the golden test uses the fixed placeholder key.
    public static func sampleLoginVectorInput(publicKey: Data) -> Input {
        Input(
            action: .login,
            accountID: Data((0 ..< 16).map { UInt8($0 * 0x11) }), // 00 11 .. ff
            deviceID: Data((1 ... 16).map { UInt8($0) }), // 01 .. 10
            publicKey: publicKey,
            challenge: Data((0 ..< 32).map { UInt8($0) }), // 00 .. 1f
            expiresAt: 1_000_000_000,
            txnID: Data((0xF0 ... 0xFF).map { UInt8($0) }) // f0 .. ff
        )
    }

    // MARK: - Encoding helpers

    private static func appendLengthPrefixed(_ out: inout Data, _ field: Data) {
        appendBigEndian(&out, UInt32(field.count))
        out.append(field)
    }

    private static func appendBigEndian(_ out: inout Data, _ value: UInt16) {
        var be = value.bigEndian
        withUnsafeBytes(of: &be) { out.append(contentsOf: $0) }
    }

    private static func appendBigEndian(_ out: inout Data, _ value: UInt32) {
        var be = value.bigEndian
        withUnsafeBytes(of: &be) { out.append(contentsOf: $0) }
    }

    private static func appendBigEndian(_ out: inout Data, _ value: UInt64) {
        var be = value.bigEndian
        withUnsafeBytes(of: &be) { out.append(contentsOf: $0) }
    }
}
