import CryptoKit
import Foundation

/// DPoP-style per-request proof-of-possession (ADR-0011, R-308). The Swift encoder reproduces
/// `auth_core::request_proof::RequestProof::encode` **byte-for-byte** so the device signs exactly
/// what the server verifies. A sender-constrained access token: a stolen bearer token is useless
/// without the enrolled device key that signs each request.
public struct RequestProof: Sendable {
    public let method: String
    /// Request path, no query string (e.g. `/v1/inbox`).
    public let path: String
    /// SHA-256 of the presented access token (bytes).
    public let accessTokenHash: Data
    public let timestamp: UInt64
    public let nonce: Data  // 16 bytes

    public init(method: String, path: String, accessTokenHash: Data, timestamp: UInt64, nonce: Data)
    {
        self.method = method
        self.path = path
        self.accessTokenHash = accessTokenHash
        self.timestamp = timestamp
        self.nonce = nonce
    }

    static let domain = Data("app.nedwons.dpop.v1".utf8)
    static let protocolVersion: UInt16 = 1

    /// The canonical byte string that is signed and verified (matches the Rust encoder).
    public func canonicalBytes() -> Data {
        var out = Data()
        Self.putLengthPrefixed(&out, Self.domain)
        Self.putUInt16(&out, Self.protocolVersion)
        Self.putLengthPrefixed(&out, Data(method.utf8))
        Self.putLengthPrefixed(&out, Data(path.utf8))
        Self.putLengthPrefixed(&out, accessTokenHash)
        Self.putUInt64(&out, timestamp)
        Self.putLengthPrefixed(&out, nonce)
        return out
    }

    /// Build the `X-Nedwons-Proof` header value for a request: hashes the access token, signs the
    /// canonical proof with `signer` (the private key never leaves the signer), and formats the
    /// `v1;ts=…;nonce=…;sig=…` header. `nonce` defaults to 16 fresh random bytes (single-use).
    public static func header(
        signer: DeviceSigner,
        accessToken: Data,
        method: String,
        path: String,
        timestamp: UInt64 = UInt64(Date().timeIntervalSince1970),
        nonce: Data = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
    ) throws -> String {
        let tokenHash = Data(SHA256.hash(data: accessToken))
        let proof = RequestProof(
            method: method, path: path, accessTokenHash: tokenHash, timestamp: timestamp,
            nonce: nonce)
        let signature = try signer.sign(proof.canonicalBytes())
        return "v1;ts=\(timestamp);nonce=\(Hex.encode(nonce));sig=\(Hex.encode(signature))"
    }

    private static func putLengthPrefixed(_ out: inout Data, _ field: Data) {
        putUInt32(&out, UInt32(field.count))
        out.append(field)
    }
    private static func putUInt16(_ out: inout Data, _ value: UInt16) {
        withUnsafeBytes(of: value.bigEndian) { out.append(contentsOf: $0) }
    }
    private static func putUInt32(_ out: inout Data, _ value: UInt32) {
        withUnsafeBytes(of: value.bigEndian) { out.append(contentsOf: $0) }
    }
    private static func putUInt64(_ out: inout Data, _ value: UInt64) {
        withUnsafeBytes(of: value.bigEndian) { out.append(contentsOf: $0) }
    }

    /// The exact input behind the Rust golden vector, for cross-platform byte-identity testing.
    public static func sampleVectorInput() -> RequestProof {
        RequestProof(
            method: "POST",
            path: "/v1/conversations/aabb/messages",
            accessTokenHash: Data(repeating: 0x07, count: 32),
            timestamp: 1_700_000_000,
            nonce: Data(repeating: 0x09, count: 16)
        )
    }
}
