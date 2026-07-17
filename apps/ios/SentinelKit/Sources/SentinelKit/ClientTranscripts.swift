import CryptoKit
import Foundation

/// Client-side builders for the transcripts the device signs. Each mirrors a Rust backend
/// flow exactly (register/login rebuild the transcript from the server challenge; refresh
/// derives its anti-replay nonce and transaction id from the rotating refresh token). Byte
/// equivalence with the backend is enforced by the shared vectors.
public enum ClientTranscripts {
    /// Registration enrollment transcript (proves possession of the new device key).
    public static func register(
        accountID: Data,
        deviceID: Data,
        publicKey: Data,
        challengeNonce: Data,
        expiresAt: UInt64,
        txnID: Data
    ) -> Data {
        AuthTranscript.encode(
            AuthTranscript.Input(
                action: .register,
                accountID: accountID,
                deviceID: deviceID,
                publicKey: publicKey,
                challenge: challengeNonce,
                expiresAt: expiresAt,
                txnID: txnID
            )
        )
    }

    /// Login transcript, rebuilt from the server's login challenge.
    public static func login(
        accountID: Data,
        deviceID: Data,
        publicKey: Data,
        challengeNonce: Data,
        expiresAt: UInt64,
        txnID: Data
    ) -> Data {
        AuthTranscript.encode(
            AuthTranscript.Input(
                action: .login,
                accountID: accountID,
                deviceID: deviceID,
                publicKey: publicKey,
                challenge: challengeNonce,
                expiresAt: expiresAt,
                txnID: txnID
            )
        )
    }

    /// Refresh transcript. The rotating token's SHA-256 is the anti-replay nonce and the
    /// transaction id is derived from it, so client and server agree with no extra
    /// round-trip. Must match the backend's `refresh_txn_id`.
    public static func refresh(
        accountID: Data,
        deviceID: Data,
        publicKey: Data,
        refreshToken: Data
    ) -> Data {
        let tokenHash = Data(SHA256.hash(data: refreshToken))
        return AuthTranscript.encode(
            AuthTranscript.Input(
                action: .refresh,
                accountID: accountID,
                deviceID: deviceID,
                publicKey: publicKey,
                challenge: tokenHash,
                expiresAt: 0,
                txnID: refreshTxnID(fromTokenHash: tokenHash)
            )
        )
    }

    /// Deterministic refresh transaction id: first 16 bytes of SHA-256(tokenHash ‖ "txn").
    /// Mirrors `auth_core::refresh_txn_id`.
    public static func refreshTxnID(fromTokenHash tokenHash: Data) -> Data {
        var buffer = tokenHash
        buffer.append(Data("txn".utf8))
        let digest = Data(SHA256.hash(data: buffer))
        return digest.prefix(16)
    }
}
