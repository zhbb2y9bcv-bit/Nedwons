import Foundation
import MlsFfi
import SentinelUI

/// The **real** `SecretEngine`: a thin adapter that forwards every call to the generated `MlsClient`
/// (the Rust MLS core over UniFFI). Because every method is a 1:1 forward, all the security
/// enforcement — atomic + fail-closed reveal, the monotonic guard, the 3s/10s deadlines, expiry
/// scrub, replay rejection, crash recovery — happens in Rust, exactly as the mls-core / mls-ffi
/// tests prove. This is the adapter the report described as "belonging in the app target"; it lives
/// here in the composition package (the only place that links both SentinelUI and MlsFfi) and is
/// exercised against the real core by `SecretMessageViewModelRealCoreTests`.
public final class MlsClientSecretEngine: SecretEngine {
    private let client: MlsClient
    /// ADR-0015: given the opaque consumption envelope produced when a reveal begins, deliver it to
    /// the account's OTHER devices (the app's send path — client-side fan-out through the
    /// conversation; the relay stays blind). Omit on a single-device client — no message is emitted.
    private let broadcastConsumption: ((Data) throws -> Void)?

    public init(client: MlsClient, broadcastConsumption: ((Data) throws -> Void)? = nil) {
        self.client = client
        self.broadcastConsumption = broadcastConsumption
    }

    public func beginReveal(secretID: Data, nowMs: UInt64) throws {
        try client.beginSecretReveal(secretId: secretID, nowMs: nowMs)
        // Account-wide single-view (ADR-0015): emit the consumption control message once and fan it
        // out. Only when a broadcast path is wired — a single-device client skips this.
        if let broadcast = broadcastConsumption,
            let envelope = try client.secretConsumptionEnvelope(secretId: secretID)
        {
            try broadcast(envelope)
        }
    }

    public func phase(secretID: Data, nowMs: UInt64) throws -> SentinelUI.SecretPhase {
        Self.map(try client.secretPhase(secretId: secretID, nowMs: nowMs))
    }

    public func visibleBody(secretID: Data, nowMs: UInt64) throws -> Data? {
        try client.secretVisibleBody(secretId: secretID, nowMs: nowMs)
    }

    public func remaining(secretID: Data, nowMs: UInt64) throws
        -> (countdownMs: UInt64, viewMs: UInt64)
    {
        let r = try client.secretRemaining(secretId: secretID, nowMs: nowMs)
        return (r.countdownMs, r.viewMs)
    }

    public func consume(secretID: Data) throws {
        try client.consumeSecret(secretId: secretID)
    }

    public var tombstoneText: String { secretTombstoneText() }

    /// Map the FFI's `SecretPhase` to the UI's (same cases; two enums so SentinelUI stays free of
    /// the native binding dependency).
    static func map(_ p: MlsFfi.SecretPhase) -> SentinelUI.SecretPhase {
        switch p {
        case .sealed: return .sealed
        case .countdown: return .countdown
        case .visible: return .visible
        case .consumed: return .consumed
        case .unknown: return .unknown
        }
    }
}
