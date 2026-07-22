import Foundation
import MlsFfi
import NedwonsUI

/// The **real** `SecretEngine`: every method is a 1:1 forward to the Rust core, so all security
/// enforcement — atomic fail-closed reveal, the monotonic guard, deadlines, expiry scrub, replay
/// rejection, crash recovery — happens there, not here. Lives in the composition package because
/// it is the only place linking both NedwonsUI and MlsFfi.
public final class MlsClientSecretEngine: SecretEngine {
    private let client: MlsClient
    /// ADR-0015: given the opaque consumption envelope produced when a reveal begins, deliver it to
    /// the account's OTHER devices. The envelope is encrypted by the Rust core with this account's
    /// **device self-group** when one is established (option 3) — the conversation's other party is
    /// not a member and never learns of the open — so the app routes it to the account's own device
    /// fan-out, and each recipient device applies it via `MlsClient.processSelfInbound`. Absent a
    /// self-group it falls back to the conversation channel (option 2). The relay stays blind either
    /// way. Omit on a single-device client — no message is emitted.
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

    public func phase(secretID: Data, nowMs: UInt64) throws -> NedwonsUI.SecretPhase {
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

    /// Map the FFI's `SecretPhase` to the UI's (same cases; two enums so NedwonsUI stays free of
    /// the native binding dependency).
    static func map(_ p: MlsFfi.SecretPhase) -> NedwonsUI.SecretPhase {
        switch p {
        case .sealed: return .sealed
        case .countdown: return .countdown
        case .visible: return .visible
        case .consumed: return .consumed
        case .unknown: return .unknown
        }
    }
}
