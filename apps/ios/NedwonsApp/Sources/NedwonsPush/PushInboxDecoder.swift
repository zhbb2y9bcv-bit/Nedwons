import Foundation
import MlsFfi
import NedwonsKit

/// Decoupled from `NedwonsKit.InboxEnvelope` so the decode logic is directly testable.
public struct PushEnvelope: Sendable {
    public let id: Int
    public let ciphertext: Data
    public let sealed: Bool
    public let selfGroup: Bool

    public init(id: Int, ciphertext: Data, sealed: Bool = false, selfGroup: Bool = false) {
        self.id = id
        self.ciphertext = ciphertext
        self.sealed = sealed
        self.selfGroup = selfGroup
    }

    /// Map a fetched `InboxEnvelope` (hex ciphertext) to a `PushEnvelope`; `nil` if the hex is bad.
    public init?(_ e: InboxEnvelope) {
        guard let bytes = Hex.decode(e.ciphertext) else { return nil }
        self.init(id: e.id, ciphertext: bytes, sealed: e.sealed, selfGroup: e.selfGroup)
    }
}

/// The user-facing content a push resolves to.
public struct PushNotificationContent: Equatable, Sendable {
    public let title: String
    public let body: String
}

/// Decides what a contentless wake push should display, by processing the freshly-fetched inbox
/// through the **real** MLS core (`MlsClient`) and rendering the newest user-facing message.
///
/// **Single-writer caveat (ADR-0007):** `process*Inbound` ADVANCES the ratchet and commits durably,
/// and a given MLS group must live in exactly one client at a time. So the caller (the Notification
/// Service Extension) MUST hold the cross-process app-group lock and pass a freshly-`open`ed client;
/// the main app then re-`open`s to pick up the committed advance. See `docs/NOTIFICATION_EXTENSION.md`.
public enum PushInboxDecoder {
    /// Process `envelopes` through `client` and return what to show, or `nil` if nothing user-facing
    /// resulted (only control/duplicate messages) — the caller then shows a generic wake. Fail-safe:
    /// an envelope that fails to process is skipped, never fatal (the app re-syncs later).
    public static func decode(
        client: MlsClient, envelopes: [PushEnvelope]
    ) throws -> PushNotificationContent? {
        var latest: PushNotificationContent?
        for env in envelopes.sorted(by: { $0.id < $1.id }) {
            let result: InboundResult
            do {
                if env.selfGroup {
                    result = try client.processSelfInbound(
                        envelopeId: UInt64(env.id), ciphertext: env.ciphertext)
                } else {
                    result = try client.processInbound(
                        envelopeId: UInt64(env.id), ciphertext: env.ciphertext)
                }
            } catch {
                continue  // a commit/membership message or transient issue — the app will re-sync
            }
            switch result {
            case .application(let plaintext):
                latest = PushNotificationContent(
                    title: "New message", body: renderBody(plaintext))
            case .secretSealed:
                latest = PushNotificationContent(
                    title: "Secret message", body: "You received a view-once message.")
            // Control / already-seen: nothing to surface.
            case .duplicate, .stateAdvanced, .secretConsumedRemotely, .deliveryKeyGranted,
                .historySynced:
                continue
            }
        }
        return latest
    }

    private static func renderBody(_ plaintext: Data) -> String {
        let s = String(decoding: plaintext, as: UTF8.self)
        return s.isEmpty ? "New message" : s
    }
}
