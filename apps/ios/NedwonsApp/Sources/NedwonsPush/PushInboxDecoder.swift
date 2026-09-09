import Foundation
import MlsFfi
import NedwonsKit

/// Decoupled from `NedwonsKit.InboxEnvelope` so the decode logic is directly testable.
public struct PushEnvelope: Sendable {
    public let id: Int
    public let ciphertext: Data
    public let sealed: Bool
    public let selfGroup: Bool
    /// The routed conversation, when the relay knows it (absent for sealed and self-group mail) —
    /// what the multi-store decode uses to pick the right MLS store.
    public let conversationID: String?

    public init(
        id: Int, ciphertext: Data, sealed: Bool = false, selfGroup: Bool = false,
        conversationID: String? = nil
    ) {
        self.id = id
        self.ciphertext = ciphertext
        self.sealed = sealed
        self.selfGroup = selfGroup
        self.conversationID = conversationID
    }

    /// Map a fetched `InboxEnvelope` (hex ciphertext) to a `PushEnvelope`; `nil` if the hex is bad.
    public init?(_ e: InboxEnvelope) {
        guard let bytes = Hex.decode(e.ciphertext) else { return nil }
        self.init(
            id: e.id, ciphertext: bytes, sealed: e.sealed, selfGroup: e.selfGroup,
            conversationID: e.conversationID)
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

/// What a multi-store decode pass produced: the content to show, and exactly which envelope ids
/// were **durably processed** (the ratchet advanced and committed, duplicates included) — the only
/// ids the caller may ack. An envelope that failed, or whose store this process could not open, is
/// NOT in the list: acking it would delete mail the app never decrypted (at-least-once delivery).
public struct PushDecodeOutcome: Sendable {
    public let content: PushNotificationContent?
    public let processedIDs: [Int]
}

public enum PushInboxDecoder {
    /// Decode against the app's real store layout: one MLS store per conversation, found through
    /// the shared `MlsStoreIndex` (`clientFor` opens — and caches, if it wants — the store for a
    /// conversation id, returning `nil` for one it cannot serve). Sealed and self-group envelopes
    /// carry no conversation id the relay knows, so they are left untouched for the app: the wake
    /// stays generic rather than this extension guessing at stores.
    public static func decode(
        envelopes: [PushEnvelope],
        clientFor: (String) throws -> MlsClient?
    ) -> PushDecodeOutcome {
        var latest: PushNotificationContent?
        var processed: [Int] = []
        for env in envelopes.sorted(by: { $0.id < $1.id }) {
            guard !env.sealed, !env.selfGroup, let conversationID = env.conversationID else {
                continue
            }
            guard let client = (try? clientFor(conversationID)) ?? nil else { continue }
            let result: InboundResult
            do {
                result = try client.processInbound(
                    envelopeId: UInt64(env.id), ciphertext: env.ciphertext)
            } catch {
                continue  // a commit/Welcome or transient issue — the app will re-sync it
            }
            processed.append(env.id)
            if let content = render(result) { latest = content }
        }
        return PushDecodeOutcome(content: latest, processedIDs: processed)
    }

    /// What one processed inbound result should display; `nil` for control/duplicate outcomes.
    private static func render(_ result: InboundResult) -> PushNotificationContent? {
        switch result {
        case .application(let plaintext):
            return PushNotificationContent(title: "New message", body: renderBody(plaintext))
        case .secretSealed:
            return PushNotificationContent(
                title: "Secret message", body: "You received a view-once message.")
        // A file. The bytes are still on the relay and are not fetched here — the extension has
        // a few seconds and no business downloading a 25 MB video — so the notification
        // describes it from the reference the message already carried.
        case .attachmentReceived(let attachment):
            return PushNotificationContent(title: "New message", body: describe(attachment))
        // Control / already-seen: nothing to surface. Reactions, receipts and typing are
        // deliberately silent — the state is still applied durably by the core.
        case .duplicate, .stateAdvanced, .secretConsumedRemotely, .deliveryKeyGranted,
            .historySynced, .groupRenamed, .reactionChanged, .receiptsReceived, .typing,
            .timerChanged, .messageDeleted, .messageEdited, .groupAvatarChanged:
            return nil
        }
    }

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
            // A file. The bytes are still on the relay and are not fetched here — the extension has
            // a few seconds and no business downloading a 25 MB video — so the notification
            // describes it from the reference the message already carried.
            case .attachmentReceived(let attachment):
                latest = PushNotificationContent(
                    title: "New message", body: describe(attachment))
            // Control / already-seen: nothing to surface. A rename is applied durably by the
            // core when it is processed, so the group is correctly named the next time the app
            // opens — but it is not something to wake someone with a notification for.
            // Reactions, receipts and typing are deliberately silent: waking someone for "they
            // are typing" or "your message was read" is a notification nobody asked for, and a
            // reaction is visible next time they look. The state is still applied by the core.
            case .duplicate, .stateAdvanced, .secretConsumedRemotely, .deliveryKeyGranted,
                .historySynced, .groupRenamed, .reactionChanged, .receiptsReceived, .typing,
            .timerChanged, .messageDeleted, .messageEdited, .groupAvatarChanged:
                continue
            }
        }
        return latest
    }

    /// What to say about a file on a lock screen: a plain description from the media type. Not the
    /// filename — that is text the sender chose, and a notification is the one place it would be
    /// shown before anyone has decided to open the conversation.
    private static func describe(_ attachment: AttachmentInfo) -> String {
        switch attachment.mime.split(separator: "/").first.map(String.init) {
        case "image": "📷 Photo"
        case "video": "🎬 Video"
        case "audio": "🎤 Voice message"
        default: "📎 File"
        }
    }

    private static func renderBody(_ plaintext: Data) -> String {
        let s = String(decoding: plaintext, as: UTF8.self)
        return s.isEmpty ? "New message" : s
    }
}
