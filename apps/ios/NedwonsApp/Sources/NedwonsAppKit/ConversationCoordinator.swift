import Foundation
import MlsFfi
import NedwonsKit
import NedwonsUI

/// Owns one `MlsClient` per conversation and projects their decrypted local state into `AppModel`.
/// This is the only place that links both the UI and the MLS core, so plaintext never leaves the
/// device: previews and thread lines are built here from already-decrypted local history, never
/// from anything the relay supplied (INV-1).
///
/// MLS secrets stay inside the Rust core — this type holds handles, not key material.
@MainActor
public final class ConversationCoordinator {
    private let model: AppModel
    private let storeDirectory: URL
    private let atRestKey: Data
    private var clients: [String: MlsClient] = [:]

    public init(model: AppModel, storeDirectory: URL, atRestKey: Data) {
        self.model = model
        self.storeDirectory = storeDirectory
        self.atRestKey = atRestKey
    }

    /// Wire the model's injected actions to this coordinator. Called once after sign-in, before the
    /// authenticated UI renders.
    public func attach(aliasStore: ContactAliasStore) {
        model.aliasStore = aliasStore
        model.secretTombstoneText = secretTombstoneText()
        // The core's send path is synchronous; the action stays `async` so a future networked
        // implementation can suspend without changing every call site.
        model.sendMessageAction = { [weak self] body, conversationID in
            try self?.send(body, in: conversationID)
        }
        model.clearHistoryAction = { [weak self] conversationID in
            try self?.clearHistory(in: conversationID)
        }
    }

    private func dbPath(_ conversationID: String) -> String {
        storeDirectory.appendingPathComponent("conv-\(conversationID)").path
    }

    /// Reopen the durable store for a conversation, or `nil` when this device has no session for it
    /// yet (it has not been joined/created here).
    private func client(for conversationID: String) -> MlsClient? {
        if let existing = clients[conversationID] { return existing }
        guard
            let opened = try? MlsClient.open(
                dbPath: dbPath(conversationID), atRestKey: atRestKey)
        else { return nil }
        clients[conversationID] = opened
        return opened
    }

    public func register(_ client: MlsClient, for conversationID: String) {
        clients[conversationID] = client
        refresh(conversationID)
    }

    /// Enqueue → encrypt → mark sent. The retry path deliberately re-uses the cached ciphertext in
    /// the core rather than re-encrypting, so a resend never advances the ratchet twice.
    private func send(_ body: String, in conversationID: String) throws {
        guard let client = client(for: conversationID) else {
            throw CoordinatorError.noSessionForConversation
        }
        let localID = try client.enqueue(plaintext: Data(body.utf8))
        _ = try client.encrypt(localId: localID)
        try client.markSent(localId: localID)
        refresh(conversationID)
    }

    /// Local-only erase of the visible log. Protocol state is retained by the core, so a later
    /// message still decrypts and the thread legitimately returns.
    private func clearHistory(in conversationID: String) throws {
        guard let client = client(for: conversationID) else { return }
        try client.clearVisibleHistory()
        model.threadLines[conversationID] = []
        model.localThreads.removeValue(forKey: conversationID)
    }

    /// Rebuild the rendered lines and list preview for one conversation from decrypted local state.
    public func refresh(_ conversationID: String) {
        guard let client = client(for: conversationID),
            let stored = try? client.messages()
        else { return }

        let lines: [ThreadLine] = stored.map { message in
            let mine = message.direction == .outbound
            if let secretID = message.secretId {
                let phase = (try? client.secretPhase(
                    secretId: secretID, nowMs: UptimeClock().nowMs())) ?? .unknown
                return ThreadLine(
                    id: message.localId,
                    kind: phase == .consumed ? .consumedSecret : .sealedSecret(secretID),
                    mine: mine)
            }
            return ThreadLine(
                id: message.localId,
                kind: .text(String(decoding: message.plaintext, as: UTF8.self)),
                mine: mine)
        }
        model.threadLines[conversationID] = lines

        // A secret never contributes its body to the preview — only that one arrived.
        let preview: String? = stored.last.map { last in
            last.secretId != nil
                ? "Secret message"
                : String(decoding: last.plaintext, as: UTF8.self)
        }
        model.localThreads[conversationID] = AppModel.LocalThreadState(
            preview: preview,
            lastActivity: stored.isEmpty ? nil : Date(),
            unreadCount: 0)
    }

    public enum CoordinatorError: Error {
        case noSessionForConversation
    }
}
