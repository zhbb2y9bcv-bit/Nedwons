import Darwin
import Foundation
import MlsFfi
import NedwonsKit
import NedwonsPush
import UserNotifications

/// On a contentless APNs wake, fetch the inbox, decrypt with the REAL MLS core, and rewrite the
/// alert (`mutable-content`). The relay only ever sent "New message"; the plaintext is produced
/// here, on device.
///
/// ## Single-writer coordination (ADR-0007)
/// A given MLS group must live in exactly ONE client at a time, and decrypting advances + commits
/// the ratchet. So this extension takes an exclusive **app-group `flock`**, `open`s the shared
/// store, processes, acks, and releases; the app re-`open`s on next foreground to pick up the
/// committed advance.
///
/// `didReceive` is synchronous — an NSE may block for its ~30s budget — and the async client calls
/// are bridged to blocking, crossing only `Sendable` results. That keeps the non-`Sendable`
/// `UNMutableNotificationContent` and completion handler on one thread, avoiding structured
/// concurrency here entirely. **Fail-safe:** missing shared state, a network error, or a decrypt
/// failure falls back to the generic wake. See `docs/NOTIFICATION_EXTENSION.md`.
final class NotificationService: UNNotificationServiceExtension {
    override func didReceive(
        _ request: UNNotificationRequest,
        withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        let content = request.content.mutableCopy() as? UNMutableNotificationContent
        let fallback = content ?? request.content

        guard let shared = SharedNotificationContext.current() else {
            contentHandler(fallback)  // no provisioned shared state → generic wake
            return
        }
        if let resolved = Self.resolveBlocking(shared: shared), let content {
            content.title = resolved.title
            content.body = resolved.body
            contentHandler(content)
        } else {
            contentHandler(fallback)  // control-only or an error → generic wake
        }
    }

    /// Under the cross-process store lock. Fully synchronous; the async client calls are bridged
    /// below. Opens the store for each envelope's conversation through the shared `MlsStoreIndex`
    /// — the app's real layout is one encrypted store per conversation, not one big one.
    private static func resolveBlocking(shared: SharedNotificationContext) -> PushNotificationContent? {
        // Non-blocking: if the app holds the lock it is running and will show the message itself;
        // waiting out our budget to fight it for the store would be worse than a generic wake.
        guard let lock = StoreLock.tryAcquire(
            at: SharedStoreLayout.lockURL(storeDirectory: shared.storeDirectory))
        else { return nil }
        defer { lock.release() }

        let index = MlsStoreIndex.load(
            from: SharedStoreLayout.indexURL(storeDirectory: shared.storeDirectory))
        let envelopes = blockingFetchInbox(baseURL: shared.serverURL, token: shared.accessToken)

        var opened: [String: MlsClient] = [:]
        defer { for client in opened.values { client.close() } }
        let outcome = PushInboxDecoder.decode(
            envelopes: envelopes.compactMap(PushEnvelope.init)
        ) { conversationID in
            if let cached = opened[conversationID] { return cached }
            guard let storeID = index.conversations[conversationID],
                let key = try? shared.keyProvider(storeID),
                let client = try? MlsClient.open(
                    dbPath: SharedStoreLayout.storePath(
                        storeDirectory: shared.storeDirectory, storeID: storeID),
                    atRestKey: key)
            else { return nil }
            opened[conversationID] = client
            return client
        }
        // Ack ONLY what was durably processed (ratchet advanced + committed). Anything else —
        // sealed, self-group, a store we could not open, a failed decrypt — stays queued for the
        // app: acking it here would delete mail nothing ever decrypted.
        blockingAck(
            baseURL: shared.serverURL, token: shared.accessToken,
            ids: outcome.processedIDs, sealedIds: [], selfGroupIds: [])
        return outcome.content
    }
}

/// A `Sendable` box carrying an async result back across a blocking bridge.
private final class ResultBox<T: Sendable>: @unchecked Sendable {
    var value: T?
}

/// Only the `Sendable` `[InboxEnvelope]` crosses the Task boundary.
private func blockingFetchInbox(baseURL: URL, token: String) -> [InboxEnvelope] {
    let sem = DispatchSemaphore(value: 0)
    let box = ResultBox<[InboxEnvelope]>()
    Task {
        let client = NedwonsClient(baseURL: baseURL)
        box.value = try? await client.fetchInbox(accessToken: token)
        sem.signal()
    }
    sem.wait()
    return box.value ?? []
}

/// Best-effort.
private func blockingAck(
    baseURL: URL, token: String, ids: [Int], sealedIds: [Int], selfGroupIds: [Int]
) {
    if ids.isEmpty && sealedIds.isEmpty && selfGroupIds.isEmpty { return }
    let sem = DispatchSemaphore(value: 0)
    Task {
        let client = NedwonsClient(baseURL: baseURL)
        try? await client.ackInbox(
            accessToken: token, ids: ids, sealedIds: sealedIds, selfGroupIds: selfGroupIds)
        sem.signal()
    }
    sem.wait()
}

/// Sourced from the app group + shared Keychain; `nil` until those are provisioned, so the
/// extension safely falls back to the generic wake. What "provisioned" means concretely:
/// - the `NedwonsAppGroup` Info.plist key names an app group both targets are entitled to
///   (`com.apple.security.application-groups`), so `containerURL` resolves and the app has been
///   rooting its MLS stores there (`AppComposition.standard()`);
/// - the app and this extension share a **Keychain access group** (the first entry of both
///   `keychain-access-groups` entitlements), so the same `SessionStore` / at-rest root reads here.
/// The server URL comes from this extension's own Info.plist (`NedwonsServerURL`), mirroring
/// `AppConfig` — `NedwonsUI` cannot be linked from an extension.
struct SharedNotificationContext: Sendable {
    let serverURL: URL
    let accessToken: String
    let storeDirectory: URL
    let keyProvider: @Sendable (String) throws -> Data

    static func current() -> SharedNotificationContext? {
        guard let group = SharedStoreLayout.configuredAppGroup(),
            let storeDirectory = SharedStoreLayout.storeDirectory(appGroup: group),
            FileManager.default.fileExists(
                atPath: SharedStoreLayout.indexURL(storeDirectory: storeDirectory).path),
            let session = SessionStore().load()
        else { return nil }
        let keys = AtRestKeyHierarchy(store: KeychainStore(service: "app.nedwons.at-rest"))
        return SharedNotificationContext(
            serverURL: Self.serverURL(),
            accessToken: session.accessToken,
            storeDirectory: storeDirectory,
            keyProvider: { storeID in try keys.atRestKey(forStore: storeID) })
    }

    /// `NedwonsServerURL` from this bundle's Info.plist, with the same loopback dev fallback as
    /// the app's `AppConfig` (simulator convenience; a device build must configure https).
    private static func serverURL() -> URL {
        if let raw = Bundle.main.object(forInfoDictionaryKey: "NedwonsServerURL") as? String {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty, !trimmed.hasPrefix("$("), let url = URL(string: trimmed) {
                return url
            }
        }
        return URL(string: "http://127.0.0.1:8097")!
    }
}
