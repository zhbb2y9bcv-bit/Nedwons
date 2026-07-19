import Darwin
import Foundation
import MlsFfi
import SentinelKit
import SentinelPush
import UserNotifications

/// Notification Service Extension (#4): on a contentless APNs wake, fetch the inbox, decrypt the
/// newest message with the REAL MLS core, and rewrite the alert (`mutable-content`). The relay only
/// ever sent "New message"; the plaintext is produced here, on device.
///
/// ## Single-writer coordination (ADR-0007)
/// A given MLS group must live in exactly ONE client at a time, and decrypting advances + commits
/// the ratchet. So this extension takes an exclusive **app-group `flock`**, `open`s the shared
/// atomically-committed MLS store, processes the new envelopes, acks, and releases. The app
/// re-`open`s on next foreground to pick up the committed advance.
///
/// `didReceive` runs synchronously (an NSE may block for its ~30s budget); the two async client
/// calls are bridged to blocking internally, crossing only `Sendable` results — which keeps the
/// non-`Sendable` `UNMutableNotificationContent` / completion handler on one thread (no structured
/// concurrency in `didReceive`). **Fail-safe:** missing shared state (until the app group + shared
/// Keychain are provisioned), a network error, or a decrypt failure falls back to the generic wake.
/// See `docs/NOTIFICATION_EXTENSION.md`.
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

    /// Under the app-group `flock`: open the shared client, fetch, decode the newest message, ack.
    /// Fully synchronous (the async client calls are bridged below).
    private static func resolveBlocking(shared: SharedNotificationContext) -> PushNotificationContent? {
        let fd = open(shared.lockPath, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { return nil }
        defer { flock(fd, LOCK_UN) }

        guard let client = try? MlsClient.open(dbPath: shared.mlsDbPath, atRestKey: shared.atRestKey)
        else { return nil }
        let envelopes = blockingFetchInbox(baseURL: shared.serverURL, token: shared.accessToken)
        let decoded = try? PushInboxDecoder.decode(
            client: client, envelopes: envelopes.compactMap(PushEnvelope.init))
        // Ack what we durably processed so it is not re-shown (per-channel id spaces).
        blockingAck(
            baseURL: shared.serverURL, token: shared.accessToken,
            ids: envelopes.filter { !$0.sealed && !$0.selfGroup }.map(\.id),
            sealedIds: envelopes.filter { $0.sealed }.map(\.id),
            selfGroupIds: envelopes.filter { $0.selfGroup }.map(\.id))
        return decoded ?? nil
    }
}

/// A `Sendable` box carrying an async result back across a blocking bridge.
private final class ResultBox<T: Sendable>: @unchecked Sendable {
    var value: T?
}

/// Fetch the inbox synchronously (only the `Sendable` `[InboxEnvelope]` crosses the Task boundary).
private func blockingFetchInbox(baseURL: URL, token: String) -> [InboxEnvelope] {
    let sem = DispatchSemaphore(value: 0)
    let box = ResultBox<[InboxEnvelope]>()
    Task {
        let client = SentinelClient(baseURL: baseURL)
        box.value = try? await client.fetchInbox(accessToken: token)
        sem.signal()
    }
    sem.wait()
    return box.value ?? []
}

/// Ack processed envelopes synchronously (best-effort).
private func blockingAck(
    baseURL: URL, token: String, ids: [Int], sealedIds: [Int], selfGroupIds: [Int]
) {
    if ids.isEmpty && sealedIds.isEmpty && selfGroupIds.isEmpty { return }
    let sem = DispatchSemaphore(value: 0)
    Task {
        let client = SentinelClient(baseURL: baseURL)
        try? await client.ackInbox(
            accessToken: token, ids: ids, sealedIds: sealedIds, selfGroupIds: selfGroupIds)
        sem.signal()
    }
    sem.wait()
}

/// The shared state the extension needs, sourced from the app group + shared Keychain. Returns `nil`
/// until those are provisioned (device build), so the extension safely falls back. Wiring:
/// - `serverURL` from `AppConfig` (or the app group's shared config);
/// - `accessToken` + the at-rest root from the **shared Keychain access group**;
/// - `mlsDbPath` + `lockPath` from the **app-group container**
///   (`FileManager.containerURL(forSecurityApplicationGroupIdentifier:)`).
struct SharedNotificationContext: Sendable {
    let serverURL: URL
    let accessToken: String
    let mlsDbPath: String
    let atRestKey: Data
    let lockPath: String

    static func current() -> SharedNotificationContext? {
        // Provisioned via the app group + shared Keychain on a device build. Until then, nil.
        nil
    }
}
