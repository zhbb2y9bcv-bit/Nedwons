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
    /// The extension's own budget, deliberately under the ~30s the system allows.
    ///
    /// Finishing on OUR deadline rather than the system's is the whole point: when iOS runs the
    /// clock out it kills the process, and the user sees the unmodified payload — the literal
    /// string "New message" — with no chance to present best-attempt content. Returning early with
    /// whatever we have is always better than being killed with something better half-built.
    private static let budget: TimeInterval = 20

    /// Per-request network timeout. Must leave room for a second call (inbox fetch, then ack)
    /// inside `budget`.
    static let networkTimeout: TimeInterval = 8

    /// Retained so `serviceExtensionTimeWillExpire` can deliver something.
    private var contentHandler: ((UNNotificationContent) -> Void)?
    private var bestAttempt: UNNotificationContent?
    /// Guards exactly-once delivery. `UNNotificationServiceExtension` calls the handler at most
    /// once by contract, and calling it twice is a hard error — but there are now two callers (the
    /// normal path and the expiry callback) which can race, so the guarantee needs enforcing rather
    /// than assuming.
    private let delivered = DeliveryLatch()
    /// Cancels in-flight work when the deadline fires, so the process is not still fetching while
    /// the system tears it down.
    private var work: DispatchWorkItem?

    override func didReceive(
        _ request: UNNotificationRequest,
        withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        let mutable = request.content.mutableCopy() as? UNMutableNotificationContent
        let fallback = mutable ?? request.content
        self.contentHandler = contentHandler
        self.bestAttempt = fallback

        guard let shared = SharedNotificationContext.current() else {
            deliver(fallback)  // no provisioned shared state → generic wake
            return
        }

        // Our own deadline, ahead of the system's. Fires on the main queue so it cannot be starved
        // by the work item occupying a background queue.
        let deadline = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.work?.cancel()
            self.deliver(self.bestAttempt ?? fallback)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.budget, execute: deadline)

        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            let resolved = Self.resolveBlocking(shared: shared)
            // The deadline may have fired while this was running; `deliver` makes the loser a
            // no-op rather than a duplicate-call crash.
            deadline.cancel()
            if let resolved, let mutable {
                mutable.title = resolved.title
                mutable.body = resolved.body
                self.deliver(mutable)
            } else {
                self.deliver(fallback)  // control-only or an error → generic wake
            }
        }
        self.work = work
        DispatchQueue.global(qos: .userInitiated).async(execute: work)
    }

    /// The system is about to kill us. Deliver the best content we have — not nothing.
    ///
    /// Without this override iOS presents the ORIGINAL payload, which is the placeholder the relay
    /// sent. Overriding it is the difference between "a generic wake because we ran out of time"
    /// and "a generic wake because we were killed mid-flight", and only the first is a deliberate
    /// product behaviour.
    override func serviceExtensionTimeWillExpire() {
        work?.cancel()
        if let bestAttempt {
            deliver(bestAttempt)
        }
    }

    /// Exactly-once delivery. Every path funnels through here.
    private func deliver(_ content: UNNotificationContent) {
        guard delivered.claim() else { return }
        let handler = contentHandler
        contentHandler = nil
        handler?(content)
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

/// A one-shot claim. Guards the exactly-once delivery contract: `UNNotificationServiceExtension`
/// permits the content handler to be called at most once, and there are now two callers — the
/// normal completion and the deadline — which can race.
private final class DeliveryLatch: @unchecked Sendable {
    private let lock = NSLock()
    private var taken = false

    /// `true` exactly once, for whichever caller arrives first.
    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if taken { return false }
        taken = true
        return true
    }
}

/// A `Sendable` box carrying an async result back across a blocking bridge.
private final class ResultBox<T: Sendable>: @unchecked Sendable {
    var value: T?
}

/// A `URLSession` that gives up quickly.
///
/// The extension lives on a hard deadline, so the default 60-second request timeout is far longer
/// than the entire budget — one unreachable relay would consume every second the system granted and
/// the user would get the placeholder payload. These bounds guarantee the network can never be the
/// reason we run out of time.
private func extensionURLSession() -> URLSession {
    let config = URLSessionConfiguration.ephemeral
    config.timeoutIntervalForRequest = NotificationService.networkTimeout
    config.timeoutIntervalForResource = NotificationService.networkTimeout
    config.waitsForConnectivity = false  // never park waiting for a network that is not there
    config.allowsCellularAccess = true
    return URLSession(configuration: config)
}

/// Only the `Sendable` `[InboxEnvelope]` crosses the Task boundary.
///
/// The wait is BOUNDED. `sem.wait()` with no timeout is indistinguishable from a hang: the task
/// could be blocked on a socket that never answers, and this thread would sit there until the
/// system killed the process.
private func blockingFetchInbox(baseURL: URL, token: String) -> [InboxEnvelope] {
    let sem = DispatchSemaphore(value: 0)
    let box = ResultBox<[InboxEnvelope]>()
    let task = Task {
        let client = NedwonsClient(baseURL: baseURL, session: extensionURLSession())
        box.value = try? await client.fetchInbox(accessToken: token)
        sem.signal()
    }
    if sem.wait(timeout: .now() + NotificationService.networkTimeout + 2) == .timedOut {
        task.cancel()
        return []
    }
    return box.value ?? []
}

/// Best-effort, and likewise bounded.
///
/// Timing out here is safe in the direction that matters: an un-acked envelope stays queued and the
/// app collects it later, whereas blocking until the deadline would cost the user the decrypted
/// notification that has ALREADY been computed.
private func blockingAck(
    baseURL: URL, token: String, ids: [Int], sealedIds: [Int], selfGroupIds: [Int]
) {
    if ids.isEmpty && sealedIds.isEmpty && selfGroupIds.isEmpty { return }
    let sem = DispatchSemaphore(value: 0)
    let task = Task {
        let client = NedwonsClient(baseURL: baseURL, session: extensionURLSession())
        try? await client.ackInbox(
            accessToken: token, ids: ids, sealedIds: sealedIds, selfGroupIds: selfGroupIds)
        sem.signal()
    }
    if sem.wait(timeout: .now() + NotificationService.networkTimeout + 2) == .timedOut {
        task.cancel()
    }
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
