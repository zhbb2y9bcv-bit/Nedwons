import Darwin
import Foundation

/// The on-disk layout the app and the Notification Service Extension SHARE inside the app-group
/// container, in one place so neither side hardcodes the other's paths.
///
/// Layout (all under the container the OS hands back for the configured app group):
///
///     <container>/mls/index.json     — MlsStoreIndex: conversation id → store id (+ lobbies)
///     <container>/mls/store-<id>     — one encrypted MLS store per conversation (FileJournal)
///     <container>/mls/store.lock     — the cross-process single-writer flock (ADR-0007)
///
/// The app group id itself comes from the `NedwonsAppGroup` Info.plist key — of the app AND of the
/// extension, both set in `project.yml` — so a build without provisioning simply has no key and
/// everything degrades to the pre-existing behavior (app-private stores, generic wakes).
public enum SharedStoreLayout {
    public static let infoPlistKey = "NedwonsAppGroup"
    public static let storeSubdirectory = "mls"
    public static let lockFileName = "store.lock"

    /// The configured app group id, or `nil` when the build isn't provisioned for one. An empty
    /// value or an unsubstituted `$(...)` placeholder counts as absent.
    public static func configuredAppGroup(bundle: Bundle = .main) -> String? {
        guard let raw = bundle.object(forInfoDictionaryKey: infoPlistKey) as? String else {
            return nil
        }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return (trimmed.isEmpty || trimmed.hasPrefix("$(")) ? nil : trimmed
    }

    /// The shared MLS store directory for an app group, or `nil` when the OS has no container for
    /// it (not provisioned / not entitled). Does not create anything.
    public static func storeDirectory(appGroup: String) -> URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appendingPathComponent(storeSubdirectory, isDirectory: true)
    }

    public static func indexURL(storeDirectory: URL) -> URL {
        storeDirectory.appendingPathComponent(MlsStoreIndex.fileName)
    }

    public static func lockURL(storeDirectory: URL) -> URL {
        storeDirectory.appendingPathComponent(lockFileName)
    }

    public static func storePath(storeDirectory: URL, storeID: String) -> String {
        storeDirectory.appendingPathComponent("store-\(storeID)").path
    }
}

/// The cross-process single-writer lock (ADR-0007): decrypting advances and commits the MLS
/// ratchet, so the app (foreground) and the extension must never hold the same stores open at
/// once. Plain `flock` — released automatically by the OS if the holder dies, which is exactly
/// the failure behavior a lock guarding crash-prone processes needs.
public final class StoreLock: @unchecked Sendable {
    private let fd: Int32

    private init(fd: Int32) { self.fd = fd }

    /// Try to take the exclusive lock without blocking. `nil` = someone else (the app, or another
    /// extension instance) holds it; the caller falls back rather than waiting out its budget.
    public static func tryAcquire(at url: URL) -> StoreLock? {
        acquire(at: url, flags: LOCK_EX | LOCK_NB)
    }

    /// Take the exclusive lock, blocking until it is free. For the app side, which can afford to
    /// wait out an extension's few seconds of work on a background thread.
    public static func acquire(at url: URL) -> StoreLock? {
        acquire(at: url, flags: LOCK_EX)
    }

    private static func acquire(at url: URL, flags: Int32) -> StoreLock? {
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let fd = open(url.path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { return nil }
        guard flock(fd, flags) == 0 else {
            close(fd)
            return nil
        }
        return StoreLock(fd: fd)
    }

    public func release() {
        flock(fd, LOCK_UN)
        close(fd)
    }
}
