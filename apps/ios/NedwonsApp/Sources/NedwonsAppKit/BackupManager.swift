import Foundation
import NedwonsKit
import NedwonsPush

/// Creates and restores encrypted chat backups (docs/BACKUPS.md): the MLS store directory —
/// index.json, every per-conversation store, every R-105 archive — plus the at-rest ROOT key,
/// sealed under a user passphrase (`NedwonsKit.Backup`).
///
/// SCOPE, honestly (v1): a backup protects HISTORY against losing the app's local data — delete
/// and reinstall, a failed migration — on the SAME device, where the Keychain-held device
/// identity survives and the restored ratchets simply resume. It is NOT yet a new-phone transfer:
/// the device key is Secure-Enclave-bound and non-exportable by design, so a different device is
/// a different MLS participant; making restored history readable there is tracked future work.
public struct BackupManager: Sendable {
    public enum RestoreError: Error, Equatable {
        /// The store directory already holds conversations — restoring over live state is refused
        /// rather than merged (fail closed; wipe explicitly first if that is really wanted).
        case storeNotEmpty
    }

    let storeDirectory: URL
    let keys: AtRestKeyHierarchy

    public init(storeDirectory: URL, keys: AtRestKeyHierarchy) {
        self.storeDirectory = storeDirectory
        self.keys = keys
    }

    /// Everything under the store directory that IS the message history: the index and the
    /// per-conversation stores with their archives. Flat names only — the layout is flat by
    /// construction, and the decoder refuses anything else.
    public func createBackup(passphrase: String) throws -> Data {
        var files: [(String, Data)] = []
        let entries = (try? FileManager.default.contentsOfDirectory(
            at: storeDirectory, includingPropertiesForKeys: nil)) ?? []
        for url in entries.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            let name = url.lastPathComponent
            let isStoreFile =
                name == "index.json" || name.hasPrefix("store-") || name.hasSuffix(".archive")
            guard isStoreFile, !name.hasSuffix(".tmp"), !name.hasSuffix(".lock") else { continue }
            files.append((name, try Data(contentsOf: url)))
        }
        let archive = Backup.Archive(atRestRoot: try keys.exportRoot(), files: files)
        return try Backup.seal(archive, passphrase: passphrase)
    }

    /// Restore into an EMPTY store directory. Returns how many files landed. The at-rest root is
    /// imported only when none exists; a surviving identical root (same-device reinstall with a
    /// live Keychain) is a no-op, and a DIFFERENT live root refuses the restore inside
    /// `importRoot` — silently clobbering the keys guarding current data is never acceptable.
    public func restoreBackup(_ data: Data, passphrase: String) throws -> Int {
        let archive = try Backup.open(data, passphrase: passphrase)
        let indexURL = storeDirectory.appendingPathComponent(MlsStoreIndex.fileName)
        if FileManager.default.fileExists(atPath: indexURL.path) {
            throw RestoreError.storeNotEmpty
        }
        _ = try keys.importRoot(archive.atRestRoot)
        try FileManager.default.createDirectory(
            at: storeDirectory, withIntermediateDirectories: true)
        for (name, bytes) in archive.files {
            try bytes.write(to: storeDirectory.appendingPathComponent(name), options: .atomic)
        }
        return archive.files.count
    }
}
