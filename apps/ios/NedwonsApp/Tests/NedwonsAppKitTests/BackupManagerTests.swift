import CryptoKit
import Foundation
import NedwonsKit
import NedwonsUI
import XCTest

@testable import NedwonsAppKit

/// The full backup story over the REAL core (docs/BACKUPS.md): talk, back up, lose the local
/// data, restore, and — the part that makes it a backup rather than an export — RESUME: the
/// restored ratchets keep decrypting new mail, because the same device identity picks up exactly
/// the committed state.
@MainActor
final class BackupManagerTests: XCTestCase {
    private let conv = "c0" + String(repeating: "5", count: 30)

    /// A participant whose store keys come from a real `AtRestKeyHierarchy` (as the shipped
    /// composition wires it), so the backed-up root actually guards the backed-up files.
    private func hierarchyParticipant(
        _ name: String, relay: InMemoryRelay, store: InMemorySecretStore, directory: URL
    ) -> (AppModel, ConversationCoordinator, AtRestKeyHierarchy) {
        let keys = AtRestKeyHierarchy(store: store)
        let model = AppModel(client: NedwonsClient(baseURL: URL(string: "http://127.0.0.1:1")!))
        model.session = NedwonsClient.Session(
            accountID: String(repeating: name.first!.lowercased(), count: 32),
            deviceID: String(repeating: name.last!.lowercased(), count: 32),
            accessToken: name, accessExpiresAt: 1 << 40, refreshToken: "r",
            refreshExpiresAt: 1 << 40)
        relay.register(
            token: name,
            accountID: String(repeating: name.first!.lowercased(), count: 32),
            deviceID: String(repeating: name.last!.lowercased(), count: 32))
        let coordinator = ConversationCoordinator(
            model: model, relay: relay, storeDirectory: directory,
            keyProvider: { storeID in try keys.atRestKey(forStore: storeID) },
            minimumKeyPackages: 2)
        coordinator.attach(aliasStore: nil)
        return (model, coordinator, keys)
    }

    func testBackupRestoreResumesTheConversation() async throws {
        let relay = InMemoryRelay()
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("backup-alice-\(UUID().uuidString)", isDirectory: true)
        let keychain = InMemorySecretStore()
        let (aliceModel, aliceCoord, aliceKeys) = hierarchyParticipant(
            "alice", relay: relay, store: keychain, directory: dir)
        let bob = Participant("bob", relay: relay)

        await bob.coordinator.ensureKeyPackages()
        relay.createConversation(conv, memberDevices: [
            String(repeating: "e", count: 32), bob.deviceID,
        ])
        try await aliceCoord.bootstrap(conversationID: conv, memberAccountIDs: [bob.accountID])
        _ = try await bob.coordinator.syncOnce()
        await aliceModel.sendMessage("before the backup", to: conv)
        _ = try await bob.coordinator.syncOnce()

        // Back up, then lose the app's local data (delete + reinstall). The Keychain — device
        // identity and at-rest root — survives on iOS; the SAME secret store models that.
        let backups = BackupManager(storeDirectory: dir, keys: aliceKeys)
        let sealed = try backups.createBackup(passphrase: "correct horse battery")
        aliceCoord.stop()
        try FileManager.default.removeItem(at: dir)

        // Restoring over a live store is refused; into the emptied one it succeeds.
        let restored = try backups.restoreBackup(sealed, passphrase: "correct horse battery")
        XCTAssertGreaterThanOrEqual(restored, 2, "index + at least one store")
        XCTAssertThrowsError(
            try backups.restoreBackup(sealed, passphrase: "correct horse battery")
        ) { error in
            XCTAssertEqual(error as? BackupManager.RestoreError, .storeNotEmpty)
        }

        // "Relaunch": a fresh coordinator over the restored directory + the surviving Keychain.
        let (aliceModel2, aliceCoord2, _) = hierarchyParticipant(
            "alice", relay: relay, store: keychain, directory: dir)
        await aliceCoord2.prepare()
        XCTAssertEqual(
            (aliceModel2.threadLines[conv] ?? []).compactMap(\.quotableText),
            ["before the backup"],
            "restored history renders")

        // THE RESUME PROOF: the restored ratchet continues — new mail decrypts both ways.
        await bob.model.sendMessage("after the restore", to: conv)
        _ = try await aliceCoord2.syncOnce()
        XCTAssertEqual(
            (aliceModel2.threadLines[conv] ?? []).compactMap(\.quotableText),
            ["before the backup", "after the restore"])
        await aliceModel2.sendMessage("and back", to: conv)
        _ = try await bob.coordinator.syncOnce()
        XCTAssertEqual(bob.texts(in: conv).map(\.0).last, "and back")
    }

    func testWrongPassphraseRestoresNothing() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("backup-wrongpass-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data("{}".utf8).write(to: dir.appendingPathComponent("index.json"))
        let keys = AtRestKeyHierarchy(store: InMemorySecretStore())
        let backups = BackupManager(storeDirectory: dir, keys: keys)
        let sealed = try backups.createBackup(passphrase: "right one!")

        let freshDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("backup-fresh-\(UUID().uuidString)", isDirectory: true)
        let fresh = BackupManager(
            storeDirectory: freshDir, keys: AtRestKeyHierarchy(store: InMemorySecretStore()))
        XCTAssertThrowsError(try fresh.restoreBackup(sealed, passphrase: "wrong one!")) { error in
            XCTAssertEqual(error as? Backup.BackupError, .cannotOpen)
        }
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: freshDir.appendingPathComponent("index.json").path),
            "a failed open must write nothing")
    }
}
