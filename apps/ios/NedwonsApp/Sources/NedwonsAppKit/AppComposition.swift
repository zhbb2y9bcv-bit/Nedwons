import Combine
import Foundation
import NedwonsKit
import NedwonsPush
import NedwonsUI

/// The shipped app's object graph: the `AppModel` the screens render, and the
/// `ConversationCoordinator` that gives it a real messaging pipeline (prekeys, MLS bootstrap,
/// upload-with-retry, receive loop). Before this type existed the `@main` target built a bare
/// `AppModel`, so every send ended in "Messaging isn't available in this build" and no inbox was
/// ever fetched — the client layer was real, the app did not compose it.
///
/// The coordinator follows the session: it starts when the model becomes `.authenticated` and
/// stops on any other phase, so a sign-out releases every open store immediately.
@MainActor
public final class AppComposition: ObservableObject {
    public let model: AppModel
    public let coordinator: ConversationCoordinator?
    private var phaseObservation: AnyCancellable?

    public init(model: AppModel, coordinator: ConversationCoordinator?, aliasStore: ContactAliasStore?) {
        self.model = model
        self.coordinator = coordinator
        coordinator?.attach(aliasStore: aliasStore)
        phaseObservation = model.$phase
            .removeDuplicates()
            .sink { [weak self] phase in
                guard let self, let coordinator = self.coordinator else { return }
                if phase == .authenticated {
                    coordinator.start()
                } else {
                    coordinator.stop()
                }
            }
    }

    /// Foreground/background transitions from the scene. Backgrounding releases every open store
    /// and the cross-process lock so the Notification Service Extension can decrypt while we're
    /// away (ADR-0007 single-writer); foregrounding re-opens and picks up whatever it committed.
    public func sceneDidEnterBackground() {
        guard model.phase == .authenticated else { return }
        coordinator?.stop()
    }

    public func sceneDidBecomeActive() {
        guard model.phase == .authenticated else { return }
        coordinator?.start()
    }

    /// Production wiring: Keychain-rooted at-rest keys, the server from `AppConfig`, and MLS
    /// stores in the **app-group container** when the build is provisioned for one
    /// (`NedwonsAppGroup` in Info.plist) so the notification extension can decrypt — falling back
    /// to Application Support otherwise. An existing app-private store tree is migrated into the
    /// container once, so provisioning the group later doesn't strand history.
    public static func standard() -> AppComposition {
        let model = AppModel()
        let keys = AtRestKeyHierarchy(store: KeychainStore(service: "app.nedwons.at-rest"))
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Nedwons", isDirectory: true)
        let privateStores = support.appendingPathComponent("mls", isDirectory: true)
        let storeDirectory: URL
        if let group = SharedStoreLayout.configuredAppGroup(),
            let shared = SharedStoreLayout.storeDirectory(appGroup: group)
        {
            if FileManager.default.fileExists(atPath: privateStores.path),
                !FileManager.default.fileExists(atPath: shared.path)
            {
                try? FileManager.default.createDirectory(
                    at: shared.deletingLastPathComponent(), withIntermediateDirectories: true)
                try? FileManager.default.moveItem(at: privateStores, to: shared)
            }
            storeDirectory = shared
        } else {
            storeDirectory = privateStores
        }
        let coordinator = ConversationCoordinator(
            model: model,
            relay: NedwonsClient(baseURL: AppConfig.serverURL),
            storeDirectory: storeDirectory,
            keyProvider: { storeID in try keys.atRestKey(forStore: storeID) })
        // Encrypted chat backups (docs/BACKUPS.md): sealing reads the live store files, which is
        // safe alongside the coordinator (commits are atomic renames); RESTORE stops it first so
        // no store is open while files land, and start() re-reads the index after.
        let backups = BackupManager(storeDirectory: storeDirectory, keys: keys)
        model.createBackupAction = { passphrase in
            try backups.createBackup(passphrase: passphrase)
        }
        model.restoreBackupAction = { [weak model, weak coordinator] data, passphrase in
            coordinator?.stop()
            defer {
                if model?.phase == .authenticated { coordinator?.start() }
            }
            return try backups.restoreBackup(data, passphrase: passphrase)
        }
        // Aliases are encrypted at rest under their own derived key. If the Keychain is unusable
        // the feature is simply absent rather than falling back to plaintext.
        let aliasStore = (try? keys.atRestKey(forStore: "aliases")).map { key in
            ContactAliasStore(
                fileURL: support.appendingPathComponent("aliases.bin"), atRestKey: key)
        }
        return AppComposition(model: model, coordinator: coordinator, aliasStore: aliasStore)
    }

    #if DEBUG
        /// The UI-test harness: the fixture-backed model, no coordinator (the harness supplies its
        /// own in-process send path). Debug-only, like the harness itself.
        public static func uiTestHarness(scenario: UITestScenario) -> AppComposition {
            AppComposition(
                model: AppModel.uiTestHarness(scenario: scenario).0, coordinator: nil, aliasStore: nil)
        }
    #endif
}
