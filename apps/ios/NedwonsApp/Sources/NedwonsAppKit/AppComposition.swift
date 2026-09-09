import Combine
import Foundation
import NedwonsKit
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

    /// Production wiring: Keychain-rooted at-rest keys, stores under Application Support, the
    /// server from `AppConfig`.
    public static func standard() -> AppComposition {
        let model = AppModel()
        let keys = AtRestKeyHierarchy(store: KeychainStore(service: "app.nedwons.at-rest"))
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Nedwons", isDirectory: true)
        let coordinator = ConversationCoordinator(
            model: model,
            relay: NedwonsClient(baseURL: AppConfig.serverURL),
            storeDirectory: support.appendingPathComponent("mls", isDirectory: true),
            keyProvider: { storeID in try keys.atRestKey(forStore: storeID) })
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
