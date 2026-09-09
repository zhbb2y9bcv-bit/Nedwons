import Foundation
import NedwonsKit

#if os(iOS)
    import MetricKit
#endif

/// Opt-in crash/hang diagnostics via MetricKit — Apple's on-device pipeline, no tracking SDK.
///
/// OFF by default. When the user enables it (Settings → Privacy), MetricKit's DIAGNOSTIC payloads
/// (crash and hang reports: stack traces, OS/app versions — never message content, never
/// identifiers we add) are posted to `/v1/diagnostics` UNAUTHENTICATED, so a crash report cannot
/// double as a tracking record. Turning the toggle off unsubscribes immediately.
@MainActor
public final class DiagnosticsReporter: NSObject, ObservableObject {
    public static let defaultsKey = "nedwons.diagnostics.optin"

    private let client: NedwonsClient
    private let defaults: UserDefaults
    @Published public private(set) var enabled: Bool

    public init(client: NedwonsClient, defaults: UserDefaults = .standard) {
        self.client = client
        self.defaults = defaults
        self.enabled = defaults.bool(forKey: Self.defaultsKey) // absent = false = OFF
        super.init()
        if enabled { subscribe() }
    }

    public func setEnabled(_ on: Bool) {
        enabled = on
        defaults.set(on, forKey: Self.defaultsKey)
        if on { subscribe() } else { unsubscribe() }
    }

    private func subscribe() {
        #if os(iOS)
            MXMetricManager.shared.add(self)
        #endif
    }

    private func unsubscribe() {
        #if os(iOS)
            MXMetricManager.shared.remove(self)
        #endif
    }

    func submit(json: Data) {
        guard enabled, let payload = String(data: json, encoding: .utf8) else { return }
        let client = self.client
        Task.detached {
            try? await client.submitDiagnostics(payload)
        }
    }
}

#if os(iOS)
    extension DiagnosticsReporter: MXMetricManagerSubscriber {
        /// Diagnostics ONLY (crashes, hangs) — the metric payloads (battery, launch times) are
        /// deliberately not collected: they add tracking surface for no debugging value here.
        public nonisolated func didReceive(_ payloads: [MXDiagnosticPayload]) {
            for payload in payloads {
                let json = payload.jsonRepresentation()
                Task { @MainActor [weak self] in self?.submit(json: json) }
            }
        }
    }
#endif
