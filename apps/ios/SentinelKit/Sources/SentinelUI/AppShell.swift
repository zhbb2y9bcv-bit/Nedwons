import SentinelKit
import SwiftUI

/// The full app shell (#9): a single navigable root that gates on auth and, once signed in, presents
/// the wired product — Chats, Devices (multi-device linking + key-transparency audit), and Settings —
/// backed by the live `AppModel`. This is the composition of the pieces built across #1–#8.
public struct SentinelAppRoot: View {
    @ObservedObject private var model: AppModel

    public init(model: AppModel) {
        self.model = model
    }

    public var body: some View {
        if model.isLoggedIn {
            MainAppView(model: model)
        } else {
            OnboardingView()
        }
    }
}

/// The signed-in tab shell, wired to `AppModel` (unlike the presentation-only `RootView` scaffold).
public struct MainAppView: View {
    @ObservedObject private var model: AppModel
    @Environment(\.colorScheme) private var scheme

    public init(model: AppModel) {
        self.model = model
    }

    private var palette: Sentinel.Palette { .forScheme(scheme) }

    public var body: some View {
        TabView {
            ConversationsScreen(palette: palette)
                .tabItem { Label("Chats", systemImage: "bubble.left.and.bubble.right.fill") }

            DevicesScreen(model: model, palette: palette)
                .tabItem { Label("Devices", systemImage: "laptopcomputer.and.iphone") }

            SettingsScreen(flags: FeatureFlags(backendConfigured: true), palette: palette)
                .tabItem { Label("Settings", systemImage: "gearshape.fill") }
        }
    }
}

/// Severity of a key-transparency audit result, driving the banner styling.
public enum AuditSeverity: Sendable, Equatable {
    case ok
    case warning
    case alarm
}

/// Maps an audit result to a user-facing banner (pure — unit-tested). `nil` before the first audit.
public enum DeviceAuditBanner {
    public static func present(_ audit: AccountDeviceAudit?) -> (severity: AuditSeverity, text: String)?
    {
        guard let audit else { return nil }
        switch audit {
        case .ok:
            return (.ok, "All logged devices match the ones you trust.")
        case .unexpectedDevices(let ids):
            return (
                .alarm,
                "⚠️ \(ids.count) device(s) are bound to your account that you didn't add: "
                    + ids.joined(separator: ", ") + ". Revoke them if you don't recognize them."
            )
        case .missingDevices(let ids):
            return (
                .warning,
                "\(ids.count) device(s) you trust aren't in the log yet (still propagating)."
            )
        case .discrepancy(let unexpected, _):
            return (
                .alarm,
                "⚠️ Unrecognized device(s) in the log: " + unexpected.joined(separator: ", ") + "."
            )
        case .badSignature, .logKeyChanged, .badProof:
            return (.alarm, "⚠️ The transparency log could not be verified — do not trust it.")
        }
    }
}

/// Multi-device management + key-transparency monitoring (#8/#9), wired to the backend via `AppModel`.
public struct DevicesScreen: View {
    @ObservedObject private var model: AppModel
    private let palette: Sentinel.Palette

    public init(model: AppModel, palette: Sentinel.Palette) {
        self.model = model
        self.palette = palette
    }

    public var body: some View {
        NavigationStack {
            List {
                if let banner = DeviceAuditBanner.present(model.deviceAudit) {
                    Section {
                        Text(banner.text)
                            .font(Sentinel.TypeScale.callout)
                            .foregroundStyle(bannerColor(banner.severity))
                    } header: {
                        Text("Key transparency")
                    }
                }

                Section("Your devices") {
                    if model.devices.isEmpty {
                        Text("No devices loaded — pull to refresh.")
                            .foregroundStyle(palette.textSecondary)
                    }
                    ForEach(model.devices) { device in
                        HStack {
                            VStack(alignment: .leading) {
                                Text(device.current ? "This device" : shortID(device.deviceID))
                                    .font(Sentinel.TypeScale.callout)
                                    .foregroundStyle(palette.textPrimary)
                                if device.revoked {
                                    Text("revoked").foregroundStyle(.red).font(.caption)
                                }
                            }
                            Spacer()
                            if !device.revoked && !model.acknowledgedDeviceIDs.contains(device.deviceID) {
                                Button("Recognize") { model.acknowledgeDevice(device.deviceID) }
                                    .font(.caption)
                            }
                        }
                    }
                }

                if !model.pendingLinkDevices.isEmpty {
                    Section("Waiting to link") {
                        Text("\(model.pendingLinkDevices.count) device(s) ready to join your secure device group.")
                            .foregroundStyle(palette.textSecondary)
                        Button {
                            Task { await model.linkPendingDevices() }
                        } label: {
                            HStack {
                                Text(model.isLinking ? "Linking…" : "Link \(model.pendingLinkDevices.count) device(s)")
                                if model.isLinking {
                                    Spacer()
                                    ProgressView()
                                }
                            }
                        }
                        .disabled(model.isLinking)
                    }
                }

                Section {
                    Button("Check the transparency log") { Task { await model.auditDevices() } }
                    Button("Refresh devices") { Task { await model.refreshDevices() } }
                }
            }
            .navigationTitle("Devices")
            .task { await model.refreshDevices() }
        }
    }

    private func bannerColor(_ severity: AuditSeverity) -> Color {
        switch severity {
        case .ok: return palette.textSecondary
        case .warning: return .orange
        case .alarm: return .red
        }
    }

    private func shortID(_ id: String) -> String {
        id.count > 8 ? String(id.prefix(8)) + "…" : id
    }
}
