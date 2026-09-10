import NedwonsKit
import SwiftUI

/// The single app root. It renders exactly one `AppPhase`, so protected content is unreachable
/// until a session is validated. This is the ONLY root view: an earlier build shipped a second,
/// unwired shell that showed a dead onboarding scaffold instead of an auth form.
public struct NedwonsAppRoot: View {
    @ObservedObject private var model: AppModel

    public init(model: AppModel) {
        self.model = model
    }

    public var body: some View {
        Group {
            switch model.phase {
            case .booting:
                BootingView()
            case .unauthenticated, .authenticating:
                WelcomeView(model: model)
            case .authenticated:
                MainAppView(model: model)
            case .sessionExpired:
                SessionExpiredView(model: model)
            case .fatalRecoveryRequired(let reason):
                RecoveryRequiredView(reason: reason, model: model)
            }
        }
        .overlay(alignment: .bottom) { bannerOverlay }
        .overlay(alignment: .top) { securityNoticeOverlay }
        // App lock sits in FRONT of everything — including the banner — so a protected app shows
        // nothing until the owner authenticates. Only present when enabled AND currently locked.
        .overlay {
            if model.appLockEnabled && model.isLocked {
                LockScreenView(model: model)
                    .transition(.opacity)
            }
        }
        .task { await model.restoreSession() }
    }

    @ViewBuilder
    private var bannerOverlay: some View {
        if let banner = model.banner {
            Text(banner)
                .font(Nedwons.TypeScale.caption)
                .multilineTextAlignment(.center)
                .padding(.horizontal, Nedwons.Spacing.md)
                .padding(.vertical, Nedwons.Spacing.sm)
                .background(.thinMaterial, in: Capsule())
                .padding(.horizontal, Nedwons.Spacing.lg)
                .padding(.bottom, Nedwons.Spacing.xl)
                .onTapGesture { model.banner = nil }
                .task {
                    try? await Task.sleep(nanoseconds: 3_000_000_000)
                    model.banner = nil
                }
        }
    }

    /// A security refusal — something the app declined to apply, such as a group membership change
    /// whose signed description did not match what it actually did (ADR-0010).
    ///
    /// Deliberately unlike the banner below it: at the TOP, in the warning colour, and it does NOT
    /// time out. A message that disappears after three seconds is the wrong shape for "we refused to
    /// change who is in your group" — the user dismisses this one themselves.
    @ViewBuilder
    private var securityNoticeOverlay: some View {
        if let notice = model.securityNotice {
            HStack(alignment: .top, spacing: Nedwons.Spacing.sm) {
                Image(systemName: "exclamationmark.shield.fill")
                    .foregroundStyle(.orange)
                    .accessibilityHidden(true)
                Text(notice)
                    .font(Nedwons.TypeScale.caption)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                Button {
                    model.securityNotice = nil
                } label: {
                    Image(systemName: "xmark")
                        .font(Nedwons.TypeScale.caption)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Dismiss")
            }
            .padding(Nedwons.Spacing.md)
            .background(.thinMaterial, in: RoundedRectangle(cornerRadius: Nedwons.Radius.md))
            .padding(.horizontal, Nedwons.Spacing.md)
            .accessibilityElement(children: .contain)
            .accessibilityAddTraits(.isStaticText)
        }
    }
}

/// The signed-in tab shell. Each tab owns an independent `NavigationStack`, so switching tabs
/// preserves each stack's position and no screen can trap the root.
public struct MainAppView: View {
    @ObservedObject private var model: AppModel
    @Environment(\.colorScheme) private var scheme

    public init(model: AppModel) {
        self.model = model
    }

    private var palette: Nedwons.Palette { .forScheme(scheme) }

    public var body: some View {
        TabView {
            ChatsListView(model: model)
                .tabItem { Label("Chats", systemImage: "bubble.left.and.bubble.right.fill") }

            PeopleView(model: model)
                .tabItem { Label("People", systemImage: "person.2.fill") }

            SettingsRootView(model: model)
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
    private let palette: Nedwons.Palette
    /// Device id awaiting revoke confirmation.
    @State private var revoking: String?

    public init(model: AppModel, palette: Nedwons.Palette) {
        self.model = model
        self.palette = palette
    }

    public var body: some View {
        NavigationStack {
            List {
                if let banner = DeviceAuditBanner.present(model.deviceAudit) {
                    Section {
                        Text(banner.text)
                            .font(Nedwons.TypeScale.callout)
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
                                    .font(Nedwons.TypeScale.callout)
                                    .foregroundStyle(palette.textPrimary)
                                if device.revoked {
                                    Text("revoked").foregroundStyle(.red).font(.caption)
                                }
                            }
                            Spacer()
                            if !device.revoked && !model.acknowledgedDeviceIDs.contains(device.deviceID) {
                                Button("Recognize") { model.acknowledgeDevice(device.deviceID) }
                                    .font(.caption)
                                    .accessibilityLabel("Recognize this device as yours")
                            }
                        }
                        // Revoking a lost or stolen device is the point of this screen, so it is a
                        // swipe action on the row rather than buried in a submenu. The current
                        // device is excluded: signing yourself out through "device management" is a
                        // confusing way to lose access, and Sign out is the honest control.
                        .swipeActions(edge: .trailing) {
                            if !device.revoked && !device.current {
                                Button(role: .destructive) {
                                    revoking = device.deviceID
                                } label: {
                                    Label("Revoke", systemImage: "xmark.shield")
                                }
                            }
                        }
                        .accessibilityLabel(
                            device.current
                                ? "This device"
                                : "Device \(shortID(device.deviceID))"
                                    + (device.revoked ? ", revoked" : ""))
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
            .confirmationDialog(
                "Revoke this device?",
                isPresented: Binding(
                    get: { revoking != nil },
                    set: { if !$0 { revoking = nil } }),
                titleVisibility: .visible
            ) {
                Button("Revoke", role: .destructive) {
                    if let id = revoking {
                        Task { await model.revokeDevice(id) }
                    }
                    revoking = nil
                }
                Button("Cancel", role: .cancel) { revoking = nil }
            } message: {
                Text(
                    "Its sessions end immediately and it can no longer send or read messages. "
                        + "This cannot be undone — that device would have to be enrolled again.")
            }
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
