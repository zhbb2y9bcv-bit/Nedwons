import SwiftUI

/// Runtime feature flags. Unfinished features stay behind a disabled flag and are shown as
/// disabled controls with an explanation — never as dead buttons (per the engineering
/// rules). In this scaffold the backend is not configured, so network-dependent actions are
/// disabled rather than silently doing nothing.
public struct FeatureFlags: Sendable {
    public var backendConfigured: Bool
    public var callsEnabled: Bool
    public var groupsEnabled: Bool

    public init(
        backendConfigured: Bool = false,
        callsEnabled: Bool = false,
        groupsEnabled: Bool = false
    ) {
        self.backendConfigured = backendConfigured
        self.callsEnabled = callsEnabled
        self.groupsEnabled = groupsEnabled
    }

    public static let scaffold = FeatureFlags()
}

/// The app's tab shell: Chats, Calls, Contacts/Requests, Settings.
public struct RootView: View {
    @Environment(\.colorScheme) private var scheme
    private let flags: FeatureFlags

    public init(flags: FeatureFlags = .scaffold) {
        self.flags = flags
    }

    private var palette: Sentinel.Palette { .forScheme(scheme) }

    public var body: some View {
        TabView {
            ConversationsScreen(palette: palette)
                .tabItem { Label("Chats", systemImage: "bubble.left.and.bubble.right.fill") }

            PlaceholderScreen(
                title: "Calls",
                message: flags.callsEnabled
                    ? "No recent calls."
                    : "Encrypted calls arrive in a later release.",
                systemImage: "phone.fill",
                palette: palette
            )
            .tabItem { Label("Calls", systemImage: "phone.fill") }

            PlaceholderScreen(
                title: "Contacts",
                message: "Add people by username or QR code.",
                systemImage: "person.2.fill",
                palette: palette
            )
            .tabItem { Label("Contacts", systemImage: "person.2.fill") }

            SettingsScreen(flags: flags, palette: palette)
                .tabItem { Label("Settings", systemImage: "gearshape.fill") }
        }
    }
}

/// Conversation list with a proper empty state (the scaffold has no messages yet).
public struct ConversationsScreen: View {
    private let palette: Sentinel.Palette
    public init(palette: Sentinel.Palette) { self.palette = palette }

    public var body: some View {
        NavigationStack {
            VStack(spacing: Sentinel.Spacing.lg) {
                Spacer()
                Image(systemName: "lock.rectangle.stack.fill")
                    .font(.system(size: 44))
                    .foregroundStyle(palette.accentPrimary)
                Text("Your conversations are end-to-end encrypted")
                    .font(Sentinel.TypeScale.headline)
                    .foregroundStyle(palette.textPrimary)
                    .multilineTextAlignment(.center)
                Text("Messages you send are readable only on your and your recipient's devices.")
                    .font(Sentinel.TypeScale.callout)
                    .foregroundStyle(palette.textSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, Sentinel.Spacing.xl)
                SecurityBadge(.encrypted, palette: palette)
                Spacer()
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(palette.background)
            .navigationTitle("Chats")
        }
    }
}

public struct PlaceholderScreen: View {
    let title: String
    let message: String
    let systemImage: String
    let palette: Sentinel.Palette

    public init(title: String, message: String, systemImage: String, palette: Sentinel.Palette) {
        self.title = title
        self.message = message
        self.systemImage = systemImage
        self.palette = palette
    }

    public var body: some View {
        NavigationStack {
            VStack(spacing: Sentinel.Spacing.md) {
                Spacer()
                Image(systemName: systemImage)
                    .font(.system(size: 40))
                    .foregroundStyle(palette.textSecondary)
                Text(message)
                    .font(Sentinel.TypeScale.callout)
                    .foregroundStyle(palette.textSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, Sentinel.Spacing.xl)
                Spacer()
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(palette.background)
            .navigationTitle(title)
        }
    }
}

public struct SettingsScreen: View {
    let flags: FeatureFlags
    let palette: Sentinel.Palette

    public init(flags: FeatureFlags, palette: Sentinel.Palette) {
        self.flags = flags
        self.palette = palette
    }

    public var body: some View {
        NavigationStack {
            List {
                Section("Security") {
                    LabeledContent("This device", value: "Not yet enrolled")
                    LabeledContent("Encryption", value: "MLS (RFC 9420)")
                }
                Section("Account") {
                    LabeledContent("Status", value: flags.backendConfigured ? "Connected" : "Backend not configured")
                }
            }
            .navigationTitle("Settings")
        }
    }
}

/// Onboarding welcome + security explanation. The setup action is disabled until a backend
/// is configured, with a caption explaining why (no dead controls).
public struct OnboardingView: View {
    @Environment(\.colorScheme) private var scheme
    private let flags: FeatureFlags
    private let onSetUp: () -> Void

    public init(flags: FeatureFlags = .scaffold, onSetUp: @escaping () -> Void = {}) {
        self.flags = flags
        self.onSetUp = onSetUp
    }

    private var palette: Sentinel.Palette { .forScheme(scheme) }

    public var body: some View {
        VStack(alignment: .leading, spacing: Sentinel.Spacing.lg) {
            Spacer()
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 52))
                .foregroundStyle(palette.accentPrimary)
            Text("Private by default")
                .font(Sentinel.TypeScale.title)
                .foregroundStyle(palette.textPrimary)
            Text("""
            Sentinel binds your account to this device with a key stored in its secure \
            hardware. Your messages are end-to-end encrypted — the service never sees their \
            contents.
            """)
            .font(Sentinel.TypeScale.body)
            .foregroundStyle(palette.textSecondary)

            Spacer()

            PrimaryButton(
                "Set up secure device",
                palette: palette,
                isEnabled: flags.backendConfigured,
                action: onSetUp
            )
            if !flags.backendConfigured {
                Text("Connect a backend to enable device enrollment.")
                    .font(Sentinel.TypeScale.caption)
                    .foregroundStyle(palette.textSecondary)
                    .frame(maxWidth: .infinity, alignment: .center)
            }
        }
        .padding(Sentinel.Spacing.xl)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(palette.background)
    }
}
