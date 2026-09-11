import NedwonsKit
import SwiftUI

/// Shown while a stored session is validated. Deliberately branded and content-free: protected
/// screens must never flash before `AppModel.restoreSession()` resolves.
struct BootingView: View {
    @Environment(\.colorScheme) private var scheme
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        VStack(spacing: Nedwons.Spacing.lg) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 56))
                .foregroundStyle(palette.accentPrimary)
            Text("Nedwons")
                .font(Nedwons.TypeScale.title)
                .foregroundStyle(palette.textPrimary)
            ProgressView()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(palette.background)
    }
}

/// First launch: brand, a short privacy statement, and the two entry points.
struct WelcomeView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    @State private var showRegister = false
    @State private var showLogin = false
    @State private var showPairing = false
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        VStack(alignment: .leading, spacing: Nedwons.Spacing.lg) {
            Spacer()
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 56))
                .foregroundStyle(palette.accentPrimary)
            Text("Nedwons")
                .font(Nedwons.TypeScale.title)
                .foregroundStyle(palette.textPrimary)
            Text("""
                Messages are end-to-end encrypted on your device. The service relays them without \
                ever holding the keys to read them. Your account is bound to this device's secure \
                hardware, so your password alone is not enough to sign in somewhere else.
                """)
                .font(Nedwons.TypeScale.callout)
                .foregroundStyle(palette.textSecondary)

            Spacer()

            PrimaryButton("Create account", palette: palette, isEnabled: !model.isBusy) {
                showRegister = true
            }
            Button("Log in") { showLogin = true }
                .disabled(model.isBusy)
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.top, Nedwons.Spacing.xs)
            // The third path onto an account, and the only one that needs no password: an existing
            // device vouches for this one by signing its key (ADR-0008). Offered here because a
            // second phone has nothing to log in WITH — a password alone can never enroll a device
            // (INV-2), so without this entry point the flow is unreachable.
            Button("Add this device to an existing account") { showPairing = true }
                .disabled(model.isBusy)
                .font(Nedwons.TypeScale.callout)
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.top, Nedwons.Spacing.xs)
        }
        .padding(Nedwons.Spacing.xl)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(palette.background)
        .sheet(isPresented: $showRegister) { RegisterView(model: model) }
        .sheet(isPresented: $showLogin) { LoginView(model: model) }
        .sheet(isPresented: $showPairing) {
            NavigationStack {
                PairNewDeviceView(model: model.pairingModel(role: .newDevice))
            }
        }
    }
}

/// Registration. The username is permanent, so the rule is stated before submission and must be
/// explicitly acknowledged — it can never be edited afterwards (enforced in Settings and by the
/// backend, which has no username-update path at all).
struct RegisterView: View {
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var scheme
    @State private var username = ""
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var acceptedPermanence = false
    @State private var availability: Availability = .unknown
    @State private var availabilityTask: Task<Void, Never>?
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    enum Availability: Equatable {
        case unknown, checking, available, taken
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack {
                        TextField("Username", text: $username)
                            .usernameInput()
                        availabilityBadge
                    }
                    if let problem = usernameProblem {
                        Text(problem).font(Nedwons.TypeScale.caption).foregroundStyle(.orange)
                    } else if availability == .taken {
                        Text("That username is taken.")
                            .font(Nedwons.TypeScale.caption)
                            .foregroundStyle(.orange)
                            .accessibilityIdentifier("register.taken")
                    }
                } header: {
                    Text("Username")
                } footer: {
                    Text("Your username is permanent and cannot be changed later.")
                        .foregroundStyle(.orange)
                }
                .onChange(of: username) { _, candidate in
                    checkAvailability(of: candidate)
                }

                Section("Password") {
                    SecureField("Password", text: $password)
                    SecureField("Confirm password", text: $confirmPassword)
                    if !password.isEmpty && password.count < 12 {
                        Text("Use at least 12 characters.")
                            .font(Nedwons.TypeScale.caption)
                            .foregroundStyle(.orange)
                    }
                    if !confirmPassword.isEmpty && confirmPassword != password {
                        Text("Passwords don't match.")
                            .font(Nedwons.TypeScale.caption)
                            .foregroundStyle(.orange)
                    }
                }

                Section {
                    Toggle(isOn: $acceptedPermanence) {
                        Text("I understand my username is permanent.")
                            .font(Nedwons.TypeScale.callout)
                    }
                }

                Section {
                    Button {
                        Task {
                            await model.register(username: username, password: password)
                            if model.isLoggedIn { dismiss() }
                        }
                    } label: {
                        HStack {
                            Text("Create account")
                            if model.isBusy {
                                Spacer()
                                ProgressView()
                            }
                        }
                    }
                    .disabled(!canSubmit)
                } footer: {
                    Text("This device will be enrolled with a key held in its secure hardware.")
                }
            }
            .navigationTitle("Create account")
            .inlineNavigationTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(model.isBusy)
                }
            }
        }
    }

    @ViewBuilder
    private var availabilityBadge: some View {
        switch availability {
        case .checking:
            ProgressView().controlSize(.small)
        case .available:
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(palette.verified)
                .accessibilityLabel("Username available")
        case .taken:
            Image(systemName: "xmark.circle.fill")
                .foregroundStyle(.orange)
                .accessibilityLabel("Username taken")
        case .unknown:
            EmptyView()
        }
    }

    /// Debounced live check. Failure (offline, rate-limited) quietly returns to `unknown` — the
    /// authoritative answer is registration itself; this is a convenience, never a gate.
    private func checkAvailability(of candidate: String) {
        availabilityTask?.cancel()
        let trimmed = candidate.trimmingCharacters(in: .whitespaces)
        guard usernameProblem == nil, trimmed.count >= 3 else {
            availability = .unknown
            return
        }
        availability = .checking
        availabilityTask = Task {
            try? await Task.sleep(nanoseconds: 400_000_000)
            guard !Task.isCancelled else { return }
            do {
                let free = try await model.client.usernameAvailable(trimmed)
                guard !Task.isCancelled else { return }
                availability = free ? .available : .taken
            } catch {
                guard !Task.isCancelled else { return }
                availability = .unknown
            }
        }
    }

    /// Mirrors the server's normalization rules rather than inventing a second username format.
    private var usernameProblem: String? {
        let trimmed = username.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return nil }
        if trimmed.count < 3 { return "At least 3 characters." }
        if trimmed.count > 32 { return "At most 32 characters." }
        if !trimmed.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "." }) {
            return "Letters, numbers, underscore and dot only."
        }
        return nil
    }

    private var canSubmit: Bool {
        usernameProblem == nil
            && username.trimmingCharacters(in: .whitespaces).count >= 3
            && password.count >= 12
            && password == confirmPassword
            && acceptedPermanence
            && !model.isBusy
    }
}

/// Sign-in for an account already enrolled on this device. Errors stay generic so a failed attempt
/// never reveals whether the username exists.
struct LoginView: View {
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var username = ""
    @State private var password = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Account") {
                    TextField("Username", text: $username)
                        .usernameInput()
                    SecureField("Password", text: $password)
                }
                Section {
                    Button {
                        Task {
                            await model.signIn(username: username, password: password)
                            if model.isLoggedIn { dismiss() }
                        }
                    } label: {
                        HStack {
                            Text("Log in")
                            if model.isBusy {
                                Spacer()
                                ProgressView()
                            }
                        }
                    }
                    .disabled(username.count < 3 || password.count < 12 || model.isBusy)
                } footer: {
                    Text("""
                        Signing in requires this device's enrolled key. To use a new device, add it \
                        from a device you already trust, or recover your account.
                        """)
                }
            }
            .navigationTitle("Log in")
            .inlineNavigationTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(model.isBusy)
                }
            }
        }
    }
}

/// A stored session the server rejected. Distinct from a fresh install so the message can explain
/// what happened rather than silently dumping the user at a signup form.
struct SessionExpiredView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    @State private var showLogin = false
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        VStack(spacing: Nedwons.Spacing.lg) {
            Spacer()
            Image(systemName: "clock.badge.exclamationmark")
                .font(.system(size: 44))
                .foregroundStyle(palette.accentSecondary)
            Text("Your session expired")
                .font(Nedwons.TypeScale.headline)
                .foregroundStyle(palette.textPrimary)
            Text("Log in again to continue. Your messages stay on this device.")
                .font(Nedwons.TypeScale.callout)
                .foregroundStyle(palette.textSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, Nedwons.Spacing.xl)
            PrimaryButton("Log in", palette: palette) { showLogin = true }
                .frame(maxWidth: 240)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(palette.background)
        .sheet(isPresented: $showLogin) { LoginView(model: model) }
    }
}

/// Local state is unusable and the user must re-enroll. Never silently wipes anything.
struct RecoveryRequiredView: View {
    let reason: String
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    @State private var showLogin = false
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        VStack(spacing: Nedwons.Spacing.lg) {
            Spacer()
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 44))
                .foregroundStyle(.orange)
            Text("This device needs to be set up again")
                .font(Nedwons.TypeScale.headline)
                .multilineTextAlignment(.center)
            Text(reason)
                .font(Nedwons.TypeScale.callout)
                .foregroundStyle(palette.textSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, Nedwons.Spacing.xl)
            PrimaryButton("Log in", palette: palette) { showLogin = true }
                .frame(maxWidth: 240)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(palette.background)
        .sheet(isPresented: $showLogin) { LoginView(model: model) }
    }
}
