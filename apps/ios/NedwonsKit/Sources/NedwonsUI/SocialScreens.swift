import NedwonsKit
import SwiftUI

/// The People tab: find someone by username, act on pending requests, and open saved contacts.
struct PeopleView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    @State private var query = ""
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        NavigationStack {
            List {
                if !query.trimmingCharacters(in: .whitespaces).isEmpty {
                    searchSection
                } else {
                    if !model.incomingRequests.isEmpty {
                        Section("Requests") {
                            ForEach(model.incomingRequests) { person in
                                HStack {
                                    PersonRow(person: person)
                                    Spacer()
                                    Button("Accept") {
                                        Task { await model.accept(person.accountID) }
                                    }
                                    .buttonStyle(.borderedProminent)
                                    Button("Decline") {
                                        Task { await model.decline(person.accountID) }
                                    }
                                    .buttonStyle(.bordered)
                                }
                            }
                        }
                    }
                    Section("Contacts") {
                        if model.friends.isEmpty {
                            Text("No contacts yet. Search a username above to find someone.")
                                .font(Nedwons.TypeScale.callout)
                                .foregroundStyle(palette.textSecondary)
                        } else {
                            ForEach(model.friends) { PersonRow(person: $0) }
                        }
                    }
                }
            }
            .navigationTitle("People")
            .searchable(text: $query, prompt: "Search by username")
            .onChange(of: query) { model.searchDebounced(query) }
            .task { await model.refreshFriends() }
            .refreshable { await model.refreshFriends() }
        }
    }

    /// Every search state is explicit: too-short, loading, failed, empty, results.
    @ViewBuilder
    private var searchSection: some View {
        Section("Results") {
            let trimmed = query.trimmingCharacters(in: .whitespaces)
            if trimmed.count < 2 {
                Text("Type at least 2 characters.")
                    .font(Nedwons.TypeScale.callout)
                    .foregroundStyle(palette.textSecondary)
            } else if model.isSearching {
                HStack { ProgressView(); Text("Searching…") }
            } else if model.searchFailed {
                VStack(alignment: .leading, spacing: Nedwons.Spacing.xs) {
                    Text("Search failed.").foregroundStyle(.orange)
                    Button("Try again") { Task { await model.search(trimmed) } }
                }
            } else if model.searchResults.isEmpty {
                Text("No one found with that username.")
                    .font(Nedwons.TypeScale.callout)
                    .foregroundStyle(palette.textSecondary)
            } else {
                ForEach(model.searchResults) { person in
                    HStack {
                        PersonRow(person: person)
                        Spacer()
                        if model.friends.contains(where: { $0.accountID == person.accountID }) {
                            Text("Contact")
                                .font(Nedwons.TypeScale.caption)
                                .foregroundStyle(palette.verified)
                        } else {
                            Button("Add") {
                                Task { await model.sendFriendRequest(to: person.accountID) }
                            }
                            .buttonStyle(.borderedProminent)
                        }
                    }
                }
            }
        }
    }
}

/// Compose: search a registered user, then open (or reuse) the encrypted conversation with them.
struct NewMessageView: View {
    @ObservedObject var model: AppModel
    let onOpen: (ChatSummary) -> Void

    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var scheme
    @State private var query = ""
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if model.isSearching {
                        HStack { ProgressView(); Text("Searching…") }
                    } else if model.searchFailed {
                        Button("Search failed — try again") {
                            Task { await model.search(query) }
                        }
                        .foregroundStyle(.orange)
                    } else if query.trimmingCharacters(in: .whitespaces).count >= 2
                        && model.searchResults.isEmpty
                    {
                        Text("No one found with that username.")
                            .foregroundStyle(palette.textSecondary)
                    }
                    ForEach(model.searchResults) { person in
                        Button {
                            Task { await open(person) }
                        } label: {
                            HStack {
                                PersonRow(person: person)
                                Spacer()
                                Image(systemName: "bubble.left.fill")
                                    .foregroundStyle(palette.accentPrimary)
                            }
                        }
                        .buttonStyle(.plain)
                    }
                } header: {
                    Text("Find someone")
                } footer: {
                    Text("Usernames are permanent, so searching one always finds the same account.")
                }

                if !model.friends.isEmpty {
                    Section("Contacts") {
                        ForEach(model.friends) { person in
                            Button { Task { await open(person) } } label: {
                                PersonRow(person: person)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
            }
            .navigationTitle("New message")
            .inlineNavigationTitle()
            .searchable(text: $query, prompt: "Search by username")
            .onChange(of: query) { model.searchDebounced(query) }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
            .task { await model.refreshFriends() }
        }
    }

    /// Reuses the existing 1:1 conversation when there is one, so a duplicate thread is never made.
    private func open(_ person: ProfileSummary) async {
        if let chat = await model.openDirectConversation(with: person) {
            onOpen(chat)
        }
    }
}

/// Create a group by selecting people (friends are the suggested pool). Members need not be
/// friends (ADR-0009); the server refuses only if the group would contain a blocked pair.
struct NewGroupView: View {
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var scheme
    @State private var selected: Set<String> = []
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        NavigationStack {
            List {
                Section("Add friends") {
                    if model.friends.isEmpty {
                        Text("No friends yet. Add people by username to start a group.")
                            .font(Nedwons.TypeScale.callout)
                            .foregroundStyle(palette.textSecondary)
                    }
                    ForEach(model.friends) { friend in
                        Button {
                            toggle(friend.accountID)
                        } label: {
                            HStack {
                                PersonRow(person: friend)
                                Spacer()
                                Image(systemName: selected.contains(friend.accountID) ? "checkmark.circle.fill" : "circle")
                                    .foregroundStyle(selected.contains(friend.accountID) ? palette.accentPrimary : palette.textSecondary)
                            }
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            .navigationTitle("New group")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("Create") {
                        Task {
                            if await model.createGroup(memberAccountIDs: Array(selected)) != nil {
                                dismiss()
                            }
                        }
                    }
                    .disabled(selected.isEmpty || model.isBusy)
                }
            }
            .task { await model.refreshFriends() }
        }
    }

    private func toggle(_ id: String) {
        if selected.contains(id) { selected.remove(id) } else { selected.insert(id) }
    }
}

struct SettingsRootView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    NavigationLink {
                        ProfileEditView(model: model)
                    } label: {
                        VStack(alignment: .leading, spacing: Nedwons.Spacing.xxs) {
                            Text(model.myProfile?.displayName.isEmpty == false
                                ? model.myProfile!.displayName
                                : (model.myProfile?.username ?? "You"))
                                .font(Nedwons.TypeScale.headline)
                            Text("Edit display name and bio")
                                .font(Nedwons.TypeScale.caption)
                                .foregroundStyle(palette.textSecondary)
                        }
                    }
                } header: {
                    Text("Profile")
                }

                // Read-only by design: there is no username field to edit here, no client request
                // that could change it, and no backend route that mutates it.
                Section {
                    LabeledContent("Username", value: model.myProfile.map { "@\($0.username)" } ?? "—")
                } header: {
                    Text("Account")
                } footer: {
                    Text("Your username is permanent and cannot be changed.")
                }

                Section("Security") {
                    LabeledContent("Encryption", value: "MLS (RFC 9420)")
                    LabeledContent("Key exchange", value: "Hybrid post-quantum (X-Wing)")
                    NavigationLink("Devices and key transparency") {
                        DevicesScreen(model: model, palette: palette)
                    }
                }

                Section {
                    Button("Sign out", role: .destructive) { model.signOut() }
                }

                // Apple requires an in-app deletion path for any app that creates accounts, and it
                // must not be a link to a website or a support email.
                Section {
                    NavigationLink("Delete account") {
                        DeleteAccountView(model: model)
                    }
                    .foregroundStyle(.red)
                } footer: {
                    Text(
                        """
                        Deleting removes your account, profile, contacts, group membership and \
                        anything still queued for delivery. Messages other people already \
                        received stay on their devices — deleting your account is not an unsend.
                        """)
                }
            }
            .navigationTitle("Settings")
        }
    }
}

struct ProfileEditView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    @State private var displayName = ""
    @State private var bio = ""
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        Form {
            Section("Display name") {
                TextField("Name", text: $displayName)
            }
            Section("Bio") {
                TextField("Bio", text: $bio, axis: .vertical)
            }
            Section {
                Button("Save") {
                    Task { await model.saveProfile(displayName: displayName, bio: bio) }
                }
                .disabled(model.isBusy)
            }
        }
        .navigationTitle("Edit profile")
        .onAppear {
            displayName = model.myProfile?.displayName ?? ""
            bio = model.myProfile?.bio ?? ""
        }
    }
}

/// A compact username/display-name row used across lists.
struct PersonRow: View {
    let person: ProfileSummary
    @Environment(\.colorScheme) private var scheme
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        VStack(alignment: .leading, spacing: Nedwons.Spacing.xxs) {
            Text(person.displayName.isEmpty ? person.username : person.displayName)
                .font(Nedwons.TypeScale.body)
                .foregroundStyle(palette.textPrimary)
            Text("@\(person.username)")
                .font(Nedwons.TypeScale.caption)
                .foregroundStyle(palette.textSecondary)
        }
    }
}

/// In-app account deletion (App Store requirement).
///
/// The screen is deliberately slow to get through. Deletion is irreversible and erases across every
/// store, so it asks for the password, requires an explicit acknowledgement, and confirms once more
/// — three deliberate acts rather than one destructive tap. The consequences are stated plainly
/// BEFORE the button, including the one people get wrong: this is not an unsend.
struct DeleteAccountView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme

    @State private var password = ""
    @State private var acknowledged = false
    @State private var confirming = false
    @State private var working = false
    @State private var failure: String?

    private var palette: Nedwons.Palette { .forScheme(scheme) }

    private var canDelete: Bool {
        acknowledged && !password.isEmpty && !working
    }

    var body: some View {
        Form {
            Section {
                Text("Deleting your account is permanent. It cannot be undone.")
                    .font(Nedwons.TypeScale.callout)
                    .foregroundStyle(palette.textPrimary)
            }

            Section("What is deleted") {
                Label("Your username and profile", systemImage: "person.crop.circle")
                Label("Your contacts, requests and blocks", systemImage: "person.2")
                Label("Your group membership", systemImage: "bubble.left.and.bubble.right")
                Label("Messages still waiting to reach you", systemImage: "tray")
                Label("This device's keys and local history", systemImage: "key")
            }

            Section {
                Label(
                    "Messages other people already received stay on their devices.",
                    systemImage: "exclamationmark.triangle")
                Label(
                    "Your username becomes available for someone else to register.",
                    systemImage: "at")
            } header: {
                Text("What is not deleted")
            } footer: {
                // Said plainly because it is the expectation people most often have backwards.
                Text(
                    "Deleting your account is not an unsend. Nedwons cannot reach into anyone "
                        + "else's device to remove messages you already sent.")
            }

            Section {
                SecureField("Your password", text: $password)
                    .usernameInput()
                Toggle("I understand this cannot be undone", isOn: $acknowledged)
            } footer: {
                Text(
                    "Your password and this device's key are both required, so a stolen session "
                        + "alone cannot delete your account.")
            }

            if let failure {
                Section {
                    Text(failure).foregroundStyle(.red)
                }
            }

            Section {
                Button(role: .destructive) {
                    confirming = true
                } label: {
                    HStack {
                        Text(working ? "Deleting…" : "Delete my account")
                        if working {
                            Spacer()
                            ProgressView()
                        }
                    }
                }
                .disabled(!canDelete)
            }
        }
        .navigationTitle("Delete account")
        .inlineNavigationTitle()
        .confirmationDialog(
            "Permanently delete your account?",
            isPresented: $confirming,
            titleVisibility: .visible
        ) {
            Button("Delete permanently", role: .destructive) {
                Task { await performDeletion() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This cannot be undone.")
        }
    }

    private func performDeletion() async {
        working = true
        failure = nil
        // On success the model transitions to `.unauthenticated`, so the app root swaps this
        // screen out from underneath us — there is nothing to navigate back to.
        failure = await model.deleteAccount(password: password)
        working = false
        password = ""
    }
}
