import NedwonsKit
import SwiftUI

/// Sign-in until there is a session, then the tabbed app. `@main` constructs the `AppModel`.
public struct AppRootView: View {
    @ObservedObject private var model: AppModel

    public init(model: AppModel) {
        self.model = model
    }

    public var body: some View {
        Group {
            if model.isLoggedIn {
                MainTabs(model: model)
            } else {
                SignInView(model: model)
            }
        }
        .overlay(alignment: .bottom) {
            if let banner = model.banner {
                Text(banner)
                    .font(Nedwons.TypeScale.caption)
                    .padding(.horizontal, Nedwons.Spacing.md)
                    .padding(.vertical, Nedwons.Spacing.sm)
                    .background(.thinMaterial, in: Capsule())
                    .padding(.bottom, Nedwons.Spacing.xl)
                    .onTapGesture { model.banner = nil }
                    .task {
                        try? await Task.sleep(nanoseconds: 3_000_000_000)
                        model.banner = nil
                    }
            }
        }
    }
}

struct SignInView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    @State private var username = ""
    @State private var password = ""

    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        VStack(alignment: .leading, spacing: Nedwons.Spacing.lg) {
            Spacer()
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 48))
                .foregroundStyle(palette.accentPrimary)
            Text("Nedwons").font(Nedwons.TypeScale.title)
            Text("Private by default. Your account is bound to this device's secure hardware.")
                .font(Nedwons.TypeScale.callout)
                .foregroundStyle(palette.textSecondary)

            TextField("Username", text: $username)
                .textFieldStyle(.roundedBorder)
            SecureField("Password", text: $password)
                .textFieldStyle(.roundedBorder)

            PrimaryButton("Sign in", palette: palette, isEnabled: canSubmit) {
                Task { await model.signIn(username: username, password: password) }
            }
            Button("Create account") {
                Task { await model.register(username: username, password: password) }
            }
            .disabled(!canSubmit)
            .frame(maxWidth: .infinity, alignment: .center)

            if model.isBusy { ProgressView().frame(maxWidth: .infinity) }
            Spacer()
        }
        .padding(Nedwons.Spacing.xl)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(palette.background)
    }

    private var canSubmit: Bool {
        username.count >= 3 && password.count >= 12 && !model.isBusy
    }
}

struct MainTabs: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        TabView {
            ChatsView(model: model)
                .tabItem { Label("Chats", systemImage: "bubble.left.and.bubble.right.fill") }
            ContactsView(model: model)
                .tabItem { Label("Contacts", systemImage: "person.2.fill") }
            SettingsRootView(model: model)
                .tabItem { Label("Settings", systemImage: "gearshape.fill") }
        }
    }
}

/// Chats: entry point to start a new group (which requires mutual friends).
struct ChatsView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    @State private var showNewGroup = false
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        NavigationStack {
            Group {
                if model.conversations.isEmpty {
                    emptyState
                } else {
                    List(model.conversations) { conversation in
                        HStack(spacing: Nedwons.Spacing.md) {
                            Image(systemName: conversation.memberAccountIDs.count > 2
                                ? "person.3.fill" : "person.fill")
                                .foregroundStyle(palette.accentPrimary)
                            VStack(alignment: .leading, spacing: Nedwons.Spacing.xxs) {
                                Text(conversation.memberAccountIDs.count > 1
                                    ? "Group · \(conversation.memberAccountIDs.count + 1) people"
                                    : "Conversation")
                                    .font(Nedwons.TypeScale.body)
                                    .foregroundStyle(palette.textPrimary)
                                SecurityBadge(.encrypted, palette: palette)
                            }
                        }
                        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                            Button(role: .destructive) {
                                Task { await model.leaveGroup(conversation.conversationID) }
                            } label: {
                                Label("Leave", systemImage: "rectangle.portrait.and.arrow.right")
                            }
                        }
                    }
                }
            }
            .background(palette.background)
            .navigationTitle("Chats")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        showNewGroup = true
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityLabel("New group")
                }
            }
            .sheet(isPresented: $showNewGroup) {
                NewGroupView(model: model)
            }
            .task { await model.refreshConversations() }
            .refreshable { await model.refreshConversations() }
        }
    }

    private var emptyState: some View {
        VStack(spacing: Nedwons.Spacing.lg) {
            Spacer()
            Image(systemName: "lock.rectangle.stack.fill")
                .font(.system(size: 44))
                .foregroundStyle(palette.accentPrimary)
            Text("Start an encrypted group")
                .font(Nedwons.TypeScale.headline)
            Text("Group anyone you like — blocked people are kept apart.")
                .font(Nedwons.TypeScale.callout)
                .foregroundStyle(palette.textSecondary)
            PrimaryButton("New group", palette: palette) { showNewGroup = true }
                .frame(maxWidth: 240)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Contacts: incoming friend requests + friends list, with a SEARCH button in the top-right
/// that opens the people-search menu (per the request to put search top-right).
struct ContactsView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    @State private var showSearch = false
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        NavigationStack {
            List {
                if !model.incomingRequests.isEmpty {
                    Section("Friend requests") {
                        ForEach(model.incomingRequests) { person in
                            HStack {
                                PersonRow(person: person)
                                Spacer()
                                Button("Accept") { Task { await model.accept(person.accountID) } }
                                    .buttonStyle(.borderedProminent)
                                Button("Decline") { Task { await model.decline(person.accountID) } }
                                    .buttonStyle(.bordered)
                            }
                        }
                    }
                }
                Section("Friends") {
                    if model.friends.isEmpty {
                        Text("No friends yet. Tap search to find people by username.")
                            .font(Nedwons.TypeScale.callout)
                            .foregroundStyle(palette.textSecondary)
                    } else {
                        ForEach(model.friends) { PersonRow(person: $0) }
                    }
                }
            }
            .navigationTitle("Contacts")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        showSearch = true
                    } label: {
                        Image(systemName: "magnifyingglass")
                    }
                    .accessibilityLabel("Search people")
                }
            }
            .sheet(isPresented: $showSearch) {
                SearchView(model: model)
            }
            .task { await model.refreshFriends() }
            .refreshable { await model.refreshFriends() }
        }
    }
}

/// The people-search menu opened from the top-right of Contacts.
struct SearchView: View {
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var scheme
    @State private var query = ""
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                HStack {
                    Image(systemName: "magnifyingglass").foregroundStyle(palette.textSecondary)
                    TextField("Search by username", text: $query)
                        .textFieldStyle(.plain)
                        .onChange(of: query) { Task { await model.search(query) } }
                }
                .padding(Nedwons.Spacing.md)
                .background(palette.surface)

                List(model.searchResults) { person in
                    HStack {
                        PersonRow(person: person)
                        Spacer()
                        if model.friends.contains(where: { $0.accountID == person.accountID }) {
                            Text("Friends").font(Nedwons.TypeScale.caption)
                                .foregroundStyle(palette.verified)
                        } else {
                            Button("Add") { Task { await model.sendFriendRequest(to: person.accountID) } }
                                .buttonStyle(.borderedProminent)
                        }
                    }
                }
            }
            .navigationTitle("Find people")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
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
                Section("Profile") {
                    NavigationLink {
                        ProfileEditView(model: model)
                    } label: {
                        VStack(alignment: .leading, spacing: Nedwons.Spacing.xxs) {
                            Text(model.myProfile?.displayName.isEmpty == false
                                ? model.myProfile!.displayName
                                : (model.myProfile?.username ?? "You"))
                                .font(Nedwons.TypeScale.headline)
                            if let username = model.myProfile?.username {
                                Text("@\(username)")
                                    .font(Nedwons.TypeScale.caption)
                                    .foregroundStyle(palette.textSecondary)
                            }
                        }
                    }
                }
                Section("Security") {
                    LabeledContent("Encryption", value: "MLS (RFC 9420)")
                    LabeledContent("Device", value: "This device (hardware-bound)")
                }
                Section {
                    Button("Sign out", role: .destructive) { model.signOut() }
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
