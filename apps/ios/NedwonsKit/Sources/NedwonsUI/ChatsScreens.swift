import NedwonsKit
import SwiftUI

/// A conversation as the list renders it. Previews are derived on-device from decrypted local
/// history — never from a server field, which would require the relay to see plaintext (INV-1).
public struct ChatSummary: Identifiable, Sendable, Hashable {
    public let conversationID: String
    /// The immutable account id of the other party in a 1:1 thread; `nil` for groups. Aliases and
    /// profile lookups key off this, never off the username.
    public let peerAccountID: String?
    public let peerUsername: String?
    public let memberCount: Int
    public let lastMessagePreview: String?
    public let lastActivity: Date?
    public let unreadCount: Int

    public var id: String { conversationID }
    public var isGroup: Bool { memberCount > 2 }

    public init(
        conversationID: String,
        peerAccountID: String? = nil,
        peerUsername: String? = nil,
        memberCount: Int = 2,
        lastMessagePreview: String? = nil,
        lastActivity: Date? = nil,
        unreadCount: Int = 0
    ) {
        self.conversationID = conversationID
        self.peerAccountID = peerAccountID
        self.peerUsername = peerUsername
        self.memberCount = memberCount
        self.lastMessagePreview = lastMessagePreview
        self.lastActivity = lastActivity
        self.unreadCount = unreadCount
    }
}

/// Most recent legitimate activity first; threads without activity fall to the bottom but stay
/// listed, so a freshly created conversation is still reachable.
public func sortedByRecency(_ chats: [ChatSummary]) -> [ChatSummary] {
    chats.sorted { a, b in
        switch (a.lastActivity, b.lastActivity) {
        case let (l?, r?): return l > r
        case (_?, nil): return true
        case (nil, _?): return false
        case (nil, nil): return a.conversationID < b.conversationID
        }
    }
}

/// The Chats tab: every conversation this account takes part in, with compose, long-press delete,
/// and navigation that always returns here.
struct ChatsListView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    @State private var path = NavigationPath()
    @State private var showCompose = false
    @State private var showJoin = false
    @State private var pendingDelete: ChatSummary?
    @State private var searchQuery = ""
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        NavigationStack(path: $path) {
            Group {
                if !searchQuery.trimmingCharacters(in: .whitespaces).isEmpty {
                    searchResults
                } else if model.isBusy && model.conversations.isEmpty {
                    ProgressView("Loading conversations…")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if chats.isEmpty {
                    emptyState
                } else {
                    list
                }
            }
            .background(palette.background)
            .navigationTitle("Chats")
            // On-device search over DECRYPTED local history. There is deliberately no server-side
            // search: the relay holds only ciphertext and has nothing to answer with.
            .searchable(text: $searchQuery, prompt: "Search messages")
            .onChange(of: searchQuery) { _, q in model.searchMessages(q) }
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button { showCompose = true } label: { Image(systemName: "square.and.pencil") }
                        .accessibilityLabel("New message")
                }
                ToolbarItem(placement: .secondaryAction) {
                    Button { showJoin = true } label: {
                        Label("Join with invite", systemImage: "qrcode.viewfinder")
                    }
                    .accessibilityIdentifier("chats.join")
                }
            }
            .navigationDestination(for: ChatSummary.self) { chat in
                ConversationView(model: model, chat: chat)
            }
            .sheet(isPresented: $showCompose) {
                NewMessageView(model: model) { chat in
                    showCompose = false
                    path.append(chat)
                }
            }
            .sheet(isPresented: $showJoin) {
                NavigationStack { JoinByInviteView(model: model) }
            }
            .task { await model.refreshConversations() }
            .refreshable { await model.refreshConversations() }
            .confirmationDialog(
                "Delete conversation?",
                isPresented: Binding(
                    get: { pendingDelete != nil },
                    set: { if !$0 { pendingDelete = nil } }),
                titleVisibility: .visible
            ) {
                Button("Delete conversation", role: .destructive) {
                    if let chat = pendingDelete {
                        Task { await model.deleteConversationLocally(chat.conversationID) }
                    }
                    pendingDelete = nil
                }
                Button("Cancel", role: .cancel) { pendingDelete = nil }
            } message: {
                Text("""
                    This removes the conversation history from this device. It does not delete it \
                    from the other person's device.
                    """)
            }
        }
    }

    /// Derived from the server's conversation list (routing metadata only) joined with local
    /// display state. Previews come from decrypted on-device history, never from the relay.
    private var chats: [ChatSummary] {
        sortedForChatList(model.chatSummaries, prefs: model.chatPrefs)
    }

    private var archivedChats: [ChatSummary] {
        sortedByRecency(
            model.chatSummaries.filter { model.chatPrefs.archived.contains($0.conversationID) })
    }

    /// Message hits, newest first; tapping opens the conversation. (Jump-to-message inside the
    /// thread is an honest not-yet — the hit opens the thread, not the exact bubble.)
    private var searchResults: some View {
        List {
            if model.messageSearchHits.isEmpty {
                Text("No messages match.")
                    .foregroundStyle(palette.textSecondary)
            }
            ForEach(model.messageSearchHits) { hit in
                Button {
                    if let chat = model.chatSummaries.first(where: {
                        $0.conversationID == hit.conversationID
                    }) {
                        model.pendingScrollTarget[hit.conversationID] = hit.localID
                        searchQuery = ""
                        path.append(chat)
                    }
                } label: {
                    VStack(alignment: .leading, spacing: Nedwons.Spacing.xxs) {
                        HStack {
                            Text(titleFor(conversationID: hit.conversationID))
                                .font(Nedwons.TypeScale.caption)
                                .foregroundStyle(palette.accentPrimary)
                            Spacer()
                            if let when = hit.timestamp {
                                Text(when, style: .date)
                                    .font(Nedwons.TypeScale.caption)
                                    .foregroundStyle(palette.textSecondary)
                            }
                        }
                        Text((hit.mine ? "You: " : "") + hit.snippet)
                            .font(Nedwons.TypeScale.callout)
                            .foregroundStyle(palette.textPrimary)
                            .lineLimit(2)
                    }
                }
                .accessibilityIdentifier("search.hit.\(hit.id)")
            }
        }
        .listStyle(.plain)
    }

    private func titleFor(conversationID: String) -> String {
        chats.first(where: { $0.conversationID == conversationID })
            .map { model.conversationTitle(for: $0) } ?? "Conversation"
    }

    private var list: some View {
        List {
            ForEach(chats) { chat in
                chatRow(chat)
            }
            if !archivedChats.isEmpty {
                NavigationLink {
                    ArchivedChatsView(model: model)
                } label: {
                    Label("Archived (\(archivedChats.count))", systemImage: "archivebox")
                        .foregroundStyle(palette.textSecondary)
                }
                .accessibilityIdentifier("chats.archived")
            }
        }
        .listStyle(.plain)
    }

    @ViewBuilder
    private func chatRow(_ chat: ChatSummary) -> some View {
        NavigationLink(value: chat) {
            HStack(spacing: Nedwons.Spacing.xs) {
                ChatRow(model: model, chat: chat, palette: palette)
                if model.chatPrefs.pinned.contains(chat.conversationID) {
                    Image(systemName: "pin.fill")
                        .imageScale(.small)
                        .foregroundStyle(palette.textSecondary)
                        .accessibilityLabel("Pinned")
                }
                if model.chatPrefs.muted.contains(chat.conversationID) {
                    Image(systemName: "bell.slash.fill")
                        .imageScale(.small)
                        .foregroundStyle(palette.textSecondary)
                        .accessibilityLabel("Muted")
                }
            }
        }
        // Stable handle for the XCUITest suite (apps/ios/Nedwons/UITests).
        .accessibilityIdentifier("chats.row.\(chat.conversationID)")
        .contextMenu {
            Button("Delete conversation", systemImage: "trash", role: .destructive) {
                pendingDelete = chat
            }
        }
        .swipeActions(edge: .leading, allowsFullSwipe: true) {
            Button {
                model.togglePinned(chat.conversationID)
            } label: {
                Label(
                    model.chatPrefs.pinned.contains(chat.conversationID) ? "Unpin" : "Pin",
                    systemImage: "pin")
            }
            .tint(.orange)
        }
        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
            Button(role: .destructive) { pendingDelete = chat } label: {
                Label("Delete", systemImage: "trash")
            }
            Button {
                model.toggleArchived(chat.conversationID)
            } label: {
                Label("Archive", systemImage: "archivebox")
            }
            .tint(.indigo)
            Button {
                model.toggleMuted(chat.conversationID)
            } label: {
                Label(
                    model.chatPrefs.muted.contains(chat.conversationID) ? "Unmute" : "Mute",
                    systemImage: "bell.slash")
            }
            .tint(.gray)
        }
    }

    private var emptyState: some View {
        VStack(spacing: Nedwons.Spacing.lg) {
            Spacer()
            Image(systemName: "bubble.left.and.bubble.right")
                .font(.system(size: 44))
                .foregroundStyle(palette.accentPrimary)
            Text("No conversations yet")
                .font(Nedwons.TypeScale.headline)
                .foregroundStyle(palette.textPrimary)
            Text("Find someone by username to start a private conversation.")
                .font(Nedwons.TypeScale.callout)
                .foregroundStyle(palette.textSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, Nedwons.Spacing.xl)
            PrimaryButton("Find People", palette: palette) { showCompose = true }
                .frame(maxWidth: 240)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct ChatRow: View {
    @ObservedObject var model: AppModel
    let chat: ChatSummary
    let palette: Nedwons.Palette

    var body: some View {
        HStack(spacing: Nedwons.Spacing.md) {
            if chat.isGroup {
                GroupAvatarView(
                    model: model, conversationID: chat.conversationID, fallbackLabel: title,
                    palette: palette)
            } else {
                Avatar(label: title, palette: palette, isGroup: false)
            }
            VStack(alignment: .leading, spacing: Nedwons.Spacing.xxs) {
                Text(title)
                    .font(Nedwons.TypeScale.body)
                    .foregroundStyle(palette.textPrimary)
                    .lineLimit(1)
                Text(chat.lastMessagePreview ?? "No messages yet")
                    .font(Nedwons.TypeScale.caption)
                    .fontWeight(chat.unreadCount > 0 ? .semibold : .regular)
                    .foregroundStyle(chat.unreadCount > 0 ? palette.textPrimary : palette.textSecondary)
                    .lineLimit(1)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: Nedwons.Spacing.xxs) {
                if let when = chat.lastActivity {
                    Text(when, style: .time)
                        .font(Nedwons.TypeScale.caption)
                        .foregroundStyle(palette.textSecondary)
                }
                if chat.unreadCount > 0 {
                    Text("\(chat.unreadCount)")
                        .font(Nedwons.TypeScale.caption)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(palette.accentPrimary, in: Capsule())
                        .foregroundStyle(.white)
                        .accessibilityIdentifier("chats.unread.\(chat.conversationID)")
                        .accessibilityLabel("\(chat.unreadCount) unread")
                }
            }
        }
        .padding(.vertical, Nedwons.Spacing.xxs)
    }

    /// The group's E2EE name if it has one, else the alias/username for a 1:1 or the group's size.
    private var title: String { model.conversationTitle(for: chat) }
}

/// Initial-based placeholder; a real profile image replaces it once avatars ship.
struct Avatar: View {
    let label: String
    let palette: Nedwons.Palette
    var isGroup = false

    var body: some View {
        ZStack {
            Circle().fill(palette.incomingBubble)
            if isGroup {
                Image(systemName: "person.3.fill").foregroundStyle(palette.accentPrimary)
            } else {
                Text(initial)
                    .font(Nedwons.TypeScale.headline)
                    .foregroundStyle(palette.accentPrimary)
            }
        }
        .frame(width: 44, height: 44)
    }

    private var initial: String {
        String(label.trimmingCharacters(in: .whitespaces).prefix(1)).uppercased()
    }
}

/// Archived chats: hidden from the main list, one tap away, un-archive by swipe. Local
/// presentation state only — nothing about archiving reaches the relay.
struct ArchivedChatsView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    private var chats: [ChatSummary] {
        sortedByRecency(
            model.chatSummaries.filter { model.chatPrefs.archived.contains($0.conversationID) })
    }

    var body: some View {
        List {
            ForEach(chats) { chat in
                NavigationLink {
                    ConversationView(model: model, chat: chat)
                } label: {
                    ChatRow(model: model, chat: chat, palette: palette)
                }
                .swipeActions(edge: .trailing) {
                    Button {
                        model.toggleArchived(chat.conversationID)
                    } label: {
                        Label("Unarchive", systemImage: "tray.and.arrow.up")
                    }
                    .tint(.indigo)
                }
            }
        }
        .listStyle(.plain)
        .navigationTitle("Archived")
        .inlineNavigationTitle()
    }
}
