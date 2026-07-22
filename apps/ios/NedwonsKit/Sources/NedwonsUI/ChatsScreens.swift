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
    @State private var pendingDelete: ChatSummary?
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        NavigationStack(path: $path) {
            Group {
                if model.isBusy && model.conversations.isEmpty {
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
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button { showCompose = true } label: { Image(systemName: "square.and.pencil") }
                        .accessibilityLabel("New message")
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
        sortedByRecency(
            model.visibleConversations.map { conversation in
                let peer = conversation.memberAccountIDs.first { $0 != model.session?.accountID }
                return ChatSummary(
                    conversationID: conversation.conversationID,
                    peerAccountID: peer,
                    peerUsername: peer.flatMap { model.username(forAccountID: $0) },
                    memberCount: conversation.memberAccountIDs.count,
                    lastMessagePreview: model.localPreview(for: conversation.conversationID),
                    lastActivity: model.localLastActivity(for: conversation.conversationID)
                )
            })
    }

    private var list: some View {
        List {
            ForEach(chats) { chat in
                NavigationLink(value: chat) {
                    ChatRow(model: model, chat: chat, palette: palette)
                }
                .contextMenu {
                    Button("Delete conversation", systemImage: "trash", role: .destructive) {
                        pendingDelete = chat
                    }
                }
                .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                    Button(role: .destructive) { pendingDelete = chat } label: {
                        Label("Delete", systemImage: "trash")
                    }
                }
            }
        }
        .listStyle(.plain)
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
            Avatar(label: title, palette: palette, isGroup: chat.isGroup)
            VStack(alignment: .leading, spacing: Nedwons.Spacing.xxs) {
                Text(title)
                    .font(Nedwons.TypeScale.body)
                    .foregroundStyle(palette.textPrimary)
                    .lineLimit(1)
                Text(chat.lastMessagePreview ?? "No messages yet")
                    .font(Nedwons.TypeScale.caption)
                    .foregroundStyle(palette.textSecondary)
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
                }
            }
        }
        .padding(.vertical, Nedwons.Spacing.xxs)
    }

    /// Alias when the viewer set one, otherwise the real username. Groups show their size.
    private var title: String {
        if chat.isGroup { return "Group · \(chat.memberCount) people" }
        guard let accountID = chat.peerAccountID else { return "Conversation" }
        return model.displayName(for: accountID, username: chat.peerUsername ?? "Unknown")
    }
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
