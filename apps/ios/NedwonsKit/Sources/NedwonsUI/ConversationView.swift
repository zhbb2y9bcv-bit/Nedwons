import NedwonsKit
import SwiftUI

/// One rendered line in a thread. Secrets carry no body here — they render as a sealed placeholder
/// driven by the core's state machine, and are only revealed by a deliberate tap.
public struct ThreadLine: Identifiable, Sendable, Equatable {
    public enum Kind: Sendable, Equatable {
        case text(String)
        case sealedSecret(Data)
        case consumedSecret
    }
    public let id: UInt64
    public let kind: Kind
    public let mine: Bool

    public init(id: UInt64, kind: Kind, mine: Bool) {
        self.id = id
        self.kind = kind
        self.mine = mine
    }
}

/// A single conversation. The header centers the other person's identity and is the entry point to
/// their profile and to the private-rename menu; back always returns to the Chats list.
struct ConversationView: View {
    @ObservedObject var model: AppModel
    let chat: ChatSummary

    @Environment(\.colorScheme) private var scheme
    @State private var draft = ""
    @State private var showProfile = false
    @State private var showRenameSheet = false
    @State private var renameText = ""
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        VStack(spacing: 0) {
            messages
            composer
        }
        .background(palette.background)
        .inlineNavigationTitle()
        .toolbar {
            ToolbarItem(placement: .principal) { header }
        }
        .sheet(isPresented: $showProfile) {
            if let accountID = chat.peerAccountID {
                PersonProfileView(
                    model: model, accountID: accountID,
                    username: chat.peerUsername ?? "Unknown")
            }
        }
        .confirmationDialog("Name", isPresented: $showRenameSheet, titleVisibility: .hidden) {
            renameActions
        }
        .sheet(isPresented: $showRenameEditor) { renameEditor }
    }

    @State private var showRenameEditor = false

    /// Centered identity. When a private alias exists it becomes the main name, with the real
    /// `@username` beneath — the account's true identity is never fully hidden.
    private var header: some View {
        Button {
            showProfile = true
        } label: {
            VStack(spacing: 0) {
                Text(headerTitle)
                    .font(Nedwons.TypeScale.headline)
                    .foregroundStyle(palette.textPrimary)
                    .lineLimit(1)
                if hasAlias, let username = chat.peerUsername {
                    Text("@\(username)")
                        .font(.caption2)
                        .foregroundStyle(palette.textSecondary)
                        .lineLimit(1)
                }
            }
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Open profile")
        .onLongPressGesture {
            guard chat.peerAccountID != nil else { return }
            renameText = model.alias(for: chat.peerAccountID ?? "") ?? ""
            showRenameSheet = true
        }
    }

    private var hasAlias: Bool {
        guard let id = chat.peerAccountID else { return false }
        return model.alias(for: id) != nil
    }

    private var headerTitle: String {
        if chat.isGroup { return "Group · \(chat.memberCount) people" }
        guard let id = chat.peerAccountID else { return "Conversation" }
        return model.displayName(for: id, username: chat.peerUsername ?? "Unknown")
    }

    @ViewBuilder
    private var renameActions: some View {
        Button(hasAlias ? "Edit Alias" : "Rename for Me") { showRenameEditor = true }
        if hasAlias {
            Button("Remove Alias", role: .destructive) {
                if let id = chat.peerAccountID { model.removeAlias(for: id) }
            }
        }
        Button("Cancel", role: .cancel) {}
    }

    private var renameEditor: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name", text: $renameText)
                } footer: {
                    Text("""
                        Only you see this name. It is stored encrypted on your device, is never \
                        sent to them, and does not change their username for anyone else.
                        """)
                }
            }
            .navigationTitle("Rename for me")
            .inlineNavigationTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { showRenameEditor = false }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        if let id = chat.peerAccountID,
                            case .valid = model.setAlias(renameText, for: id)
                        {
                            showRenameEditor = false
                        }
                    }
                }
            }
        }
    }

    private var lines: [ThreadLine] { model.threadLines[chat.conversationID] ?? [] }

    @ViewBuilder
    private var messages: some View {
        if lines.isEmpty {
            VStack(spacing: Nedwons.Spacing.md) {
                Spacer()
                Image(systemName: "lock.fill")
                    .font(.system(size: 32))
                    .foregroundStyle(palette.accentPrimary)
                Text("Messages here are end-to-end encrypted.")
                    .font(Nedwons.TypeScale.callout)
                    .foregroundStyle(palette.textSecondary)
                    .multilineTextAlignment(.center)
                Spacer()
            }
            .frame(maxWidth: .infinity)
        } else {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: Nedwons.Spacing.sm) {
                        ForEach(lines) { line in
                            row(line)
                                .frame(
                                    maxWidth: .infinity,
                                    alignment: line.mine ? .trailing : .leading)
                                .id(line.id)
                        }
                    }
                    .padding(Nedwons.Spacing.md)
                }
                .onChange(of: lines.count) {
                    if let last = lines.last { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
        }
    }

    @ViewBuilder
    private func row(_ line: ThreadLine) -> some View {
        switch line.kind {
        case .text(let text):
            Text(text)
                .font(Nedwons.TypeScale.body)
                .foregroundStyle(line.mine ? .white : palette.textPrimary)
                .padding(.horizontal, Nedwons.Spacing.md)
                .padding(.vertical, Nedwons.Spacing.sm)
                .background(line.mine ? palette.accentPrimary : palette.incomingBubble)
                .clipShape(RoundedRectangle(cornerRadius: Nedwons.Radius.bubble))
        case .sealedSecret(let secretID):
            SecretSealedPlaceholderView { model.revealSecret?(secretID) }
                .foregroundStyle(palette.accentSecondary)
        case .consumedSecret:
            SecretTombstoneView(text: model.secretTombstoneText)
        }
    }

    private var composer: some View {
        HStack(spacing: Nedwons.Spacing.sm) {
            TextField("Message", text: $draft, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .lineLimit(1...4)
            Button {
                let body = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                draft = ""
                Task { await model.sendMessage(body, to: chat.conversationID) }
            } label: {
                Image(systemName: "arrow.up.circle.fill").imageScale(.large)
            }
            .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(Nedwons.Spacing.md)
        .background(palette.surface)
    }
}

/// A person's real, permanent identity plus the viewer's private alias. The registered username is
/// always shown here, so an alias can never disguise which account this is.
struct PersonProfileView: View {
    @ObservedObject var model: AppModel
    let accountID: String
    let username: String

    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var scheme
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(spacing: Nedwons.Spacing.sm) {
                        Avatar(label: username, palette: palette)
                            .scaleEffect(1.6)
                            .frame(height: 80)
                        Text("@\(username)")
                            .font(Nedwons.TypeScale.headline)
                            .foregroundStyle(palette.textPrimary)
                        Text("Permanent username")
                            .font(Nedwons.TypeScale.caption)
                            .foregroundStyle(palette.textSecondary)
                    }
                    .frame(maxWidth: .infinity)
                }
                if let alias = model.alias(for: accountID) {
                    Section("Your private name for them") {
                        Text(alias)
                        Text("Only you see this. They are never told.")
                            .font(Nedwons.TypeScale.caption)
                            .foregroundStyle(palette.textSecondary)
                        Button("Remove alias", role: .destructive) {
                            model.removeAlias(for: accountID)
                        }
                    }
                }
                Section {
                    Button("Block", role: .destructive) {
                        Task { await model.block(accountID) }
                    }
                    Button("Report") {
                        Task { await model.report(accountID, reason: "reported from profile") }
                    }
                }
            }
            .navigationTitle("Profile")
            .inlineNavigationTitle()
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
    }
}
