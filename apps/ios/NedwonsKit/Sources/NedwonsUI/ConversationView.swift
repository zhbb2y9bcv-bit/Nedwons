import NedwonsKit
import PhotosUI
import SwiftUI

/// One rendered line in a thread. Secrets carry no body here — they render as a sealed placeholder
/// driven by the core's state machine, and are only revealed by a deliberate tap.
public struct ThreadLine: Identifiable, Sendable, Equatable {
    public enum Kind: Sendable, Equatable {
        case text(String)
        case sealedSecret(Data)
        case consumedSecret
        /// A file. The bytes are not here: they are fetched from the relay and decrypted on
        /// demand, so a thread with fifty photos does not hold fifty photos in memory.
        case attachment(AttachmentLine)
    }
    public let id: UInt64
    public let kind: Kind
    public let mine: Bool
    /// When THIS device queued (mine) or decrypted (theirs) the message. `nil` for messages logged
    /// before timestamps existed — rendered without a time rather than with a guessed one.
    public let timestamp: Date?
    /// Mine, and the relay has not accepted it yet: shown as sending, never as delivered.
    public let isPending: Bool

    public init(
        id: UInt64, kind: Kind, mine: Bool, timestamp: Date? = nil, isPending: Bool = false
    ) {
        self.id = id
        self.kind = kind
        self.mine = mine
        self.timestamp = timestamp
        self.isPending = isPending
    }
}

/// What the UI needs to render a file, without its bytes.
public struct AttachmentLine: Sendable, Equatable {
    /// Relay blob id (hex) — the handle used to fetch it.
    public let blobID: String
    public let mime: String
    public let filename: String
    /// Plaintext size, for the "1.2 MB" label before anything is downloaded.
    public let size: UInt64
    /// A caption typed with the file, if any.
    public let caption: String

    public init(blobID: String, mime: String, filename: String, size: UInt64, caption: String) {
        self.blobID = blobID
        self.mime = mime
        self.filename = filename
        self.size = size
        self.caption = caption
    }

    public var isImage: Bool { mime.hasPrefix("image/") }

    /// What to call it when there is no filename — never a guess at the content.
    public var displayName: String {
        if !filename.isEmpty { return filename }
        if isImage { return "Photo" }
        if mime.hasPrefix("video/") { return "Video" }
        if mime.hasPrefix("audio/") { return "Voice message" }
        return "File"
    }

    public var formattedSize: String {
        ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
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
    @State private var showGroupInfo = false
    @State private var showPhotoPicker = false
    @State private var pickedItem: PhotosPickerItem?
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        VStack(spacing: 0) {
            messages
            if let lock = model.composerLock(for: chat.conversationID) {
                lockedComposer(lock)
            } else {
                composer
            }
        }
        .background(palette.background)
        .inlineNavigationTitle()
        .toolbar {
            ToolbarItem(placement: .principal) { header }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showGroupInfo = true
                } label: {
                    Image(systemName: chat.isGroup ? "person.3" : "info.circle")
                }
                .accessibilityLabel(chat.isGroup ? "Group info" : "Conversation details")
                .accessibilityIdentifier(GroupAdminA11y.conversationGroupInfo)
            }
        }
        .navigationDestination(isPresented: $showGroupInfo) {
            GroupAdminView(model: model, chat: chat)
        }
        // The picker returns the image's own bytes; they are encrypted before anything leaves the
        // device, so what the relay receives is never the photo.
        .photosPicker(isPresented: $showPhotoPicker, selection: $pickedItem, matching: .images)
        .onChange(of: pickedItem) { _, item in
            guard let item else { return }
            Task {
                defer { pickedItem = nil }
                guard let data = try? await item.loadTransferable(type: Data.self) else {
                    model.banner = "Couldn't read that photo."
                    return
                }
                await model.sendAttachment(
                    data, mime: "image/jpeg", filename: "photo.jpg", caption: "",
                    to: chat.conversationID)
            }
        }
        // One round trip on open: the composer locks (or not) from the same rows the relay's send
        // gate reads, so a muted member finds out here rather than from a refused send. Opening the
        // thread is also what marks it read — the user is looking at it.
        .task {
            await model.markConversationRead(chat.conversationID)
            await model.refreshGroupState(chat.conversationID)
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
        // The label must name the conversation: a button that only says "open profile" tells a
        // VoiceOver user which control this is but not which thread they are in.
        .accessibilityLabel("\(headerTitle), open details")
        .accessibilityIdentifier(GroupAdminA11y.conversationTitle)
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

    private var headerTitle: String { model.conversationTitle(for: chat) }

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
                            VStack(alignment: line.mine ? .trailing : .leading, spacing: 2) {
                                row(line)
                                metadata(line)
                            }
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

    /// Time, and — for your own messages — whether the relay has it yet. A pending message says so
    /// rather than looking identical to a delivered one; that difference is the whole point of
    /// showing it at all.
    @ViewBuilder
    private func metadata(_ line: ThreadLine) -> some View {
        if line.timestamp != nil || line.isPending {
            HStack(spacing: 4) {
                if line.isPending {
                    Image(systemName: "clock")
                        .font(.system(size: 9))
                    Text("Sending")
                } else if let when = line.timestamp {
                    Text(when, style: .time)
                }
            }
            .font(.system(size: 11))
            .foregroundStyle(palette.textSecondary)
            .padding(.horizontal, Nedwons.Spacing.xxs)
            .accessibilityLabel(accessibilityMetadata(line))
        }
    }

    private func accessibilityMetadata(_ line: ThreadLine) -> String {
        if line.isPending { return "Sending" }
        guard let when = line.timestamp else { return "" }
        return "Sent at \(when.formatted(date: .omitted, time: .shortened))"
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
        case .attachment(let attachment):
            AttachmentBubble(model: model, line: line, attachment: attachment, palette: palette)
        }
    }

    /// Shown instead of the composer when the relay would refuse this account's messages: an admin
    /// muted you, or the group is in announcement mode. Reading stays available — a mute is a
    /// send permission, never a removal.
    private func lockedComposer(_ lock: ComposerLock) -> some View {
        HStack(spacing: Nedwons.Spacing.sm) {
            Image(systemName: "speaker.slash.fill")
                .foregroundStyle(palette.textSecondary)
            Text(lock.text)
                .font(Nedwons.TypeScale.callout)
                .foregroundStyle(palette.textSecondary)
                .multilineTextAlignment(.leading)
            Spacer()
        }
        .padding(Nedwons.Spacing.md)
        .background(palette.surface)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier(GroupAdminA11y.composerLocked)
    }

    private var composer: some View {
        HStack(spacing: Nedwons.Spacing.sm) {
            Button {
                showPhotoPicker = true
            } label: {
                Image(systemName: "paperclip").imageScale(.large)
            }
            .accessibilityLabel("Attach a photo")
            .accessibilityIdentifier(GroupAdminA11y.composerAttach)
            .disabled(model.isBusy)
            TextField("Message", text: $draft, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .lineLimit(1...4)
                .accessibilityIdentifier(GroupAdminA11y.composerField)
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
