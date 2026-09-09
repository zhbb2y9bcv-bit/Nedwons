import NedwonsKit
import PhotosUI
import SwiftUI
import UniformTypeIdentifiers

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
    /// The id other devices know this message by — what a reply or reaction names. Empty for
    /// messages logged before ids existed, which therefore cannot be replied or reacted to.
    public let messageID: String
    /// What this message answers, resolved for display by looking it up in the same thread.
    public let replyTo: String?
    /// Reactions, grouped for display: emoji → how many people, and whether one of them is you.
    public let reactions: [ReactionSummary]
    /// Mine only: how many other members have received / read it.
    public let deliveredCount: Int
    public let readCount: Int
    /// Retracted by its author (delete-for-everyone): rendered as "Message deleted", offers no
    /// reply/react/forward, and quotes as nothing.
    public let deleted: Bool
    /// The sender's MLS device identity (hex), for REPORTING a group message's author — the
    /// server resolves the device to its account. Empty for pre-field history.
    public let senderDeviceID: String
    /// The author replaced the text after sending; shown as an "edited" tag, always.
    public let edited: Bool

    public init(
        id: UInt64, kind: Kind, mine: Bool, timestamp: Date? = nil, isPending: Bool = false,
        messageID: String = "", replyTo: String? = nil, reactions: [ReactionSummary] = [],
        deliveredCount: Int = 0, readCount: Int = 0, deleted: Bool = false,
        senderDeviceID: String = "", edited: Bool = false
    ) {
        self.id = id
        self.kind = kind
        self.mine = mine
        self.timestamp = timestamp
        self.isPending = isPending
        self.messageID = messageID
        self.replyTo = replyTo
        self.reactions = reactions
        self.deliveredCount = deliveredCount
        self.readCount = readCount
        self.deleted = deleted
        self.senderDeviceID = senderDeviceID
        self.edited = edited
    }

    /// The plain text of this line, for quoting it in a reply preview. A secret never yields one —
    /// its body is the thing that must not be shown twice — and neither does a deleted message.
    public var quotableText: String? {
        if deleted { return nil }
        switch kind {
        case .text(let t): return t.isEmpty ? nil : t
        case .attachment(let a): return a.caption.isEmpty ? a.displayName : a.caption
        case .sealedSecret, .consumedSecret: return nil
        }
    }
}

/// One emoji on one message, with how many people used it.
public struct ReactionSummary: Sendable, Equatable, Identifiable {
    public let emoji: String
    public let count: Int
    /// Whether the viewer is one of them — so tapping toggles rather than piling on.
    public let includesMe: Bool

    public var id: String { emoji }

    public init(emoji: String, count: Int, includesMe: Bool) {
        self.emoji = emoji
        self.count = count
        self.includesMe = includesMe
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
    public var isAudio: Bool { mime.hasPrefix("audio/") }
    public var isVideo: Bool { mime.hasPrefix("video/") }

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
    @State private var pickerFilter: PHPickerFilter = .images
    @State private var showFileImporter = false
    @State private var pickedItem: PhotosPickerItem?
    @StateObject private var recorder = VoiceNoteRecorder()
    @State private var deleteCandidate: ThreadLine?
    @State private var forwardCandidate: ThreadLine?
    @State private var reportCandidate: ThreadLine?
    @State private var flashedLineID: UInt64?
    @State private var reactionSheetLine: ThreadLine?
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
        .confirmationDialog(
            "Delete for everyone?",
            isPresented: Binding(
                get: { deleteCandidate != nil }, set: { if !$0 { deleteCandidate = nil } }),
            titleVisibility: .visible
        ) {
            Button("Delete for everyone", role: .destructive) {
                if let line = deleteCandidate {
                    Task { await model.deleteForEveryone(line, in: chat.conversationID) }
                }
                deleteCandidate = nil
            }
            Button("Cancel", role: .cancel) { deleteCandidate = nil }
        } message: {
            Text(
                "Everyone's app is asked to remove it. That is best-effort: someone may have "
                    + "already seen it, and a device that never comes online keeps its copy.")
        }
        .sheet(item: $forwardCandidate) { line in
            ForwardPickerView(model: model, line: line, sourceConversationID: chat.conversationID)
        }
        .sheet(item: $reportCandidate) { line in
            ReportMessageSheet(model: model, line: line, chat: chat)
        }
        .sheet(item: $reactionSheetLine) { line in
            ReactionPickerSheet(model: model, line: line, conversationID: chat.conversationID)
                .presentationDetents([.height(320)])
        }
        // The picker returns the media's own bytes; they are encrypted before anything leaves the
        // device, so what the relay receives is never the photo or video.
        .photosPicker(isPresented: $showPhotoPicker, selection: $pickedItem, matching: pickerFilter)
        .onChange(of: pickedItem) { _, item in
            guard let item else { return }
            let isVideo = pickerFilter == .videos
            Task {
                defer { pickedItem = nil }
                guard let data = try? await item.loadTransferable(type: Data.self) else {
                    model.banner = isVideo ? "Couldn't read that video." : "Couldn't read that photo."
                    return
                }
                await model.sendAttachment(
                    data,
                    mime: isVideo ? "video/mp4" : "image/jpeg",
                    filename: isVideo ? "video.mp4" : "photo.jpg",
                    caption: "",
                    to: chat.conversationID)
            }
        }
        .fileImporter(isPresented: $showFileImporter, allowedContentTypes: [.data]) { result in
            guard case .success(let url) = result else { return }
            Task {
                let secured = url.startAccessingSecurityScopedResource()
                defer { if secured { url.stopAccessingSecurityScopedResource() } }
                guard let data = try? Data(contentsOf: url) else {
                    model.banner = "Couldn't read that file."
                    return
                }
                let mime = ConversationView.mimeType(for: url)
                await model.sendAttachment(
                    data, mime: mime, filename: url.lastPathComponent, caption: "",
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
                HStack(spacing: Nedwons.Spacing.xs) {
                    Text(headerTitle)
                        .font(Nedwons.TypeScale.headline)
                        .foregroundStyle(palette.textPrimary)
                        .lineLimit(1)
                    if model.disappearTimer(for: chat.conversationID) > 0 {
                        Image(systemName: "timer")
                            .font(.caption2)
                            .foregroundStyle(palette.textSecondary)
                            .accessibilityLabel(
                                "Disappearing messages: \(AppModel.timerLabel(model.disappearTimer(for: chat.conversationID)))")
                    }
                }
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
                                if let quoted = quotedLine(for: line) {
                                    QuotedPreview(line: quoted, palette: palette, compact: true)
                                        .onTapGesture {
                                            model.pendingScrollTarget[chat.conversationID] =
                                                quoted.id
                                        }
                                        .accessibilityAddTraits(.isButton)
                                        .accessibilityHint("Jump to the original message")
                                }
                                row(line)
                                if !line.reactions.isEmpty {
                                    ReactionRow(
                                        line: line, palette: palette,
                                        onTap: { emoji in
                                            Task {
                                                await model.toggleReaction(
                                                    emoji, on: line, in: chat.conversationID)
                                            }
                                        })
                                }
                                metadata(line)
                            }
                            .frame(
                                maxWidth: .infinity,
                                alignment: line.mine ? .trailing : .leading)
                            .id(line.id)
                            .background(
                                RoundedRectangle(cornerRadius: Nedwons.Radius.bubble)
                                    .fill(
                                        flashedLineID == line.id
                                            ? palette.accentPrimary.opacity(0.18) : .clear)
                                    .animation(.easeOut(duration: 0.6), value: flashedLineID)
                            )
                            .contextMenu { messageActions(line) }
                        }
                    }
                    .padding(Nedwons.Spacing.md)
                }
                .onChange(of: lines.count) {
                    // A pending jump (search hit, reply-quote tap) wins over follow-the-bottom.
                    if model.pendingScrollTarget[chat.conversationID] == nil,
                        let last = lines.last
                    {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
                .onChange(of: model.pendingScrollTarget[chat.conversationID]) { _, target in
                    jump(to: target, proxy: proxy)
                }
                .onAppear {
                    jump(to: model.pendingScrollTarget[chat.conversationID], proxy: proxy)
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
                    if line.edited { Text("edited ·") }
                    Text(when, style: .time)
                    if line.mine, let ticks = receiptTicks(line) {
                        Image(systemName: ticks.symbol)
                            .font(.system(size: 9))
                            .foregroundStyle(ticks.read ? palette.accentPrimary : palette.textSecondary)
                    }
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
        var text = "Sent at \(when.formatted(date: .omitted, time: .shortened))"
        if line.mine, let ticks = receiptTicks(line) {
            text += ticks.read ? ", read" : ", delivered"
        }
        return text
    }

    /// One tick for delivered, two for read — and nothing at all until someone confirms, rather
    /// than a tick that merely means "we tried".
    private func receiptTicks(_ line: ThreadLine) -> (symbol: String, read: Bool)? {
        if line.readCount > 0 { return ("checkmark.circle.fill", true) }
        if line.deliveredCount > 0 { return ("checkmark.circle", false) }
        return nil
    }

    /// The message a line answers, if it is still in this thread. A reply to something no longer
    /// held renders as an ordinary message rather than an empty quote.
    private func quotedLine(for line: ThreadLine) -> ThreadLine? {
        guard let target = line.replyTo else { return nil }
        return lines.first { $0.messageID == target }
    }

    /// Scroll to a specific line (search hit / reply-quote tap), flash it, consume the request.
    private func jump(to target: UInt64?, proxy: ScrollViewProxy) {
        guard let target, lines.contains(where: { $0.id == target }) else { return }
        withAnimation { proxy.scrollTo(target, anchor: .center) }
        flashedLineID = target
        model.pendingScrollTarget.removeValue(forKey: chat.conversationID)
        Task {
            try? await Task.sleep(nanoseconds: 900_000_000)
            if flashedLineID == target { flashedLineID = nil }
        }
    }

    /// Long-press actions. Reply and react need the message to HAVE an id — older messages predate
    /// ids and honestly cannot be referred to, so the actions are not offered for them.
    @ViewBuilder
    private func messageActions(_ line: ThreadLine) -> some View {
        if !line.messageID.isEmpty, !line.deleted {
            Button {
                model.startReply(to: line, in: chat.conversationID)
            } label: {
                Label("Reply", systemImage: "arrowshape.turn.up.left")
            }
            ForEach(Self.quickReactions, id: \.self) { emoji in
                Button(emoji) {
                    Task { await model.toggleReaction(emoji, on: line, in: chat.conversationID) }
                }
            }
            Button {
                reactionSheetLine = line
            } label: {
                Label("More reactions…", systemImage: "face.smiling")
            }
        }
        if !line.deleted, line.quotableText != nil || lineIsForwardableAttachment(line) {
            Button {
                forwardCandidate = line
            } label: {
                Label("Forward", systemImage: "arrowshape.turn.up.right")
            }
        }
        if line.mine, !line.messageID.isEmpty, !line.deleted {
            if case .text = line.kind {
                Button {
                    model.startEdit(of: line, in: chat.conversationID)
                    draft = line.quotableText ?? ""
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
            }
            Button(role: .destructive) {
                deleteCandidate = line
            } label: {
                Label("Delete for everyone", systemImage: "trash")
            }
        }
        if !line.mine, !line.deleted {
            Button(role: .destructive) {
                reportCandidate = line
            } label: {
                Label("Report", systemImage: "flag")
            }
        }
    }

    private func lineIsForwardableAttachment(_ line: ThreadLine) -> Bool {
        if case .attachment = line.kind { return true }
        return false
    }

    /// A small, fixed set: a picker with every emoji is a different feature, and these cover the
    /// overwhelming majority of real use.
    static let quickReactions = ["👍", "❤️", "😂", "😮", "😢", "🎉"]

    @ViewBuilder
    private func row(_ line: ThreadLine) -> some View {
        if line.deleted {
            // An honest tombstone: the retraction is visible, the words are gone.
            Text(line.mine ? "You deleted this message" : "Message deleted")
                .font(Nedwons.TypeScale.callout.italic())
                .foregroundStyle(palette.textSecondary)
                .padding(.horizontal, Nedwons.Spacing.md)
                .padding(.vertical, Nedwons.Spacing.sm)
                .background(palette.surface)
                .clipShape(RoundedRectangle(cornerRadius: Nedwons.Radius.bubble))
                .accessibilityIdentifier("message.deleted.\(line.id)")
        } else {
            undeletedRow(line)
        }
    }

    @ViewBuilder
    private func undeletedRow(_ line: ThreadLine) -> some View {
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
        VStack(spacing: 0) {
            if model.editDrafts[chat.conversationID] != nil {
                HStack(spacing: Nedwons.Spacing.sm) {
                    Label("Editing message", systemImage: "pencil")
                        .font(Nedwons.TypeScale.caption)
                        .foregroundStyle(palette.accentPrimary)
                        .accessibilityIdentifier("composer.editing")
                    Spacer()
                    Button {
                        model.cancelEdit(in: chat.conversationID)
                        draft = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                    }
                    .accessibilityLabel("Cancel edit")
                }
                .padding(.horizontal, Nedwons.Spacing.md)
                .padding(.top, Nedwons.Spacing.xs)
            }
            if let draft = model.replyDrafts[chat.conversationID] {
                HStack(spacing: Nedwons.Spacing.sm) {
                    // The identifier sits on the preview, not the row: an identifier on the
                    // container makes SwiftUI merge it into ONE element, which hides the cancel
                    // button from assistive technology (and from the UI test that caught it).
                    QuotedPreview(line: draft, palette: palette, compact: false)
                        .accessibilityIdentifier(GroupAdminA11y.replyBar)
                    Spacer()
                    Button {
                        model.cancelReply(in: chat.conversationID)
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                    }
                    .accessibilityLabel("Cancel reply")
                    .accessibilityIdentifier(GroupAdminA11y.replyCancel)
                }
                .padding(.horizontal, Nedwons.Spacing.md)
                .padding(.top, Nedwons.Spacing.xs)
            }
            if let typing = typingText {
                HStack {
                    Text(typing)
                        .font(Nedwons.TypeScale.caption)
                        .foregroundStyle(palette.textSecondary)
                    Spacer()
                }
                .padding(.horizontal, Nedwons.Spacing.md)
                .accessibilityIdentifier(GroupAdminA11y.typingIndicator)
            }
            composerRow
        }
        .background(palette.surface)
    }

    private var typingText: String? {
        let names = model.typingNames(in: chat.conversationID)
        switch names.count {
        case 0: return nil
        case 1: return "\(names[0]) is typing…"
        default: return "\(names.count) people are typing…"
        }
    }

    @ViewBuilder
    private var composerRow: some View {
        if recorder.isRecording {
            recordingRow
        } else {
            standardComposerRow
        }
    }

    /// Replaces the composer while a voice note records: elapsed time, cancel, send.
    private var recordingRow: some View {
        HStack(spacing: Nedwons.Spacing.md) {
            Image(systemName: "waveform")
                .foregroundStyle(palette.destructive)
                .symbolEffect(.variableColor.iterative, isActive: true)
            Text(VoiceNoteBubbleView.clock(recorder.elapsed))
                .font(Nedwons.TypeScale.body)
                .monospacedDigit()
                .foregroundStyle(palette.textPrimary)
            Spacer()
            Button("Cancel", role: .cancel) { recorder.cancel() }
            Button {
                let data = recorder.finish()
                Task {
                    if let data {
                        await model.sendAttachment(
                            data, mime: "audio/mp4", filename: "Voice message.m4a", caption: "",
                            to: chat.conversationID)
                    }
                }
            } label: {
                Image(systemName: "arrow.up.circle.fill").imageScale(.large)
            }
            .accessibilityLabel("Send voice message")
        }
        .padding(Nedwons.Spacing.md)
        .accessibilityIdentifier("composer.recording")
    }

    private var standardComposerRow: some View {
        HStack(spacing: Nedwons.Spacing.sm) {
            Menu {
                Button {
                    pickerFilter = .images
                    showPhotoPicker = true
                } label: {
                    Label("Photo", systemImage: "photo")
                }
                Button {
                    pickerFilter = .videos
                    showPhotoPicker = true
                } label: {
                    Label("Video", systemImage: "film")
                }
                Button {
                    showFileImporter = true
                } label: {
                    Label("File", systemImage: "doc")
                }
            } label: {
                Image(systemName: "paperclip").imageScale(.large)
            }
            .accessibilityLabel("Attach a photo, video, or file")
            .accessibilityIdentifier(GroupAdminA11y.composerAttach)
            .disabled(model.isBusy)
            Button {
                Task {
                    if await recorder.start() == false {
                        model.banner = "Nedwons needs microphone access to record — enable it in iOS Settings."
                    }
                }
            } label: {
                Image(systemName: "mic").imageScale(.large)
            }
            .accessibilityLabel("Record a voice message")
            .accessibilityIdentifier("composer.mic")
            .disabled(model.isBusy)
            TextField("Message", text: $draft, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .lineLimit(1...4)
                .accessibilityIdentifier(GroupAdminA11y.composerField)
            .onChange(of: draft) { _, text in
                // Intent, not keystrokes: the composition layer throttles, and stops when the
                // field empties so a cleared draft does not leave someone "typing".
                Task { await model.setTyping(!text.isEmpty, in: chat.conversationID) }
            }
            Button {
                let body = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                draft = ""
                Task {
                    await model.setTyping(false, in: chat.conversationID)
                    await model.sendMessageOrReply(body, to: chat.conversationID)
                }
            } label: {
                Image(systemName: "arrow.up.circle.fill").imageScale(.large)
            }
            .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(Nedwons.Spacing.md)
    }
}

extension ConversationView {
    /// Best-effort media type from the picked file's extension — advisory only, exactly like
    /// every sender-chosen mime in the protocol (recipients validate the bytes they decode).
    static func mimeType(for url: URL) -> String {
        if let type = UTType(filenameExtension: url.pathExtension),
            let mime = type.preferredMIMEType
        {
            return mime
        }
        return "application/octet-stream"
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
