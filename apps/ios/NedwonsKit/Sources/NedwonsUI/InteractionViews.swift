import NedwonsKit
import SwiftUI

/// The quoted message shown above a reply — in the thread, and in the composer while writing one.
///
/// It renders the quoted line from THIS device's copy of the message, found by id. The reply itself
/// carries only that id: if it carried the text, a modified client could put words in someone's
/// mouth by "quoting" something they never wrote.
struct QuotedPreview: View {
    let line: ThreadLine
    let palette: Nedwons.Palette
    /// Compact is the in-thread version above a bubble; the composer version is roomier.
    let compact: Bool

    var body: some View {
        HStack(spacing: Nedwons.Spacing.xs) {
            Rectangle()
                .fill(palette.accentPrimary)
                .frame(width: 2)
            VStack(alignment: .leading, spacing: 0) {
                Text(line.mine ? "You" : "Reply")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(palette.accentPrimary)
                Text(line.quotableText ?? "Message")
                    .font(Nedwons.TypeScale.caption)
                    .foregroundStyle(palette.textSecondary)
                    .lineLimit(compact ? 1 : 2)
            }
        }
        .padding(.vertical, 2)
        .frame(maxWidth: compact ? 240 : nil, alignment: .leading)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Replying to: \(line.quotableText ?? "a message")")
    }
}

/// Reactions under a message. Each is a toggle: tapping one you already sent takes it back, which
/// is why the viewer's own reactions are drawn differently rather than merely counted.
struct ReactionRow: View {
    let line: ThreadLine
    let palette: Nedwons.Palette
    let onTap: (String) -> Void

    var body: some View {
        HStack(spacing: Nedwons.Spacing.xxs) {
            ForEach(line.reactions) { reaction in
                Button {
                    onTap(reaction.emoji)
                } label: {
                    HStack(spacing: 2) {
                        Text(reaction.emoji).font(.system(size: 12))
                        if reaction.count > 1 {
                            Text("\(reaction.count)")
                                .font(.system(size: 11))
                                .foregroundStyle(palette.textSecondary)
                        }
                    }
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(
                        reaction.includesMe
                            ? palette.accentPrimary.opacity(0.18) : palette.incomingBubble,
                        in: Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("thread.reaction.\(line.messageID).\(reaction.emoji)")
                .accessibilityLabel(
                    "\(reaction.emoji), \(reaction.count)"
                        + (reaction.includesMe ? ", including you. Tap to remove." : ". Tap to add."))
            }
        }
    }
}

/// Pick where a forwarded message goes. Groups the user can't send into are shown but disabled
/// (the relay would refuse anyway — showing why beats a mystery failure).
struct ForwardPickerView: View {
    @ObservedObject var model: AppModel
    let line: ThreadLine
    let sourceConversationID: String

    @Environment(\.colorScheme) private var scheme
    @Environment(\.dismiss) private var dismiss
    @State private var sending = false
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    private var destinations: [ChatSummary] {
        sortedByRecency(model.chatSummaries.filter { $0.conversationID != sourceConversationID })
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if destinations.isEmpty {
                        Text("No other conversations to forward into.")
                            .foregroundStyle(palette.textSecondary)
                    }
                    ForEach(destinations) { chat in
                        Button {
                            guard !sending else { return }
                            sending = true
                            Task {
                                await model.forward(
                                    line, from: sourceConversationID, to: chat.conversationID)
                                sending = false
                                dismiss()
                            }
                        } label: {
                            HStack {
                                Text(model.conversationTitle(for: chat))
                                    .foregroundStyle(palette.textPrimary)
                                Spacer()
                                if sending { ProgressView() }
                            }
                        }
                        .disabled(model.composerLock(for: chat.conversationID) != nil)
                        .accessibilityIdentifier("forward.to.\(chat.conversationID)")
                    }
                } footer: {
                    Text("A forwarded file is re-encrypted with a fresh key for the destination — the two conversations never share key material.")
                }
            }
            .navigationTitle("Forward to…")
            .inlineNavigationTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }
}

/// A curated reaction grid beyond the six quick ones — enough coverage without a full system
/// emoji keyboard (which is a text-input feature, not a picker component Apple exposes).
struct ReactionPickerSheet: View {
    @ObservedObject var model: AppModel
    let line: ThreadLine
    let conversationID: String
    @Environment(\.dismiss) private var dismiss

    static let emoji: [String] = [
        "👍", "👎", "❤️", "🔥", "🎉", "😂", "🤣", "😮", "😢", "😡",
        "🙏", "👏", "💯", "✅", "❌", "❓", "‼️", "🤝", "🫡", "🤔",
        "😍", "🥳", "😴", "🤯", "🙄", "😅", "🤷", "🫶", "💀", "🌟",
        "🍀", "☕️", "🍕", "⚽️", "🎵", "📸", "✈️", "🏠", "⏰", "💡",
    ]

    var body: some View {
        ScrollView {
            LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 8),
                      spacing: Nedwons.Spacing.md) {
                ForEach(Self.emoji, id: \.self) { emoji in
                    Button(emoji) {
                        dismiss()
                        Task { await model.toggleReaction(emoji, on: line, in: conversationID) }
                    }
                    .font(.system(size: 28))
                    .accessibilityLabel("React with \(emoji)")
                }
            }
            .padding(Nedwons.Spacing.lg)
        }
    }
}
