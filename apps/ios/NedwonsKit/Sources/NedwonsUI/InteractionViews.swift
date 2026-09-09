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
