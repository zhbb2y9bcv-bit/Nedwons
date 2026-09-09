import NedwonsKit
import SwiftUI

#if canImport(UIKit)
    import UIKit
#endif

/// Where one attachment's bytes are, for this session.
public enum AttachmentState: Sendable, Equatable {
    case notLoaded
    case loading
    case loaded(Data)
    /// User-facing reason; the row becomes a retry.
    case failed(String)
}

/// How a file appears in a thread. Nothing is downloaded until it is asked for: the relay holds
/// ciphertext, and fetching it costs bandwidth and battery, so an image shows its size and a tap
/// target first. Once decrypted, the bytes live in memory for the session and are never written to
/// disk in the clear — a photo you were shown is not a photo left in a cache directory.
struct AttachmentBubble: View {
    @ObservedObject var model: AppModel
    let line: ThreadLine
    let attachment: AttachmentLine
    let palette: Nedwons.Palette

    private var state: AttachmentState { model.attachmentState(attachment.blobID) }

    var body: some View {
        VStack(alignment: line.mine ? .trailing : .leading, spacing: Nedwons.Spacing.xxs) {
            content
            if !attachment.caption.isEmpty {
                Text(attachment.caption)
                    .font(Nedwons.TypeScale.body)
                    .foregroundStyle(line.mine ? .white : palette.textPrimary)
            }
        }
        .padding(.horizontal, Nedwons.Spacing.md)
        .padding(.vertical, Nedwons.Spacing.sm)
        .background(line.mine ? palette.accentPrimary : palette.incomingBubble)
        .clipShape(RoundedRectangle(cornerRadius: Nedwons.Radius.bubble))
        .accessibilityIdentifier("thread.attachment.\(attachment.blobID)")
    }

    @ViewBuilder
    private var content: some View {
        switch state {
        case .loaded(let data):
            if attachment.isImage, let image = platformImage(data) {
                image
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: 240, maxHeight: 320)
                    .clipShape(RoundedRectangle(cornerRadius: Nedwons.Radius.bubble))
                    .accessibilityLabel(attachment.displayName)
            } else {
                // Decrypted, but not something this build renders inline. Saying so plainly beats
                // showing a broken image: the file is intact, we just do not display this type yet.
                fileRow(subtitle: "Downloaded · \(attachment.formattedSize)")
            }
        case .loading:
            HStack(spacing: Nedwons.Spacing.sm) {
                ProgressView()
                Text("Downloading…").font(Nedwons.TypeScale.caption)
            }
            .foregroundStyle(line.mine ? .white : palette.textSecondary)
        case .failed(let reason):
            Button {
                Task { await model.loadAttachment(attachment) }
            } label: {
                fileRow(subtitle: reason, systemImage: "exclamationmark.arrow.circlepath")
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("thread.attachment.retry.\(attachment.blobID)")
        case .notLoaded:
            Button {
                Task { await model.loadAttachment(attachment) }
            } label: {
                fileRow(subtitle: attachment.formattedSize)
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("thread.attachment.open.\(attachment.blobID)")
        }
    }

    private func fileRow(subtitle: String, systemImage: String? = nil) -> some View {
        HStack(spacing: Nedwons.Spacing.sm) {
            Image(systemName: systemImage ?? icon)
                .imageScale(.large)
            VStack(alignment: .leading, spacing: 1) {
                Text(attachment.displayName)
                    .font(Nedwons.TypeScale.body)
                    .lineLimit(1)
                Text(subtitle)
                    .font(Nedwons.TypeScale.caption)
                    .opacity(0.8)
            }
        }
        .foregroundStyle(line.mine ? .white : palette.textPrimary)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(attachment.displayName), \(subtitle)")
    }

    private var icon: String {
        if attachment.isImage { return "photo" }
        if attachment.mime.hasPrefix("video/") { return "film" }
        if attachment.mime.hasPrefix("audio/") { return "waveform" }
        return "doc"
    }

    /// Decoding is attempted, never assumed: `mime` is a value the sender chose, so bytes that do
    /// not decode as an image fall back to the file row rather than rendering nothing.
    private func platformImage(_ data: Data) -> Image? {
        #if canImport(UIKit)
            guard let ui = UIImage(data: data) else { return nil }
            return Image(uiImage: ui)
        #else
            return nil
        #endif
    }
}
