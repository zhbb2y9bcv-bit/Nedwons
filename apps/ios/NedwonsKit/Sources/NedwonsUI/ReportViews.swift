import NedwonsKit
import SwiftUI

/// Report one message to the review team (docs/MODERATION.md). The sheet is explicit about the
/// one privacy-relevant thing happening here: the selected content — and ONLY it — is decrypted
/// on this device and submitted as evidence, by the reporter's choice. Nothing else leaves the
/// conversation, because the server has nothing else to take.
struct ReportMessageSheet: View {
    @ObservedObject var model: AppModel
    let line: ThreadLine
    let chat: ChatSummary

    @Environment(\.colorScheme) private var scheme
    @Environment(\.dismiss) private var dismiss
    @State private var category = "illegal_content"
    @State private var note = ""
    @State private var includeText = true
    @State private var includeMedia = true
    @State private var alsoBlock = false
    @State private var submitting = false
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    private static let categories: [(String, String)] = [
        ("illegal_content", "Illegal content"),
        ("sexual_exploitation", "Sexual exploitation"),
        ("threats_violence", "Threats or violence"),
        ("spam_fraud", "Spam or fraud"),
        ("other", "Something else"),
    ]

    private var attachment: AttachmentLine? {
        if case .attachment(let a) = line.kind { return a }
        return nil
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("What is it?", selection: $category) {
                        ForEach(Self.categories, id: \.0) { value, label in
                            Text(label).tag(value)
                        }
                    }
                    .accessibilityIdentifier("report.category")
                } footer: {
                    Text("Reports are reviewed against what's ILLEGAL to send — not against opinions you disagree with.")
                }

                Section {
                    TextField("Anything the review team should know", text: $note, axis: .vertical)
                        .lineLimit(2...5)
                        .accessibilityIdentifier("report.note")
                }

                Section {
                    if line.quotableText != nil {
                        Toggle("Include the message text", isOn: $includeText)
                    }
                    if attachment != nil {
                        Toggle("Include the photo/file", isOn: $includeMedia)
                    }
                    Toggle("Also block this person", isOn: $alsoBlock)
                        .disabled(chat.peerAccountID == nil && line.senderDeviceID.isEmpty)
                } header: {
                    Text("What gets shared")
                } footer: {
                    Text(
                        "Only what you select here is decrypted on your device and sent to the "
                            + "review team, with your account attached as the reporter. The rest "
                            + "of the conversation stays end-to-end encrypted — the server cannot "
                            + "read it and your report does not change that.")
                }

                Section {
                    Button {
                        submit()
                    } label: {
                        if submitting {
                            ProgressView().frame(maxWidth: .infinity)
                        } else {
                            Text("Submit report").frame(maxWidth: .infinity)
                        }
                    }
                    .disabled(submitting)
                    .accessibilityIdentifier("report.submit")
                }
            }
            .navigationTitle("Report")
            .inlineNavigationTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private func submit() {
        submitting = true
        Task {
            var media: Data?
            var mime: String?
            if includeMedia, let attachment {
                media = await model.attachmentEvidence(attachment)
                mime = attachment.mime
                if media == nil {
                    model.banner = "Couldn't fetch the file to attach — the report was not sent. Try again."
                    submitting = false
                    return
                }
                if let bytes = media, bytes.count > 5 * 1024 * 1024 {
                    // The cap is the server's; refusing here beats a mystery 400.
                    media = nil
                    mime = nil
                }
            }
            let ok = await model.reportMessage(
                line, in: chat.conversationID,
                category: category, note: note, includeText: includeText,
                media: media, mediaMime: mime,
                fallbackAccountID: chat.peerAccountID)
            if ok, alsoBlock, let peer = chat.peerAccountID {
                await model.block(peer)
            }
            submitting = false
            if ok { dismiss() }
        }
    }
}
