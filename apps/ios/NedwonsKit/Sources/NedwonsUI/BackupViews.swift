import NedwonsKit
import SwiftUI
import UniformTypeIdentifiers

/// Encrypted chat backup (docs/BACKUPS.md): create a passphrase-sealed file of the message
/// stores, and restore one. The copy carries the two facts the user must not learn the hard way:
/// the passphrase is unrecoverable by anyone (including Nedwons), and v1 restores protect this
/// device's data — not yet a new-phone transfer.
struct ChatBackupView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    @State private var passphrase = ""
    @State private var confirm = ""
    @State private var working = false
    @State private var backupFile: URL?
    @State private var showImporter = false
    @State private var restorePassphrase = ""
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    private var passphraseOK: Bool {
        passphrase.count >= 8 && passphrase == confirm
    }

    var body: some View {
        List {
            Section {
                SecureField("Backup passphrase (min. 8 characters)", text: $passphrase)
                    .accessibilityIdentifier("backup.passphrase")
                SecureField("Repeat passphrase", text: $confirm)
                Button {
                    working = true
                    Task {
                        backupFile = await model.createBackup(passphrase: passphrase)
                        working = false
                    }
                } label: {
                    if working {
                        ProgressView()
                    } else {
                        Label("Create encrypted backup", systemImage: "lock.doc")
                    }
                }
                .disabled(!passphraseOK || working)
                .accessibilityIdentifier("backup.create")
                if let backupFile {
                    ShareLink(item: backupFile) {
                        Label("Save the backup file…", systemImage: "square.and.arrow.up")
                    }
                }
            } header: {
                Text("Create a backup")
            } footer: {
                Text(
                    "The file contains your message history, sealed with this passphrase. "
                        + "Nobody — including Nedwons — can open or recover it without the "
                        + "passphrase, so store both somewhere safe.")
            }

            Section {
                SecureField("Passphrase of the backup", text: $restorePassphrase)
                Button {
                    showImporter = true
                } label: {
                    Label("Restore from a backup file…", systemImage: "arrow.counterclockwise")
                }
                .disabled(restorePassphrase.isEmpty || working)
                .accessibilityIdentifier("backup.restore")
            } header: {
                Text("Restore")
            } footer: {
                Text(
                    "Restore only works into an empty app (fresh install on this device) — it "
                        + "will not merge into existing conversations. A backup from another "
                        + "phone can't resume its encrypted sessions here; new-device transfer "
                        + "is coming separately.")
            }
        }
        .navigationTitle("Chat backup")
        .inlineNavigationTitle()
        .fileImporter(
            isPresented: $showImporter,
            allowedContentTypes: [UTType.data]
        ) { result in
            guard case .success(let url) = result else { return }
            working = true
            Task {
                _ = await model.restoreBackup(from: url, passphrase: restorePassphrase)
                working = false
            }
        }
    }
}
