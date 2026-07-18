import MlsFfi
import SentinelAppKit
import SentinelUI
import SwiftUI

/// One conversation item the demo renders.
struct DemoItem: Identifiable {
    let id = UUID()
    enum Kind {
        case text(String)
        case secret(Data)  // secret id; render a sealed placeholder / tombstone
    }
    let kind: Kind
    let mine: Bool  // true = sent by "You" (never a secret in this demo)
}

/// Drives a real two-party MLS group in-process: a "Contact" (Alice) sends to "You" (Bob). Messages
/// flow through the genuine MLS pipeline (encrypt → processInbound); secrets arrive sealed and are
/// revealed once via the Rust state machine. No mock crypto, no network.
@MainActor
final class SecretDemoModel: ObservableObject {
    @Published var items: [DemoItem] = []
    @Published var draft: String = ""
    @Published var secretArmed: Bool = false
    /// Non-nil while a secret overlay is presented.
    @Published var revealing: SecretMessageViewModel?

    private let contact: MlsClient  // Alice — the remote sender
    private let me: MlsClient  // Bob — this device
    private var envelopeCounter: UInt64 = 0
    let engine: MlsClientSecretEngine

    init() {
        let key = Data(repeating: 7, count: 32)
        let dir = NSTemporaryDirectory()
        contact = try! MlsClient.createGroup(
            identity: Data("contact".utf8), dbPath: dir + "contact-\(UUID())", atRestKey: key)
        me = try! MlsClient.newJoiner(
            identity: Data("me".utf8), dbPath: dir + "me-\(UUID())", atRestKey: key)
        let add = try! contact.addMember(keyPackage: try! me.keyPackage())
        try! me.joinGroup(welcome: add.welcome)
        engine = MlsClientSecretEngine(client: me)

        // Seed the conversation so the feature is visible on first launch.
        receiveFromContact("Hey — here's the address.", secret: false)
        receiveFromContact("meet me at pier 39 at 9", secret: true)

        // Testing affordance: `-autoRevealDemo` reveals the seeded secret shortly after launch so
        // the overlay/countdown can be screenshotted headlessly (no tap tooling). Not used in
        // normal operation.
        if ProcessInfo.processInfo.arguments.contains("-autoRevealDemo"),
            let first = items.first(where: {
                if case .secret = $0.kind { return true } else { return false }
            }), case let .secret(sid) = first.kind
        {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { [weak self] in
                self?.reveal(sid)
            }
        }
    }

    /// The Contact sends a message to You (drives the sealed-placeholder + reveal path).
    func receiveFromContact(_ text: String, secret: Bool) {
        do {
            let localId: UInt64
            if secret {
                localId = try contact.enqueueSecret(body: Data(text.utf8)).localId
            } else {
                localId = try contact.enqueue(plaintext: Data(text.utf8))
            }
            let envelope = try contact.encrypt(localId: localId)
            try contact.markSent(localId: localId)
            envelopeCounter += 1
            switch try me.processInbound(envelopeId: envelopeCounter, ciphertext: envelope) {
            case .application(let pt):
                items.append(DemoItem(kind: .text(String(decoding: pt, as: UTF8.self)), mine: false))
            case .secretSealed(let sid):
                items.append(DemoItem(kind: .secret(sid), mine: false))
            default:
                break
            }
        } catch {
            // A demo: surface nothing sensitive, just skip.
        }
    }

    /// You send a normal message (secrets from this device aren't part of this demo's scope).
    func sendDraft() {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        items.append(DemoItem(kind: .text(text), mine: true))
        draft = ""
        secretArmed = false
    }

    /// Tap a sealed placeholder → present the reveal overlay backed by the real core.
    func reveal(_ secretID: Data) {
        let vm = SecretMessageViewModel(secretID: secretID, engine: engine)
        vm.beginReveal()
        revealing = vm
    }

    func phase(_ secretID: Data) -> SentinelUI.SecretPhase {
        (try? engine.phase(secretID: secretID, nowMs: UptimeClock().nowMs())) ?? .unknown
    }
}

/// The demo conversation screen: a scrollable message list (normal bubbles + sealed placeholders /
/// tombstones), a composer with the Secret toggle, and the full-cover reveal overlay.
public struct SecretDemoView: View {
    @StateObject private var model = SecretDemoModel()
    @Environment(\.colorScheme) private var scheme

    public init() {}

    public var body: some View {
        let palette = Sentinel.Palette.forScheme(scheme)
        ZStack {
            palette.background.ignoresSafeArea()
            VStack(spacing: 0) {
                header(palette)
                messageList(palette)
                composer(palette)
            }
            if let vm = model.revealing {
                SecretOverlayView(model: vm) { model.revealing = nil }
                    .transition(.opacity)
            }
        }
    }

    private func header(_ palette: Sentinel.Palette) -> some View {
        HStack {
            Text("Contact")
                .font(Sentinel.TypeScale.headline)
                .foregroundStyle(palette.textPrimary)
            Spacer()
            Image(systemName: "lock.shield.fill").foregroundStyle(palette.verified)
        }
        .padding(Sentinel.Spacing.lg)
        .background(palette.surface)
    }

    private func messageList(_ palette: Sentinel.Palette) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Sentinel.Spacing.sm) {
                ForEach(model.items) { item in
                    row(item, palette)
                        .frame(maxWidth: .infinity, alignment: item.mine ? .trailing : .leading)
                }
            }
            .padding(Sentinel.Spacing.md)
        }
    }

    @ViewBuilder
    private func row(_ item: DemoItem, _ palette: Sentinel.Palette) -> some View {
        switch item.kind {
        case .text(let text):
            Text(text)
                .font(Sentinel.TypeScale.body)
                .foregroundStyle(item.mine ? .white : palette.textPrimary)
                .padding(.horizontal, Sentinel.Spacing.md)
                .padding(.vertical, Sentinel.Spacing.sm)
                .background(item.mine ? palette.accentPrimary : palette.incomingBubble)
                .clipShape(RoundedRectangle(cornerRadius: Sentinel.Radius.bubble))
        case .secret(let sid):
            if model.phase(sid) == .consumed {
                SecretTombstoneView(text: model.engine.tombstoneText)
                    .padding(.vertical, Sentinel.Spacing.xs)
            } else {
                SecretSealedPlaceholderView { model.reveal(sid) }
                    .foregroundStyle(palette.accentSecondary)
            }
        }
    }

    private func composer(_ palette: Sentinel.Palette) -> some View {
        HStack(spacing: Sentinel.Spacing.sm) {
            SecretComposerToggle(isArmed: $model.secretArmed)
            TextField("Message", text: $model.draft)
                .textFieldStyle(.roundedBorder)
            Button {
                model.sendDraft()
            } label: {
                Image(systemName: "arrow.up.circle.fill").imageScale(.large)
            }
            .disabled(model.draft.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(Sentinel.Spacing.md)
        .background(palette.surface)
    }
}
