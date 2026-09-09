import CoreImage.CIFilterBuiltins
import NedwonsKit
import SwiftUI

#if os(iOS) && canImport(VisionKit)
    import VisionKit
#endif
#if canImport(UIKit)
    import UIKit
#elseif canImport(AppKit)
    import AppKit
#endif

/// Accessibility identifiers for the verification + invite surfaces (XCUITest).
public enum VerificationA11y {
    public static let safetyNumber = "verify.number"
    public static let markVerified = "verify.mark"
    public static let scan = "verify.scan"
    public static let pasteField = "verify.paste"
    public static let joinField = "join.field"
    public static let joinButton = "join.button"
    public static let inviteQR = "invite.qr"
}

// MARK: - QR rendering

/// A QR code rendered from a payload string with CoreImage. Pure display; the payload formats
/// live in `NedwonsKit` (`SafetyNumber.qrPayload`, `InviteCode.payload`) where they are tested.
struct QRCodeView: View {
    let payload: String

    var body: some View {
        if let image = Self.render(payload) {
            image
                .interpolation(.none) // crisp modules, not blurred pixels
                .resizable()
                .scaledToFit()
                .accessibilityLabel("QR code")
        } else {
            // CoreImage failing to encode a short ASCII string does not happen in practice, but
            // a blank square with no explanation would be worse than saying so.
            Text("Couldn't draw the code.")
                .font(Nedwons.TypeScale.caption)
        }
    }

    static func render(_ payload: String) -> Image? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        // Scale up before rasterizing so the CGImage is sharp at display size.
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 12, y: 12))
        let context = CIContext()
        guard let cg = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return Image(decorative: cg, scale: 1)
    }
}

// MARK: - Code scanning (camera on iOS hardware, paste everywhere)

/// Scans a QR code where the hardware can (VisionKit, iOS device) and always offers paste as the
/// fallback — the simulator and Macs have no scanner, and a paste path also serves codes received
/// over another channel. The `onCode` callback receives the raw string; callers parse it with the
/// tested `NedwonsKit` codecs and decide what it means.
struct CodeCaptureView: View {
    @Environment(\.colorScheme) private var scheme
    let prompt: String
    /// Off when the host screen provides its own entry field (the join screen does), so the user
    /// never sees two paste boxes for one code.
    var showPasteFallback = true
    let onCode: (String) -> Void

    @State private var pasted = ""
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        VStack(spacing: Nedwons.Spacing.lg) {
            #if os(iOS) && canImport(VisionKit)
                if DataScannerViewController.isSupported {
                    DataScannerRepresentable(onCode: onCode)
                        .frame(maxWidth: .infinity, minHeight: 280)
                        .clipShape(RoundedRectangle(cornerRadius: Nedwons.Radius.md))
                } else {
                    unsupportedNote
                }
            #else
                unsupportedNote
            #endif
            VStack(alignment: .leading, spacing: Nedwons.Spacing.sm) {
                Text(prompt)
                    .font(Nedwons.TypeScale.caption)
                    .foregroundStyle(palette.textSecondary)
                if showPasteFallback {
                    HStack(spacing: Nedwons.Spacing.sm) {
                        TextField("Paste a code", text: $pasted)
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                            .accessibilityIdentifier(VerificationA11y.pasteField)
                        Button("Use") { onCode(pasted) }
                            .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                }
            }
        }
        .padding(Nedwons.Spacing.lg)
    }

    private var unsupportedNote: some View {
        Text("This device can't scan — paste the code instead.")
            .font(Nedwons.TypeScale.caption)
            .foregroundStyle(palette.textSecondary)
    }
}

#if os(iOS) && canImport(VisionKit)
    /// Thin VisionKit wrapper: report each recognized QR payload once and let SwiftUI own all
    /// state. Requires camera permission (`NSCameraUsageDescription` is in the app's Info.plist).
    struct DataScannerRepresentable: UIViewControllerRepresentable {
        let onCode: (String) -> Void

        func makeUIViewController(context: Context) -> DataScannerViewController {
            let controller = DataScannerViewController(
                recognizedDataTypes: [.barcode(symbologies: [.qr])],
                qualityLevel: .balanced,
                isHighlightingEnabled: true)
            controller.delegate = context.coordinator
            try? controller.startScanning()
            return controller
        }

        func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}

        func makeCoordinator() -> Coordinator { Coordinator(onCode: onCode) }

        final class Coordinator: NSObject, DataScannerViewControllerDelegate {
            let onCode: (String) -> Void
            private var reported = Set<String>()
            init(onCode: @escaping (String) -> Void) { self.onCode = onCode }

            func dataScanner(
                _ scanner: DataScannerViewController, didAdd added: [RecognizedItem],
                allItems: [RecognizedItem]
            ) {
                for item in added {
                    if case .barcode(let barcode) = item,
                        let payload = barcode.payloadStringValue,
                        reported.insert(payload).inserted
                    {
                        onCode(payload)
                    }
                }
            }
        }
    }
#endif

// MARK: - Safety number screen

/// The safety-number comparison screen (roadmap step 4): 60 digits both people can read aloud, a
/// QR code that compares them exactly, and the switch that records this user's judgment. The
/// number is computed from transparency-verified keys — see `AppModel.safetyNumber`.
public struct SafetyNumberView: View {
    @ObservedObject var model: AppModel
    let peerAccountID: String
    let peerLabel: String

    @Environment(\.colorScheme) private var scheme
    @State private var info: SafetyNumberInfo?
    @State private var loading = true
    @State private var showScanner = false
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    public init(model: AppModel, peerAccountID: String, peerLabel: String) {
        self.model = model
        self.peerAccountID = peerAccountID
        self.peerLabel = peerLabel
    }

    public var body: some View {
        List {
            if let info {
                Section {
                    VStack(spacing: Nedwons.Spacing.lg) {
                        QRCodeView(payload: info.qrPayload)
                            .frame(width: 220, height: 220)
                            .padding(Nedwons.Spacing.sm)
                            .background(Color.white) // QR quiet zone: always white, both themes
                            .clipShape(RoundedRectangle(cornerRadius: Nedwons.Radius.md))
                        digitsGrid(info.digitGroups)
                            .accessibilityIdentifier(VerificationA11y.safetyNumber)
                        if model.isPeerVerified(peerAccountID) {
                            SecurityBadge(.verified, palette: palette)
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, Nedwons.Spacing.md)
                }

                Section {
                    Toggle(
                        "Mark as verified",
                        isOn: Binding(
                            get: { model.isPeerVerified(peerAccountID) },
                            set: { model.setPeerVerified(peerAccountID, $0) }
                        )
                    )
                    .accessibilityIdentifier(VerificationA11y.markVerified)
                    Button {
                        showScanner = true
                    } label: {
                        Label("Scan their code", systemImage: "qrcode.viewfinder")
                    }
                    .accessibilityIdentifier(VerificationA11y.scan)
                } footer: {
                    Text(explainer(info))
                }
            } else if loading {
                Section {
                    HStack(spacing: Nedwons.Spacing.sm) {
                        ProgressView()
                        Text("Checking the key transparency log…")
                            .font(Nedwons.TypeScale.caption)
                            .foregroundStyle(palette.textSecondary)
                    }
                }
            } else {
                Section {
                    Text("Couldn't compute a safety number.")
                        .foregroundStyle(palette.textSecondary)
                    Button("Try again") { Task { await load() } }
                }
            }
        }
        .navigationTitle("Verify \(peerLabel)")
        .inlineNavigationTitle()
        .task { await load() }
        .sheet(isPresented: $showScanner) {
            NavigationStack {
                CodeCaptureView(prompt: "Scan or paste the code shown on their screen.") { code in
                    showScanner = false
                    Task { _ = await model.confirmScannedSafetyCode(code, peerAccountID: peerAccountID) }
                }
                .navigationTitle("Scan to verify")
                .inlineNavigationTitle()
            }
        }
    }

    private func load() async {
        loading = true
        info = await model.safetyNumber(with: peerAccountID)
        loading = false
    }

    private func digitsGrid(_ groups: [String]) -> some View {
        // 12 groups as 3 rows of 4 — the layout people actually read aloud.
        VStack(spacing: Nedwons.Spacing.xs) {
            ForEach(0..<3, id: \.self) { row in
                HStack(spacing: Nedwons.Spacing.md) {
                    ForEach(0..<4, id: \.self) { col in
                        Text(groups[row * 4 + col])
                            .font(Nedwons.TypeScale.monoSmall)
                            .foregroundStyle(palette.textPrimary)
                    }
                }
            }
        }
    }

    private func explainer(_ info: SafetyNumberInfo) -> String {
        "Compare these numbers with \(peerLabel) in person or on a call you trust — or scan "
            + "each other's codes. Matching numbers mean both phones agree on the keys the "
            + "transparency log served (\(info.myDeviceCount) of yours, \(info.peerDeviceCount) "
            + "of theirs). The number changes when either of you adds or removes a device; "
            + "re-verify when it does. Verification is stored only on this device."
    }
}

// MARK: - Invite QR (admin side)

/// Shows a minted invite token as a QR code plus the raw token for copying — the share surface
/// behind each row of the group panel's invite list.
struct InviteQRView: View {
    @Environment(\.colorScheme) private var scheme
    let token: String
    let groupTitle: String
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        VStack(spacing: Nedwons.Spacing.lg) {
            Text("Invite to \(groupTitle)")
                .font(Nedwons.TypeScale.headline)
            QRCodeView(payload: InviteCode.payload(token: token))
                .frame(width: 240, height: 240)
                .padding(Nedwons.Spacing.sm)
                .background(Color.white)
                .clipShape(RoundedRectangle(cornerRadius: Nedwons.Radius.md))
                .accessibilityIdentifier(VerificationA11y.inviteQR)
            Text(token)
                .font(Nedwons.TypeScale.monoSmall)
                .foregroundStyle(palette.textSecondary)
                .textSelection(.enabled)
                .lineLimit(2)
                .padding(.horizontal, Nedwons.Spacing.lg)
            Button {
                #if os(iOS)
                    UIPasteboard.general.string = token
                #elseif os(macOS)
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(token, forType: .string)
                #endif
            } label: {
                Label("Copy invite code", systemImage: "doc.on.doc")
            }
            Text("Anyone with this code can join (or request to join) until it expires, runs out of uses, or is revoked. Share it like a key.")
                .font(Nedwons.TypeScale.caption)
                .foregroundStyle(palette.textSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, Nedwons.Spacing.lg)
        }
        .padding(Nedwons.Spacing.xl)
    }
}

// MARK: - Join with an invite

/// The joiner's half of QR invites: scan or paste a code, join (or request to join). Reachable
/// from the chats list.
public struct JoinByInviteView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    @Environment(\.dismiss) private var dismiss
    @State private var code = ""
    @State private var invalid = false
    @State private var joining = false
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    public init(model: AppModel) { self.model = model }

    public var body: some View {
        VStack(spacing: Nedwons.Spacing.lg) {
            CodeCaptureView(
                prompt: "Scan an invite QR, or paste the invite code you were sent.",
                showPasteFallback: false
            ) { scanned in
                accept(raw: scanned)
            }
            TextField("Invite code", text: $code)
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
                .accessibilityIdentifier(VerificationA11y.joinField)
                .padding(.horizontal, Nedwons.Spacing.lg)
            if invalid {
                Text("That doesn't look like a Nedwons invite code.")
                    .font(Nedwons.TypeScale.caption)
                    .foregroundStyle(palette.destructive)
            }
            Button {
                accept(raw: code)
            } label: {
                if joining {
                    ProgressView()
                } else {
                    Text("Join")
                        .frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(joining || code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            .accessibilityIdentifier(VerificationA11y.joinButton)
            .padding(.horizontal, Nedwons.Spacing.lg)
            Text("Joining is your choice — an invite never adds you by itself (and this screen is how you exercise it).")
                .font(Nedwons.TypeScale.caption)
                .foregroundStyle(palette.textSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, Nedwons.Spacing.lg)
            Spacer()
        }
        .padding(.top, Nedwons.Spacing.lg)
        .navigationTitle("Join a group")
        .inlineNavigationTitle()
    }

    private func accept(raw: String) {
        guard let token = InviteCode.parse(raw) else {
            invalid = true
            return
        }
        invalid = false
        joining = true
        Task {
            let joined = await model.joinWithInvite(token: token)
            joining = false
            if joined { dismiss() }
        }
    }
}
