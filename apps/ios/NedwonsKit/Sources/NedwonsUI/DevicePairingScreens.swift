import NedwonsKit
import SwiftUI

/// Accessibility identifiers for the pairing surface (XCUITest).
public enum PairingA11y {
    public static let code = "pair.code"
    public static let offerQR = "pair.offer.qr"
    public static let grantQR = "pair.grant.qr"
    public static let codesMatch = "pair.codesMatch"
    public static let codesDiffer = "pair.codesDiffer"
    public static let done = "pair.done"
}

/// The screen the **new** device shows: its offer as a QR, the code to compare, then a scanner for
/// the grant coming back.
public struct PairNewDeviceView: View {
    @StateObject private var model: DevicePairingModel
    @Environment(\.colorScheme) private var scheme
    @Environment(\.dismiss) private var dismiss

    private var palette: Nedwons.Palette { .forScheme(scheme) }

    public init(model: @autoclosure @escaping () -> DevicePairingModel) {
        _model = StateObject(wrappedValue: model())
    }

    public var body: some View {
        Form {
            switch model.step {
            case .idle:
                Section { ProgressView() }
            case .showingOffer:
                offerSection
                codeSection(
                    caption: "Check this code matches the one on your other device, then scan the "
                        + "code it shows you.")
                scanGrantSection
            case .paired:
                Section {
                    Label("This device is now part of your account.", systemImage: "checkmark.seal.fill")
                        .foregroundStyle(palette.verified)
                    Button("Done") { dismiss() }
                        .accessibilityIdentifier(PairingA11y.done)
                }
            case .failed(let reason):
                Section {
                    Text(reason).foregroundStyle(.red)
                    Button("Start over") { model.beginAsNewDevice() }
                }
            default:
                Section { ProgressView() }
            }
        }
        .navigationTitle("Add this device")
        .inlineNavigationTitle()
        .onAppear { if model.step == .idle { model.beginAsNewDevice() } }
    }

    @ViewBuilder
    private var offerSection: some View {
        if let payload = model.payload {
            Section {
                QRCodeView(payload: payload)
                    .frame(maxWidth: 240)
                    .frame(maxWidth: .infinity)
                    .padding(Nedwons.Spacing.sm)
                    // QR quiet zone is white in both themes; a dark-mode-tinted code will not scan.
                    .background(Color.white)
                    .accessibilityIdentifier(PairingA11y.offerQR)
            } header: {
                Text("Show this to your other device")
            } footer: {
                Text(
                    "Your existing device scans this to add you. The code carries this device's "
                        + "public key only — never your messages or your password.")
            }
        }
    }

    @ViewBuilder
    private var scanGrantSection: some View {
        Section {
            CodeCaptureView(prompt: "Scan the code from your other device") { raw in
                Task { await model.receiveGrant(raw) }
            }
        } header: {
            Text("Then scan theirs")
        }
    }

    private func codeSection(caption: String) -> some View {
        Section {
            PairingCodeView(groups: model.code, palette: palette)
        } header: {
            Text("Pairing code")
        } footer: {
            Text(caption)
        }
    }
}

/// The screen an **already-enrolled** device shows: scan the new device's offer, compare the code,
/// and only then sign the enrollment.
public struct PairTrustedDeviceView: View {
    @StateObject private var model: DevicePairingModel
    @Environment(\.colorScheme) private var scheme
    @Environment(\.dismiss) private var dismiss

    private var palette: Nedwons.Palette { .forScheme(scheme) }

    public init(model: @autoclosure @escaping () -> DevicePairingModel) {
        _model = StateObject(wrappedValue: model())
    }

    public var body: some View {
        Form {
            switch model.step {
            case .idle:
                Section {
                    CodeCaptureView(prompt: "Scan the code on the device you're adding") { raw in
                        model.receiveOffer(raw)
                    }
                } footer: {
                    Text("On the new device, choose \"Add this device\" to get its code.")
                }

            case .confirmingCode:
                Section {
                    PairingCodeView(groups: model.code, palette: palette)
                } header: {
                    Text("Pairing code")
                } footer: {
                    // The one thing the user must actually do. Stated as a comparison, not as a
                    // confirmation prompt, because "OK" on a dialog is not a check.
                    Text(
                        "These five-digit groups must be identical to the ones on the other "
                            + "device. If they differ, someone else's code was scanned — choose "
                            + "\"They don't match\".")
                }
                Section {
                    Button("They match — add this device") {
                        Task { await model.confirmCodeAndEnroll() }
                    }
                    .accessibilityIdentifier(PairingA11y.codesMatch)
                    Button("They don't match", role: .destructive) { model.rejectCode() }
                        .accessibilityIdentifier(PairingA11y.codesDiffer)
                }

            case .enrolling:
                Section { HStack { ProgressView(); Text("Adding the device…") } }

            case .showingGrant:
                if let payload = model.payload {
                    Section {
                        QRCodeView(payload: payload)
                            .frame(maxWidth: 240)
                            .frame(maxWidth: .infinity)
                            .padding(Nedwons.Spacing.sm)
                            .background(Color.white)
                            .accessibilityIdentifier(PairingA11y.grantQR)
                    } header: {
                        Text("Show this back to the new device")
                    } footer: {
                        Text(
                            "This code is encrypted so only the device you just scanned can open "
                                + "it. Don't share a photo of it.")
                    }
                    Section {
                        Button("The other device has scanned it") { model.finishTrustedFlow() }
                            .accessibilityIdentifier(PairingA11y.done)
                    }
                }

            case .paired:
                Section {
                    Label("Device added.", systemImage: "checkmark.seal.fill")
                        .foregroundStyle(palette.verified)
                    Button("Done") { dismiss() }
                        .accessibilityIdentifier(PairingA11y.done)
                }

            case .failed(let reason):
                Section {
                    Text(reason).foregroundStyle(.red)
                    Button("Start over") { model.reset() }
                }

            case .showingOffer:
                EmptyView()
            }
        }
        .navigationTitle("Add a device")
        .inlineNavigationTitle()
    }
}

/// The six five-digit groups, laid out so two people can read them to each other.
struct PairingCodeView: View {
    let groups: [String]
    let palette: Nedwons.Palette

    private let columns = [GridItem(.adaptive(minimum: 78))]

    var body: some View {
        LazyVGrid(columns: columns, spacing: Nedwons.Spacing.sm) {
            ForEach(Array(groups.enumerated()), id: \.offset) { _, group in
                Text(group)
                    .font(Nedwons.TypeScale.monoSmall)
                    .foregroundStyle(palette.textPrimary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, Nedwons.Spacing.xs)
                    .background(palette.surfaceRaised, in: RoundedRectangle(cornerRadius: Nedwons.Radius.sm))
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityIdentifier(PairingA11y.code)
        .accessibilityLabel("Pairing code")
        // Digit by digit: VoiceOver reading "12345" as "twelve thousand three hundred forty-five"
        // is unusable for a code two people must compare aloud.
        .accessibilityValue(groups.joined(separator: ", ").map(String.init).joined(separator: " "))
    }
}
