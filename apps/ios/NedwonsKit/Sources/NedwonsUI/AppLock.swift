import LocalAuthentication
import SwiftUI

/// App lock: an optional Face ID / Touch ID / passcode gate in FRONT of the whole app, so a phone
/// left unlocked doesn't hand someone your messages. It is a LOCAL convenience over presentation
/// only — it is not part of the E2EE story and protects nothing on the wire; the message store is
/// already encrypted at rest regardless. The biometric check is abstracted behind
/// `AppLockAuthenticating` so the lock STATE MACHINE is testable without hardware.
public protocol AppLockAuthenticating: Sendable {
    /// Whether this device can authenticate the owner at all (a biometric enrolled, or a passcode
    /// set). If false, app lock cannot be turned on — better than locking someone out.
    var isAvailable: Bool { get }
    /// "Face ID", "Touch ID", or "passcode" — for naming the control honestly.
    var biometryName: String { get }
    /// Prompt the owner. Returns true only on a successful check; any failure or cancel is false.
    func authenticate(reason: String) async -> Bool
}

/// The production authenticator, wrapping `LocalAuthentication`. Uses
/// `.deviceOwnerAuthentication` (biometrics OR the device passcode) so it still works on a device
/// with no biometric enrolled, and never silently degrades to "no check".
public struct LocalAuthAppLock: AppLockAuthenticating {
    public init() {}

    private func freshContext() -> LAContext { LAContext() }

    public var isAvailable: Bool {
        var error: NSError?
        return freshContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    }

    public var biometryName: String {
        let ctx = freshContext()
        // canEvaluatePolicy must be called before biometryType is populated.
        _ = ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
        switch ctx.biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        default: return "passcode"
        }
    }

    public func authenticate(reason: String) async -> Bool {
        let ctx = freshContext()
        return await withCheckedContinuation { continuation in
            ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
                continuation.resume(returning: success)
            }
        }
    }
}

/// The full-screen cover shown while the app is locked. It hides whatever is behind it and offers
/// the unlock prompt; on appear it attempts to authenticate immediately, so foregrounding goes
/// straight to Face ID rather than making the user tap first.
struct LockScreenView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    @State private var attempting = false
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    var body: some View {
        ZStack {
            palette.background.ignoresSafeArea()
            VStack(spacing: Nedwons.Spacing.lg) {
                Image(systemName: "lock.fill")
                    .font(.system(size: 52))
                    .foregroundStyle(palette.accentPrimary)
                Text("Nedwons is locked")
                    .font(Nedwons.TypeScale.headline)
                    .foregroundStyle(palette.textPrimary)
                Button {
                    attempt()
                } label: {
                    Text("Unlock with \(model.appLockBiometryName)")
                        .frame(maxWidth: 260)
                }
                .buttonStyle(.borderedProminent)
                .disabled(attempting)
                .accessibilityIdentifier("applock.unlock")
            }
        }
        .accessibilityIdentifier("applock.screen")
        // Foregrounding presents this view fresh; prompt right away.
        .onAppear { attempt() }
    }

    private func attempt() {
        guard !attempting else { return }
        attempting = true
        Task {
            await model.unlock()
            attempting = false
        }
    }
}
