import Foundation
import NedwonsKit

/// Drives App Attest (#10, ADR-0017): generate a hardware-backed key once, attest it against a
/// server challenge, and remember that it was done.
///
/// `AppAttestation` and the two endpoints existed and were tested; nothing called them, so no build
/// ever attested. This is the piece that runs it — at registration and again on session restore,
/// since an install that was created before attestation was wired, or whose attempt failed, must
/// still converge.
///
/// ## The key id is the state
///
/// `DCAppAttestService.generateKey()` provisions a key with Apple. Calling it repeatedly mints a
/// NEW key every time, so a coordinator that forgot the id across launches would leak keys and
/// never attest the same one twice. The id is therefore persisted the moment it is generated —
/// BEFORE the attestation round trip, because a crash in between must leave the id recoverable
/// rather than orphan a key only Apple knows about.
@MainActor
public final class AppAttestCoordinator: ObservableObject {
    public enum Status: Equatable, Sendable {
        /// No usable App Attest (Simulator, unsupported hardware). Not an error — the server
        /// accepts unattested devices in bootstrap mode and records the lower assurance.
        case unsupported
        case notAttested
        case attested
        /// Attempted and refused. Carries the reason for display/diagnostics.
        case failed(String)
    }

    @Published public private(set) var status: Status = .notAttested

    private let attestation: AppAttestationProviding
    private let store: SecretStore
    private let keyIDAccount = "attest-key-id"
    private let attestedAccount = "attest-completed"

    /// Bounded per launch. A device that cannot attest (revoked key, Apple outage, no network)
    /// must not retry on every foreground forever — it would burn Apple's per-app rate limit and
    /// the app works without attestation regardless.
    private var attemptsThisLaunch = 0
    private static let maxAttemptsPerLaunch = 2

    public init(
        attestation: AppAttestationProviding = AppAttestation(),
        store: SecretStore = KeychainStore(service: "app.nedwons.attest")
    ) {
        self.attestation = attestation
        self.store = store
    }

    /// The key id provisioned with Apple for this install, if any.
    public var storedKeyID: String? {
        (try? store.load(account: keyIDAccount)).flatMap { $0 }.map {
            String(decoding: $0, as: UTF8.self)
        }
    }

    /// Whether this install has already completed attestation.
    public var hasAttested: Bool {
        ((try? store.load(account: attestedAccount)) ?? nil) != nil
    }

    /// Attest if this device can and has not already. Safe to call on every launch.
    ///
    /// Never throws to the caller: attestation is defence in depth, and a failure here must not
    /// block sign-in or leave the user staring at an error they cannot act on.
    public func attestIfNeeded(
        requestChallenge: () async throws -> Data,
        submit: (_ keyID: String, _ challenge: Data, _ attestation: Data) async throws -> Void
    ) async {
        guard attestation.isSupported else {
            status = .unsupported
            return
        }
        if hasAttested {
            status = .attested
            return
        }
        guard attemptsThisLaunch < Self.maxAttemptsPerLaunch else { return }
        attemptsThisLaunch += 1

        do {
            // Reuse the provisioned key. Generating a fresh one per attempt would mint a new Apple
            // key on every retry and attest none of them twice.
            let keyID: String
            if let existing = storedKeyID {
                keyID = existing
            } else {
                keyID = try await attestation.generateKey()
                // Persisted BEFORE the round trip: a crash here must not orphan a key.
                try? store.save(
                    Data(keyID.utf8), account: keyIDAccount,
                    accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
            }

            let challenge = try await requestChallenge()
            let blob = try await attestation.attestKey(keyID, challenge: challenge)
            try await submit(keyID, challenge, blob)

            try? store.save(
                Data("1".utf8), account: attestedAccount,
                accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
            status = .attested
        } catch let error as AppAttestError {
            // An invalid key cannot be rehabilitated — drop it so the NEXT launch provisions a
            // fresh one instead of retrying a key Apple has already rejected forever.
            if error == .invalidKey {
                try? store.delete(account: keyIDAccount)
            }
            status = .failed(String(describing: error))
        } catch {
            status = .failed("attestation could not be submitted")
        }
    }

    /// Forget attestation state (account deletion / sign-out of the last account on the device).
    public func reset() {
        try? store.delete(account: keyIDAccount)
        try? store.delete(account: attestedAccount)
        attemptsThisLaunch = 0
        status = .notAttested
    }
}

/// The slice of `AppAttestation` this coordinator uses, so tests can supply a fake. The real type
/// talks to `DCAppAttestService`, which is unavailable in the Simulator and in SwiftPM tests.
public protocol AppAttestationProviding: Sendable {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attestKey(_ keyID: String, challenge: Data) async throws -> Data
}

extension AppAttestation: AppAttestationProviding {}
