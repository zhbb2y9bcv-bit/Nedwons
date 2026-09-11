import Foundation
import NedwonsKit

/// Drives both halves of QR device pairing (ADR-0008, BN-4).
///
/// The two roles are one type because they share a state machine and, crucially, a SAS: the whole
/// point of the code is that the SAME value is derived on both sides from the same offer, so
/// keeping the derivation in one place is what keeps them comparable.
///
/// Every operation that touches the Secure Enclave or the network is injected, so the flow —
/// including the refusal paths, which are the ones that matter — is unit-testable with no hardware
/// and no server.
@MainActor
public final class DevicePairingModel: ObservableObject {
    /// Which side of the pairing this device is on.
    public enum Role: Equatable, Sendable {
        /// The device being added. Shows an offer, then scans the grant.
        case newDevice
        /// An already-enrolled device. Scans the offer, signs the enrollment, shows the grant.
        case trustedDevice
    }

    public enum Step: Equatable, Sendable {
        case idle
        /// New device: offer generated and displayed, waiting for the grant.
        case showingOffer
        /// Trusted device: offer scanned; the user must compare the SAS before anything is signed.
        case confirmingCode
        /// Trusted device: enrollment in flight.
        case enrolling
        /// Trusted device: grant ready to display.
        case showingGrant
        case paired
        case failed(String)
    }

    @Published public private(set) var step: Step = .idle
    /// The six-group code shown on BOTH devices. Empty until an offer exists.
    @Published public private(set) var code: [String] = []
    /// The payload to render as a QR, if this step shows one.
    @Published public private(set) var payload: String?

    /// The offer this device generated (new-device role) or scanned (trusted role).
    private(set) var offer: DevicePairing.Offer?

    private let role: Role

    /// Provisions (or reloads) this device's signer and returns its public key. New-device role.
    private let provisionKey: () throws -> Data
    /// Enrolls `publicKey` using this device's trusted signer, returning the new device's session.
    /// Trusted role.
    private let enroll: (Data) async throws -> NedwonsClient.Session
    /// Adopts a session received through a grant. New-device role.
    private let adopt: (NedwonsClient.Session) async -> Void

    public init(
        role: Role,
        provisionKey: @escaping () throws -> Data = { Data() },
        enroll: @escaping (Data) async throws -> NedwonsClient.Session = { _ in
            throw DevicePairing.PairingError.sealFailed
        },
        adopt: @escaping (NedwonsClient.Session) async -> Void = { _ in }
    ) {
        self.role = role
        self.provisionKey = provisionKey
        self.enroll = enroll
        self.adopt = adopt
    }

    // MARK: New device

    /// Generate this device's key and show the offer.
    public func beginAsNewDevice() {
        guard role == .newDevice else { return }
        do {
            let publicKey = try provisionKey()
            let offer = DevicePairing.Offer.create(devicePublicKeyX963: publicKey)
            self.offer = offer
            code = DevicePairing.shortAuthenticationString(for: offer)
            payload = DevicePairing.encode(offer)
            step = .showingOffer
        } catch {
            step = .failed(
                "This device couldn't create a secure key. Pairing needs the Secure Enclave.")
        }
    }

    /// A grant was scanned. Opens it with THIS device's pairing key and adopts the session.
    public func receiveGrant(_ raw: String) async {
        guard role == .newDevice, let offer else { return }
        guard let grant = DevicePairing.decodeGrant(raw) else {
            step = .failed("That isn't a pairing code from another Nedwons device.")
            return
        }
        do {
            let session = try DevicePairing.open(grant: grant, with: offer)
            await adopt(session)
            payload = nil
            step = .paired
        } catch {
            // The grant did not open under our pairing key, so it was produced for a DIFFERENT
            // offer. Refusing is the point: it means the other device enrolled somebody else's
            // key, and adopting the session anyway would be adopting a stranger's pairing.
            step = .failed(
                "That code was meant for a different device. Start the pairing again on both "
                    + "devices.")
        }
    }

    // MARK: Trusted device

    /// An offer was scanned. Shows the SAS; NOTHING is signed until the user confirms.
    public func receiveOffer(_ raw: String) {
        guard role == .trustedDevice else { return }
        guard let offer = DevicePairing.decodeOffer(raw) else {
            step = .failed("That isn't a Nedwons pairing code.")
            return
        }
        self.offer = offer
        code = DevicePairing.shortAuthenticationString(for: offer)
        payload = nil
        step = .confirmingCode
    }

    /// The user confirmed the codes match on both screens. Only now is the enrollment signed.
    public func confirmCodeAndEnroll() async {
        guard role == .trustedDevice, let offer, step == .confirmingCode else { return }
        step = .enrolling
        do {
            let session = try await enroll(offer.devicePublicKeyX963)
            let grant = try DevicePairing.seal(session: session, under: offer)
            payload = DevicePairing.encode(grant)
            step = .showingGrant
        } catch {
            step = .failed("Couldn't add that device. It hasn't been added to your account.")
        }
    }

    /// The user says the codes differ — abandon without signing anything.
    ///
    /// The state is fully cleared rather than merely stepping back: a mismatched offer must not
    /// remain available to a later "confirm" tap.
    public func rejectCode() {
        offer = nil
        code = []
        payload = nil
        step = .failed(
            "Pairing cancelled because the codes didn't match. Nothing was added to your account.")
    }

    /// The trusted device is finished once the new device has taken the grant.
    public func finishTrustedFlow() {
        payload = nil
        step = .paired
    }

    public func reset() {
        offer = nil
        code = []
        payload = nil
        step = .idle
    }
}
