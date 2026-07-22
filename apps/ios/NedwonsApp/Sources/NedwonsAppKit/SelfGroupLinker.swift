import Foundation
import MlsFfi
import NedwonsKit

/// Orchestrates the ADR-0015 self-group device link over `NedwonsClient` + `MlsClient`. The CLI
/// harness (`SelfGroupLiveRun`, which proves it live) and the Devices screen drive this same code,
/// so the UI path is the tested path.
///
/// Two roles, matching the two sides of a link:
///   • **Primary** (a device that already holds the account's self-group, or is establishing it):
///     for each pending sibling it claims a key package, `addSelfDevice`s it (a real MLS Welcome),
///     and delivers that Welcome to the sibling over `/v1/self-group/deliver`.
///   • **Joiner** (a freshly-enrolled sibling): it pulls the Welcome waiting on its self-group
///     channel, `joinSelfGroup`s it, registers as a member, and acks.
///
/// The relay stays MLS-blind throughout: only opaque Welcome/commit bytes cross it. Every step is
/// idempotent-safe (fresh idempotency keys; re-running after a partial link is a no-op for devices
/// already added). `MlsClient` is not `Sendable`, so callers hand it in on the calling actor/thread;
/// the linker itself is a stateless value.
public struct SelfGroupLinker: Sendable {
    private let client: NedwonsClient

    public init(client: NedwonsClient) { self.client = client }

    /// The outcome of a primary-side link pass.
    public struct LinkResult: Sendable, Equatable {
        /// Sibling device ids a Welcome was newly delivered to this pass.
        public let linked: [String]
        /// Whether this pass had to establish the self-group first (first sibling ever linked).
        public let createdSelfGroup: Bool
    }

    /// **Primary side.** Ensure this device holds the account's self-group (create + register it if
    /// not), then link every currently-pending sibling: claim its key package, `addSelfDevice`, and
    /// deliver the Welcome. Returns which siblings were linked. Safe to call repeatedly — only
    /// devices the relay still reports as pending are added.
    ///
    /// `mls` must be this (primary) device's durable client. Throws on the first hard transport/MLS
    /// error; a sibling that has published no key package yet is skipped (left pending for next time).
    @discardableResult
    public func linkPendingSiblings(mls: MlsClient, accessToken: String) async throws -> LinkResult {
        var createdSelfGroup = false
        if !(try mls.hasSelfGroup()) {
            try mls.createSelfGroup()
            try await client.registerSelfGroupMember(accessToken: accessToken)
            createdSelfGroup = true
        }

        let pending = try await client.pendingSelfGroupDevices(accessToken: accessToken)
        var linked: [String] = []
        for deviceID in pending {
            let claim: ClaimedKeyPackage
            do {
                claim = try await client.claimSelfGroupKeyPackage(
                    accessToken: accessToken, deviceID: deviceID)
            } catch let NedwonsClient.ClientError.http(status, _) where status == 404 {
                continue  // sibling hasn't published a key package yet — leave it pending
            }
            guard claim.deviceID == deviceID, let keyPackage = Hex.decode(claim.keyPackage) else {
                continue
            }
            let add = try mls.addSelfDevice(keyPackage: keyPackage)  // real MLS Welcome
            _ = try await client.deliverSelfGroup(
                accessToken: accessToken, recipientDevice: deviceID,
                ciphertext: add.welcome, idempotencyKey: Self.idempotencyKey())
            linked.append(deviceID)
        }
        return LinkResult(linked: linked, createdSelfGroup: createdSelfGroup)
    }

    /// **Joiner side.** If this device isn't yet in the self-group, pull the Welcome waiting on its
    /// self-group channel, `joinSelfGroup` it, register as a member, and ack the consumed Welcome.
    /// Returns `true` once the device holds the self-group (including if it already did). Idempotent:
    /// a second call after joining returns `true` without touching the relay.
    ///
    /// `mls` must be this (joining) device's durable client — the one whose published key package the
    /// primary claimed.
    @discardableResult
    public func joinSelfGroupFromInbox(mls: MlsClient, accessToken: String) async throws -> Bool {
        if try mls.hasSelfGroup() { return true }

        let inbox = try await client.fetchInbox(accessToken: accessToken)
        let welcomes = inbox.filter { $0.selfGroup }
        guard let welcome = welcomes.first, let bytes = Hex.decode(welcome.ciphertext) else {
            return false  // no Welcome yet — the primary hasn't linked us
        }
        try mls.joinSelfGroup(welcome: bytes)
        try await client.registerSelfGroupMember(accessToken: accessToken)
        try await client.ackInbox(
            accessToken: accessToken, ids: [], selfGroupIds: welcomes.map { $0.id })
        return try mls.hasSelfGroup()
    }

    /// A fresh 16-byte idempotency key so a retried deliver is de-duped by the relay.
    private static func idempotencyKey() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        for i in bytes.indices { bytes[i] = .random(in: 0 ... 255) }
        return Data(bytes)
    }
}
