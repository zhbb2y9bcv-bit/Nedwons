import Foundation
import NedwonsKit

/// The slice of the relay the messaging pipeline needs: prekeys in and out, targeted Welcomes,
/// fan-out sends, and the at-least-once inbox. `NedwonsClient` is the production implementation.
/// Tests supply an in-memory relay so two REAL MLS clients can be driven through the entire
/// pipeline — bootstrap, send, retry, relaunch, receive — deterministically and offline.
///
/// Every method takes the access token explicitly: the coordinator owns no credential, it reads
/// the current session from `AppModel` on each call, so a sign-out is honoured immediately.
public protocol ConversationRelay: Sendable {
    func publishKeyPackage(accessToken: String, keyPackage: Data) async throws
    /// Unexpired prekeys the relay still holds for this device.
    func availableKeyPackages(accessToken: String) async throws -> Int
    func claimKeyPackage(accessToken: String, accountID: String) async throws -> ClaimedKeyPackage
    func sendWelcome(
        accessToken: String, conversationID: String, recipientDevice: String, ciphertext: Data,
        idempotencyKey: Data
    ) async throws
    /// Fan-out; returns the number of recipient devices newly queued.
    func sendMessage(
        accessToken: String, conversationID: String, ciphertext: Data, idempotencyKey: Data
    ) async throws -> Int
    /// Upload encrypted attachment bytes; returns the relay's blob id.
    func uploadAttachment(accessToken: String, conversationID: String, ciphertext: Data) async throws
        -> String
    /// Fetch an attachment's ciphertext by blob id.
    func downloadAttachment(accessToken: String, blobID: String) async throws -> Data
    func fetchInbox(accessToken: String, waitSeconds: Int) async throws -> [InboxEnvelope]
    func ackInbox(accessToken: String, ids: [Int]) async throws

    // MLS setup queue (V27): the reconcile loop that gives invite joiners, deferred adds, and
    // freshly linked sibling devices their Welcomes automatically.
    func setupNeeded(accessToken: String) async throws -> [SetupTarget]
    func claimSetup(accessToken: String, conversationID: String, deviceID: String) async throws
        -> Bool
    func confirmSetup(accessToken: String, conversationID: String, deviceID: String) async throws
    func claimDeviceKeyPackage(accessToken: String, deviceID: String) async throws
        -> ClaimedKeyPackage

    // Sealed sender (ADR-0014). Registering a verifier is authenticated (we set our own gate);
    // DELIVERING is deliberately unauthenticated — presenting the recipient's `K_r` is the only
    // credential, which is the whole point: the relay never learns who sent it.
    func registerDeliveryAccessKey(accessToken: String, deliveryKey: DeliveryAccessKey) async throws
    func deliverSealed(
        deliveryKey: DeliveryAccessKey, recipientDevice: String, ciphertext: Data,
        idempotencyKey: Data
    ) async throws
    /// Acknowledge sealed envelopes. They live in their own id space, so they are acked separately
    /// from identified ones — never mixed.
    func ackSealed(accessToken: String, sealedIDs: [Int]) async throws
    /// This account's own device ids, which a grant carries so contacts can fan out sealed to us.
    func myDeviceIDs(accessToken: String) async throws -> [String]
}

extension NedwonsClient: ConversationRelay {
    public func availableKeyPackages(accessToken: String) async throws -> Int {
        try await keyPackageCount(accessToken: accessToken).available
    }

    /// Identified envelopes only: sealed-sender and self-group envelopes live in separate id
    /// spaces and are acked by their own consumers.
    public func ackInbox(accessToken: String, ids: [Int]) async throws {
        try await ackInbox(accessToken: accessToken, ids: ids, sealedIds: [], selfGroupIds: [])
    }

    public func ackSealed(accessToken: String, sealedIDs: [Int]) async throws {
        try await ackInbox(accessToken: accessToken, ids: [], sealedIds: sealedIDs, selfGroupIds: [])
    }

    public func myDeviceIDs(accessToken: String) async throws -> [String] {
        try await listDevices(accessToken: accessToken)
            .filter { !$0.revoked }
            .map(\.deviceID)
    }
}
