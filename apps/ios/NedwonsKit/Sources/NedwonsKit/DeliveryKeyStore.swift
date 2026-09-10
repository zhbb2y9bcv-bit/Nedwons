import CryptoKit
import Foundation

/// What a contact granted us: their sealed-sender delivery access key and the devices to fan a
/// sealed message out to (ADR-0014 Slice 2c). Both arrive inside the E2EE channel, so the relay
/// never learns either.
public struct DeliveryGrant: Codable, Equatable, Sendable {
    /// Hex of the 32-byte `K_r`. Stored as hex so the JSON blob is a plain, inspectable map; the
    /// blob itself is encrypted at rest.
    public let keyHex: String
    /// Hex device ids of the granter's own devices.
    public let deviceIDs: [String]

    public init(keyHex: String, deviceIDs: [String]) {
        self.keyHex = keyHex
        self.deviceIDs = deviceIDs
    }

    public var key: DeliveryAccessKey? {
        Hex.decode(keyHex).flatMap { DeliveryAccessKey(keyMaterial: $0) }
    }
}

/// Sealed-sender key material at rest: OUR delivery access key `K_r` (the one we register a
/// verifier for and hand to approved contacts), and the grants contacts have handed US.
///
/// Encrypted with a key from `AtRestKeyHierarchy`, exactly like private aliases, so it dies with
/// the at-rest root on sign-out. `K_r` is a capability to *deliver* to us — leaking it would let
/// someone put sealed envelopes in our inbox — so it never touches plaintext storage.
public final class DeliveryKeyStore: @unchecked Sendable {
    private struct Blob: Codable {
        var mineHex: String?
        var grants: [String: DeliveryGrant] = [:]
        /// Accounts we have already handed our CURRENT `K_r` to, so a re-grant is only sent when it
        /// is actually needed (a new contact, or after a rotation clears this).
        var grantedTo: Set<String> = []
    }

    private let url: URL
    private let key: SymmetricKey
    private var blob: Blob
    private let lock = NSLock()

    public init(fileURL: URL, atRestKey: Data) {
        self.url = fileURL
        self.key = SymmetricKey(data: atRestKey)
        self.blob = Self.read(url: fileURL, key: self.key)
    }

    private static func read(url: URL, key: SymmetricKey) -> Blob {
        guard let data = try? Data(contentsOf: url),
            let sealed = try? AES.GCM.SealedBox(combined: data),
            let plain = try? AES.GCM.open(sealed, using: key),
            let blob = try? JSONDecoder().decode(Blob.self, from: plain)
        else { return Blob() }
        return blob
    }

    private func flush() {
        guard let plain = try? JSONEncoder().encode(blob),
            let sealed = try? AES.GCM.seal(plain, using: key).combined
        else { return }
        try? sealed.write(to: url, options: .atomic)
    }

    // MARK: Our own key

    /// Our current `K_r`, generating and persisting one on first use. The verifier for this is what
    /// gets registered with the relay.
    public func mineOrCreate() -> DeliveryAccessKey {
        lock.lock()
        defer { lock.unlock() }
        if let hex = blob.mineHex, let material = Hex.decode(hex),
            let existing = DeliveryAccessKey(keyMaterial: material)
        {
            return existing
        }
        let fresh = DeliveryAccessKey.generate()
        blob.mineHex = Hex.encode(fresh.key)
        blob.grantedTo.removeAll()
        flush()
        return fresh
    }

    /// Replace our `K_r` (a rotation, e.g. on block). Every previous grant is invalidated, so the
    /// "already granted" set is cleared and every remaining contact must be re-granted.
    public func rotateMine(to fresh: DeliveryAccessKey) {
        lock.lock()
        defer { lock.unlock() }
        blob.mineHex = Hex.encode(fresh.key)
        blob.grantedTo.removeAll()
        flush()
    }

    /// Contacts we have handed the CURRENT key to.
    public func hasGranted(to accountID: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return blob.grantedTo.contains(accountID)
    }

    public func markGranted(to accountID: String) {
        lock.lock()
        defer { lock.unlock() }
        blob.grantedTo.insert(accountID)
        flush()
    }

    // MARK: Grants received from contacts

    /// The grant `accountID` gave us, if any — the key AND devices needed to send them sealed.
    public func grant(from accountID: String) -> DeliveryGrant? {
        lock.lock()
        defer { lock.unlock() }
        return blob.grants[accountID]
    }

    public func storeGrant(_ grant: DeliveryGrant, from accountID: String) {
        lock.lock()
        defer { lock.unlock() }
        blob.grants[accountID] = grant
        flush()
    }

    /// Forget a contact's grant — used when blocking, so we stop sealing to them.
    public func forgetGrant(from accountID: String) {
        lock.lock()
        defer { lock.unlock() }
        blob.grants.removeValue(forKey: accountID)
        flush()
    }

    /// Accounts whose grant we hold (i.e. everyone we could currently send sealed).
    public func grantedKeys() -> Set<String> {
        lock.lock()
        defer { lock.unlock() }
        return Set(blob.grants.keys)
    }

    /// Erase everything, including the backing file — sealed-sender material must not outlive the
    /// account, exactly like private aliases.
    public func eraseAll() {
        lock.lock()
        defer { lock.unlock() }
        blob = Blob()
        try? FileManager.default.removeItem(at: url)
    }
}
