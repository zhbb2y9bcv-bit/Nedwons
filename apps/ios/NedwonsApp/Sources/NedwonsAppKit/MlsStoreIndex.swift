import Foundation

/// Which encrypted MLS store backs which conversation, plus the **lobby**: joiner identities whose
/// published prekeys are still outstanding.
///
/// Why a lobby exists: a prekey is redeemable only by the store that generated its private key, and
/// a store becomes exactly one conversation the moment it joins. So each outstanding prekey has its
/// own store, and a Welcome for a conversation we do not know yet is tried against each lobby
/// store until one fits. The stores themselves persist the key material (the core's
/// `PendingIdentity`), so a Welcome that arrives after a relaunch still joins.
///
/// Plain JSON on purpose: it holds only ids the relay already knows (conversation ids) and random
/// store ids — never key material, which lives inside the encrypted stores.
struct MlsStoreIndex: Codable, Equatable {
    /// conversation id → store id
    var conversations: [String: String] = [:]
    /// store ids awaiting a Welcome, oldest first
    var lobbies: [String] = []

    static let fileName = "index.json"

    static func load(from url: URL) -> MlsStoreIndex {
        guard let data = try? Data(contentsOf: url),
            let index = try? JSONDecoder().decode(MlsStoreIndex.self, from: data)
        else { return MlsStoreIndex() }
        return index
    }

    /// Atomic replace, so a crash mid-write leaves the previous index rather than a torn one.
    func save(to url: URL) throws {
        let data = try JSONEncoder().encode(self)
        try data.write(to: url, options: .atomic)
    }
}
