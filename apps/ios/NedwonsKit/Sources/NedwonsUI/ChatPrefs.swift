import Foundation
import NedwonsKit

/// Per-chat, per-account LOCAL preferences: pinned, archived, muted. Presentation state on this
/// device — nothing here is sent to the relay (which therefore cannot know what you pinned), and
/// nothing here affects what is delivered, only how it is shown.
public protocol ChatPrefsStoring {
    func load(account: String) -> ChatPrefs
    func save(_ prefs: ChatPrefs, account: String)
}

public struct ChatPrefs: Codable, Equatable, Sendable {
    public var pinned: Set<String> = []
    public var archived: Set<String> = []
    public var muted: Set<String> = []

    public init() {}
}

public struct UserDefaultsChatPrefsStore: ChatPrefsStoring {
    let defaults: UserDefaults
    public init(defaults: UserDefaults = .standard) { self.defaults = defaults }
    private func key(_ account: String) -> String { "nedwons.chat-prefs.\(account)" }
    public func load(account: String) -> ChatPrefs {
        guard let data = defaults.data(forKey: key(account)),
            let prefs = try? JSONDecoder().decode(ChatPrefs.self, from: data)
        else { return ChatPrefs() }
        return prefs
    }
    public func save(_ prefs: ChatPrefs, account: String) {
        if let data = try? JSONEncoder().encode(prefs) {
            defaults.set(data, forKey: key(account))
        }
    }
}

public final class MemoryChatPrefsStore: ChatPrefsStoring, @unchecked Sendable {
    public private(set) var byAccount: [String: ChatPrefs] = [:]
    public init() {}
    public func load(account: String) -> ChatPrefs { byAccount[account] ?? ChatPrefs() }
    public func save(_ prefs: ChatPrefs, account: String) { byAccount[account] = prefs }
}

/// Chats-list ordering with pins: pinned chats first (each group recency-sorted). Archived
/// chats are excluded here — they live behind the Archived row.
public func sortedForChatList(_ chats: [ChatSummary], prefs: ChatPrefs) -> [ChatSummary] {
    let visible = chats.filter { !prefs.archived.contains($0.conversationID) }
    let pinned = visible.filter { prefs.pinned.contains($0.conversationID) }
    let rest = visible.filter { !prefs.pinned.contains($0.conversationID) }
    return sortedByRecency(pinned) + sortedByRecency(rest)
}
