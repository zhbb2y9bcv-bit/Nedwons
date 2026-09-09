import Foundation
import NedwonsKit

/// How long a mute lasts. Presentation-level: the server takes seconds (or nothing, for
/// indefinite) and clamps timed mutes to [1 minute, 1 year].
public enum MuteDuration: String, CaseIterable, Identifiable, Sendable {
    case oneHour, eightHours, oneDay, oneWeek, untilUnmuted

    public var id: String { rawValue }

    /// `nil` = until an admin lifts it.
    public var seconds: Int? {
        switch self {
        case .oneHour: 3600
        case .eightHours: 8 * 3600
        case .oneDay: 24 * 3600
        case .oneWeek: 7 * 24 * 3600
        case .untilUnmuted: nil
        }
    }

    public var label: String {
        switch self {
        case .oneHour: "1 hour"
        case .eightHours: "8 hours"
        case .oneDay: "24 hours"
        case .oneWeek: "1 week"
        case .untilUnmuted: "Until unmuted"
        }
    }
}

/// Why the composer is locked for the current user in a conversation, if it is.
public enum ComposerLock: Equatable, Sendable {
    /// An admin muted this account.
    case muted(until: Date?)
    /// Announcement mode: only admins may send.
    case announcementsOnly

    public var text: String {
        switch self {
        case .muted(let until?):
            "An admin muted you until \(until.formatted(date: .abbreviated, time: .shortened))."
        case .muted(nil):
            "An admin muted you in this group."
        case .announcementsOnly:
            "Only admins can send messages in this group."
        }
    }
}

// Group administration (ADR-0009): the surface the group panel calls. Every action performs the
// request, then RELOADS the panel from the server rather than patching local state — so what the
// admin sees after an action is what the relay will enforce, never a client-side guess.
extension AppModel {
    /// The last loaded panel state, if any.
    public func groupState(for conversationID: String) -> GroupState? {
        groupStates[conversationID]
    }

    /// Whether this user administers the conversation, per the last loaded state.
    public func isGroupAdmin(_ conversationID: String) -> Bool {
        groupStates[conversationID]?.isAdmin ?? false
    }

    /// The composer lock for this user, derived from the last loaded state. Unknown state means
    /// unlocked: the server is the authority and refuses with a specific reason if it must, and a
    /// composer that locks itself on a stale guess would silence people the admin never muted.
    public func composerLock(for conversationID: String) -> ComposerLock? {
        guard let state = groupStates[conversationID], !state.canSend else { return nil }
        let me = session?.accountID ?? ""
        if let mine = state.member(me), mine.muted {
            return .muted(until: mine.muteExpiresAt.map { Date(timeIntervalSince1970: TimeInterval($0)) })
        }
        if state.announcementsOnly && !state.isAdmin {
            return .announcementsOnly
        }
        // `can_send == false` for a reason this client does not know how to name. Lock anyway —
        // the server said no — with the generic wording.
        return .announcementsOnly
    }

    /// Load (or reload) the panel. Quiet on failure: the panel renders its own empty/error state,
    /// and a transient failure must not erase a state the user is looking at.
    public func refreshGroupState(_ conversationID: String) async {
        guard let token else { return }
        do {
            let state = try await client.groupState(
                accessToken: token, conversationID: conversationID)
            groupStates[conversationID] = state
            for member in state.members {
                rememberUsername(member.username, forAccountID: member.accountID)
            }
        } catch let NedwonsClient.ClientError.http(status, body) {
            // Not a member any more (removed, or the group is gone): drop the stale panel so the
            // UI stops offering controls the server will refuse.
            if status == 403 || status == 404 {
                groupStates[conversationID] = nil
            }
            banner = errorText(for: status, body: body)
        } catch NedwonsClient.ClientError.transport {
            banner = "Can't reach the server. Check your connection."
        } catch {
            banner = "Couldn't load the group."
        }
    }

    // MARK: Membership

    /// Direct-add friends. The server requires admin + friendship with each person + no block.
    /// Returns true when every add succeeded.
    @discardableResult
    public func addGroupMembers(_ accountIDs: [String], to conversationID: String) async -> Bool {
        var allAdded = true
        for accountID in accountIDs {
            let ok = await groupAction(conversationID, success: nil) { [self] token in
                try await client.addGroupMember(
                    accessToken: token, conversationID: conversationID, accountID: accountID)
            }
            allAdded = allAdded && ok
        }
        guard allAdded else { return false }
        conversations = (try? await client.listConversations(accessToken: token ?? "")) ?? conversations
        // Routing alone would hand them ciphertext they hold no key for: they must also join the
        // MLS group, and (if it has one) learn the group's name.
        if let addMembersToConversationAction {
            do {
                try await addMembersToConversationAction(conversationID, accountIDs)
            } catch {
                // Deferred, not failed (V27): the add completes on a later sync — theirs or any
                // member's — the moment they publish a prekey.
                banner = "Added. Anyone who hasn't opened Nedwons yet joins automatically when they do."
                await refreshGroupState(conversationID)
                return true
            }
        }
        banner = accountIDs.count == 1 ? "Added to the group." : "Added \(accountIDs.count) people."
        return true
    }

    /// Finish an invite joiner's setup: they already hold routing membership (their own consent,
    /// via the link), so only the MLS add — the part that actually hands them keys — remains.
    /// Reuses the injected composition-layer add; reports honestly when it isn't available or the
    /// member is already set up (the duplicate add fails and the banner says so).
    @discardableResult
    public func completeMemberEncryption(_ accountID: String, in conversationID: String) async -> Bool {
        guard let addMembersToConversationAction else {
            banner = "Encryption setup isn't available in this build."
            return false
        }
        do {
            try await addMembersToConversationAction(conversationID, [accountID])
            banner = "Encryption setup finished — new messages reach them now."
            return true
        } catch {
            banner = "Nothing to finish — they're either already set up, or they'll be added "
                + "automatically when they next open Nedwons."
            return false
        }
    }

    /// Remove ("kick") a member. Their queued mail for the group is purged server-side.
    @discardableResult
    public func removeGroupMember(_ accountID: String, from conversationID: String) async -> Bool {
        await groupAction(conversationID, success: "Removed from the group.") { [self] token in
            try await client.removeGroupMember(
                accessToken: token, conversationID: conversationID, accountID: accountID)
            conversations = try await client.listConversations(accessToken: token)
        }
    }

    // MARK: Roles

    @discardableResult
    public func promoteGroupAdmin(_ accountID: String, in conversationID: String) async -> Bool {
        await groupAction(conversationID, success: "Made an admin.") { [self] token in
            try await client.promoteGroupAdmin(
                accessToken: token, conversationID: conversationID, accountID: accountID)
        }
    }

    @discardableResult
    public func demoteGroupAdmin(_ accountID: String, in conversationID: String) async -> Bool {
        await groupAction(conversationID, success: "Admin role removed.") { [self] token in
            try await client.demoteGroupAdmin(
                accessToken: token, conversationID: conversationID, accountID: accountID)
        }
    }

    // MARK: Moderation

    @discardableResult
    public func muteGroupMember(
        _ accountID: String, in conversationID: String, for duration: MuteDuration
    ) async -> Bool {
        let success =
            duration == .untilUnmuted ? "Muted until an admin unmutes them." : "Muted for \(duration.label)."
        return await groupAction(conversationID, success: success) { [self] token in
            try await client.muteGroupMember(
                accessToken: token, conversationID: conversationID, accountID: accountID,
                durationSecs: duration.seconds)
        }
    }

    @discardableResult
    public func unmuteGroupMember(_ accountID: String, in conversationID: String) async -> Bool {
        await groupAction(conversationID, success: "Unmuted.") { [self] token in
            try await client.unmuteGroupMember(
                accessToken: token, conversationID: conversationID, accountID: accountID)
        }
    }

    @discardableResult
    public func unmuteAllGroupMembers(in conversationID: String) async -> Bool {
        await groupAction(conversationID, success: "Everyone is unmuted.") { [self] token in
            try await client.unmuteAllGroupMembers(
                accessToken: token, conversationID: conversationID)
        }
    }

    /// "Mute all": only admins may send.
    @discardableResult
    public func setAnnouncementsOnly(_ on: Bool, in conversationID: String) async -> Bool {
        await groupAction(
            conversationID,
            success: on ? "Only admins can send now." : "Everyone can send again."
        ) { [self] token in
            try await client.updateGroupSettings(
                accessToken: token, conversationID: conversationID, announcementsOnly: on)
        }
    }

    @discardableResult
    public func setJoinApproval(_ on: Bool, in conversationID: String) async -> Bool {
        await groupAction(
            conversationID,
            success: on ? "New members now need admin approval." : "Invite links join directly."
        ) { [self] token in
            try await client.updateGroupSettings(
                accessToken: token, conversationID: conversationID, joinApproval: on)
        }
    }

    // MARK: Invites & join requests

    /// Mint an invite link token. Returns it (hex) for sharing, or nil on refusal.
    public func createGroupInvite(in conversationID: String) async -> String? {
        var created: String?
        _ = await groupAction(conversationID, success: "Invite link created.") { [self] token in
            created = try await client.createInvite(
                accessToken: token, conversationID: conversationID)
        }
        return created
    }

    @discardableResult
    public func revokeGroupInvite(_ inviteToken: String, in conversationID: String) async -> Bool {
        await groupAction(conversationID, success: "Invite link revoked.") { [self] token in
            try await client.revokeInvite(
                accessToken: token, conversationID: conversationID, inviteToken: inviteToken)
        }
    }

    @discardableResult
    public func approveJoinRequest(_ accountID: String, in conversationID: String) async -> Bool {
        await groupAction(conversationID, success: "Approved.") { [self] token in
            try await client.approveJoinRequest(
                accessToken: token, conversationID: conversationID, accountID: accountID)
            conversations = try await client.listConversations(accessToken: token)
        }
    }

    @discardableResult
    public func denyJoinRequest(_ accountID: String, in conversationID: String) async -> Bool {
        await groupAction(conversationID, success: "Declined.") { [self] token in
            try await client.denyJoinRequest(
                accessToken: token, conversationID: conversationID, accountID: accountID)
        }
    }

    // MARK: Runner

    /// Perform one admin request, then reload the panel from the server. Errors become banners
    /// with the SPECIFIC refusal wording where the server gave a code; the generic `forbidden` on
    /// these endpoints means "not an admin", and is worded that way here.
    private func groupAction(
        _ conversationID: String,
        success: String?,
        _ body: (String) async throws -> Void
    ) async -> Bool {
        guard let token else { return false }
        isBusy = true
        defer { isBusy = false }
        do {
            try await body(token)
            await refreshGroupState(conversationID)
            if let success { banner = success }
            return true
        } catch let NedwonsClient.ClientError.http(status, body) {
            if GroupRefusal.from(errorBody: body) == .forbidden {
                banner = GroupRefusal.forbidden.userFacingText
            } else {
                banner = errorText(for: status, body: body)
            }
            // The server's refusal may reflect a state change (someone else demoted you, the
            // member left); show the truth rather than the panel that led to the refusal.
            await refreshGroupState(conversationID)
            return false
        } catch NedwonsClient.ClientError.transport {
            banner = "Can't reach the server. Check your connection."
            return false
        } catch {
            banner = "Something went wrong."
            return false
        }
    }
}
