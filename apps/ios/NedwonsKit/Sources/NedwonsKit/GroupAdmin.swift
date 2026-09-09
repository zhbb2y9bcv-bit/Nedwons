import Foundation

// Group administration (ADR-0009): roles, membership changes, invites, join requests, and
// moderation (per-member mutes + announcement mode).
//
// What moderation is, stated the way the server states it: a mute is a RELAY-enforced send
// permission. The relay is MLS-blind, so a muted member still holds the group's keys and could
// still encrypt for the group; what they lose is the server's willingness to distribute those
// bytes, which is the only distribution path the product offers. This file never claims more.

/// One member of a group as the admin panel renders it. Account-level: roles and mutes follow the
/// person, so an account with several linked devices appears once.
public struct GroupMember: Decodable, Sendable, Identifiable, Hashable {
    public let accountID: String
    public let username: String
    public let displayName: String
    public let isAdmin: Bool
    /// A mute is in force right now (the server filters lapsed timed mutes before answering).
    public let muted: Bool
    /// Unix seconds. Absent for an unmuted member AND for an indefinite mute — check `muted`
    /// first, then treat nil as "until an admin lifts it".
    public let muteExpiresAt: Int?
    public let mutedBy: String?

    public var id: String { accountID }

    enum CodingKeys: String, CodingKey {
        case accountID = "account_id", username, displayName = "display_name"
        case isAdmin = "is_admin", muted, muteExpiresAt = "mute_expires_at", mutedBy = "muted_by"
    }

    public init(
        accountID: String, username: String, displayName: String = "", isAdmin: Bool = false,
        muted: Bool = false, muteExpiresAt: Int? = nil, mutedBy: String? = nil
    ) {
        self.accountID = accountID
        self.username = username
        self.displayName = displayName
        self.isAdmin = isAdmin
        self.muted = muted
        self.muteExpiresAt = muteExpiresAt
        self.mutedBy = mutedBy
    }
}

/// An active invite link (admin view only).
public struct GroupInvite: Decodable, Sendable, Identifiable, Hashable {
    public let inviteToken: String
    public let expiresAt: Int
    public let maxUses: Int
    public let uses: Int

    public var id: String { inviteToken }

    enum CodingKeys: String, CodingKey {
        case inviteToken = "invite_token", expiresAt = "expires_at", maxUses = "max_uses", uses
    }

    public init(inviteToken: String, expiresAt: Int, maxUses: Int, uses: Int) {
        self.inviteToken = inviteToken
        self.expiresAt = expiresAt
        self.maxUses = maxUses
        self.uses = uses
    }
}

/// Everything the group panel renders, from one round trip (`GET /v1/conversations/{id}/group`).
public struct GroupState: Decodable, Sendable, Hashable {
    public let conversationID: String
    /// Whether the CALLER administers the group. The UI keys admin controls off this, never off
    /// the presence of admin-only data it happens to have been sent.
    public let isAdmin: Bool
    /// Whether the CALLER may send right now, computed server-side from the same rows the relay's
    /// send gate reads — so the composer and the server cannot disagree.
    public let canSend: Bool
    public let joinApproval: Bool
    /// "Mute all": only admins may send.
    public let announcementsOnly: Bool
    /// ADR-0010: membership changes only through signed MLS commits; the legacy add/remove/invite
    /// endpoints answer 409 `commits_required` on such groups.
    public let mlsAuthoritative: Bool
    public let members: [GroupMember]
    /// Admin-only; empty for ordinary members.
    public let joinRequests: [String]
    /// Admin-only; empty for ordinary members.
    public let invites: [GroupInvite]

    enum CodingKeys: String, CodingKey {
        case conversationID = "conversation_id", isAdmin = "is_admin", canSend = "can_send"
        case joinApproval = "join_approval", announcementsOnly = "announcements_only"
        case mlsAuthoritative = "mls_authoritative", members
        case joinRequests = "join_requests", invites
    }

    public init(
        conversationID: String, isAdmin: Bool, canSend: Bool, joinApproval: Bool = false,
        announcementsOnly: Bool = false, mlsAuthoritative: Bool = false, members: [GroupMember],
        joinRequests: [String] = [], invites: [GroupInvite] = []
    ) {
        self.conversationID = conversationID
        self.isAdmin = isAdmin
        self.canSend = canSend
        self.joinApproval = joinApproval
        self.announcementsOnly = announcementsOnly
        self.mlsAuthoritative = mlsAuthoritative
        self.members = members
        self.joinRequests = joinRequests
        self.invites = invites
    }

    public var admins: [GroupMember] { members.filter(\.isAdmin) }
    public var mutedMembers: [GroupMember] { members.filter(\.muted) }
    public func member(_ accountID: String) -> GroupMember? {
        members.first { $0.accountID == accountID }
    }
}

/// The stable refusal codes the group endpoints answer with, so the UI can say something true and
/// specific instead of "not allowed". Unknown codes fall through to `nil`; callers then show the
/// generic text for the HTTP status.
public enum GroupRefusal: String, Sendable, Equatable {
    /// You are individually muted in this group.
    case muted
    /// The group is in announcement mode and you are not an admin.
    case announcementsOnly = "announcements_only"
    /// Refused to demote the group's only admin.
    case lastAdmin = "last_admin"
    /// Refused to mute an admin: demote first.
    case targetIsAdmin = "target_is_admin"
    /// The target is not in this group.
    case notMember = "not_member"
    /// ADR-0010 group: membership changes only via signed MLS commits.
    case commitsRequired = "commits_required"
    /// Direct adds require friendship with the person being added (their consent by proxy).
    case notFriends = "not_friends"
    /// A block exists between the target and a current member.
    case blockedMember = "blocked_member"
    /// Generic: not a member, or not an admin. Deliberately says no more.
    case forbidden

    /// Parse the `{"error": "<code>"}` body every `ApiError` carries.
    public static func from(errorBody body: String) -> GroupRefusal? {
        guard
            let data = body.data(using: .utf8),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let code = object["error"] as? String
        else { return nil }
        return GroupRefusal(rawValue: code)
    }

    /// The two refusals a SEND can get back while still being a member in good standing. The
    /// composer treats these as "locked", not as a transient failure to retry.
    public var isSendRefusal: Bool { self == .muted || self == .announcementsOnly }

    /// Copy shown to the person the refusal applies to.
    public var userFacingText: String {
        switch self {
        case .muted: "An admin has muted you in this group."
        case .announcementsOnly: "Only admins can send messages in this group right now."
        case .lastAdmin: "A group needs at least one admin. Make someone else an admin first."
        case .targetIsAdmin: "Admins can't be muted. Remove their admin role first."
        case .notMember: "That person isn't in this group."
        case .commitsRequired: "This group's membership can only change through a signed update."
        case .notFriends: "You can only add people you're friends with. Send them an invite link instead."
        case .blockedMember: "Someone in this group has a block with that person."
        case .forbidden: "Only group admins can do that."
        }
    }
}

public extension NedwonsClient {
    /// The whole group panel in one call. Members-only (403 for anyone else).
    func groupState(accessToken: String, conversationID: String) async throws -> GroupState {
        try decode(
            await perform(
                authed("GET", "/v1/conversations/\(conversationID)/group", accessToken: accessToken)))
    }

    /// Add a friend directly (admin + friendship + no block; strangers join via invite links).
    func addGroupMember(accessToken: String, conversationID: String, accountID: String) async throws {
        try await postAccountRef(
            "/v1/conversations/\(conversationID)/members", accessToken: accessToken,
            accountID: accountID)
    }

    /// Remove ("kick") a member. Admin only; removing yourself is `leaveConversation`.
    func removeGroupMember(accessToken: String, conversationID: String, accountID: String)
        async throws
    {
        try await postAccountRef(
            "/v1/conversations/\(conversationID)/members/remove", accessToken: accessToken,
            accountID: accountID)
    }

    /// Grant admin. Idempotent. Also lifts any mute on the target (an admin is never muted).
    func promoteGroupAdmin(accessToken: String, conversationID: String, accountID: String)
        async throws
    {
        try await postAccountRef(
            "/v1/conversations/\(conversationID)/admins", accessToken: accessToken,
            accountID: accountID)
    }

    /// Revoke admin. The server refuses (409 `last_admin`) to demote the only admin.
    func demoteGroupAdmin(accessToken: String, conversationID: String, accountID: String)
        async throws
    {
        try await postAccountRef(
            "/v1/conversations/\(conversationID)/admins/demote", accessToken: accessToken,
            accountID: accountID)
    }

    /// Mute one member. `durationSecs` nil = until an admin unmutes; the server clamps timed mutes
    /// to [1 minute, 1 year]. Re-muting replaces the expiry.
    func muteGroupMember(
        accessToken: String, conversationID: String, accountID: String, durationSecs: Int? = nil
    ) async throws {
        struct Body: Encodable {
            let account_id: String
            let duration_secs: Int?
        }
        var request = authed(
            "POST", "/v1/conversations/\(conversationID)/mutes", accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(
            Body(account_id: accountID, duration_secs: durationSecs))
        _ = try await perform(request)
    }

    /// Lift a mute. Idempotent.
    func unmuteGroupMember(accessToken: String, conversationID: String, accountID: String)
        async throws
    {
        try await postAccountRef(
            "/v1/conversations/\(conversationID)/mutes/remove", accessToken: accessToken,
            accountID: accountID)
    }

    /// Lift every mute in the group. Idempotent.
    func unmuteAllGroupMembers(accessToken: String, conversationID: String) async throws {
        var request = authed(
            "POST", "/v1/conversations/\(conversationID)/mutes/clear", accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data("{}".utf8)
        _ = try await perform(request)
    }

    /// Change group settings. Pass only the switches you mean to change: an omitted field is left
    /// exactly as it is, so two admins editing different switches never revert each other.
    func updateGroupSettings(
        accessToken: String, conversationID: String, joinApproval: Bool? = nil,
        announcementsOnly: Bool? = nil
    ) async throws {
        struct Body: Encodable {
            let join_approval: Bool?
            let announcements_only: Bool?
        }
        var request = authed(
            "POST", "/v1/conversations/\(conversationID)/settings", accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(
            Body(join_approval: joinApproval, announcements_only: announcementsOnly))
        _ = try await perform(request)
    }

    /// Revoke an invite link. Idempotent.
    func revokeInvite(accessToken: String, conversationID: String, inviteToken: String) async throws {
        struct Body: Encodable { let invite_token: String }
        var request = authed(
            "POST", "/v1/conversations/\(conversationID)/invites/revoke", accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(Body(invite_token: inviteToken))
        _ = try await perform(request)
    }

    /// Approve a pending join request (approval-gated groups). Re-checks blocks server-side.
    func approveJoinRequest(accessToken: String, conversationID: String, accountID: String)
        async throws
    {
        try await postAccountRef(
            "/v1/conversations/\(conversationID)/requests/approve", accessToken: accessToken,
            accountID: accountID)
    }

    /// Deny a pending join request.
    func denyJoinRequest(accessToken: String, conversationID: String, accountID: String) async throws {
        try await postAccountRef(
            "/v1/conversations/\(conversationID)/requests/deny", accessToken: accessToken,
            accountID: accountID)
    }
}

extension NedwonsClient {
    /// The shared shape of every "do X to this account" admin call: `{ "account_id": … }` → 204.
    func postAccountRef(_ path: String, accessToken: String, accountID: String) async throws {
        struct Body: Encodable { let account_id: String }
        var request = authed("POST", path, accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(Body(account_id: accountID))
        _ = try await perform(request)
    }
}
