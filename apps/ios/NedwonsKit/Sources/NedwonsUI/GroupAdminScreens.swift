import NedwonsKit
import SwiftUI

// The group panel (ADR-0009): who is in the group, who administers it, who is muted, and — for
// admins — the controls: add and remove people, grant and revoke admin, mute/unmute one person or
// everyone, announcement mode, approval-gated joins, invite links.
//
// Every control here is functionally wired to `AppModel` → `NedwonsClient` → the relay. The relay
// is what enforces a mute; this screen is how an admin expresses one, and how a muted member
// learns why their composer is locked. Nothing here is decorative.
//
// Accessibility identifiers (`A11y.*`) are stable API for the XCUITest suite in
// `apps/ios/Nedwons/UITests`; rename them there too.

/// Identifiers the UI tests drive. Kept in one place so a rename cannot silently strand a test.
public enum GroupAdminA11y {
    public static let panel = "group.panel"
    /// The header badge shown while announcement mode is on — distinct from the toggle's own label,
    /// so a test asserting the mode flipped cannot be satisfied by the switch's caption.
    public static let headerAnnouncementsOnly = "group.header.announcementsOnly"
    public static let toggleAnnouncementsOnly = "group.toggle.announcementsOnly"
    public static let rename = "group.rename"
    public static let renameField = "group.rename.field"
    public static let renameSave = "group.rename.save"
    public static let title = "group.title"
    public static let toggleJoinApproval = "group.toggle.joinApproval"
    public static let addMembers = "group.addMembers"
    public static let addMembersConfirm = "group.addMembers.confirm"
    public static let unmuteAll = "group.unmuteAll"
    public static let createInvite = "group.createInvite"
    public static let leave = "group.leave"
    public static let leaveConfirm = "group.leave.confirm"
    public static let memberPromote = "group.member.promote"
    public static let memberDemote = "group.member.demote"
    public static let memberMute = "group.member.mute"
    public static let memberUnmute = "group.member.unmute"
    public static let memberRemove = "group.member.remove"
    public static let memberRemoveConfirm = "group.member.remove.confirm"
    public static let memberMuteDuration = "group.member.muteDuration"
    public static let memberStatus = "group.member.status"
    public static func memberRow(_ accountID: String) -> String { "group.member.\(accountID)" }
    public static func addMemberRow(_ accountID: String) -> String { "group.addMembers.row.\(accountID)" }
    public static func inviteRevoke(_ token: String) -> String { "group.invite.revoke.\(token.prefix(8))" }
    public static func requestApprove(_ accountID: String) -> String { "group.request.approve.\(accountID)" }
    public static func requestDeny(_ accountID: String) -> String { "group.request.deny.\(accountID)" }
    public static let conversationGroupInfo = "conversation.groupInfo"
    /// The conversation header, whose accessibility label names the thread.
    public static let conversationTitle = "conversation.title"
    public static let composerLocked = "conversation.composer.locked"
    public static let composerField = "conversation.composer.field"
    public static let composerAttach = "conversation.composer.attach"
}

struct GroupAdminView: View {
    @ObservedObject var model: AppModel
    let chat: ChatSummary

    @Environment(\.colorScheme) private var scheme
    @Environment(\.dismiss) private var dismiss
    @State private var showAddMembers = false
    @State private var showRename = false
    @State private var draftName = ""
    @State private var confirmLeave = false
    @State private var newInviteToken: String?
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    private var state: GroupState? { model.groupState(for: chat.conversationID) }
    private var isAdmin: Bool { state?.isAdmin ?? false }
    /// ADR-0010 groups change membership only through signed commits; the legacy controls would
    /// be refused, so they are not offered.
    private var membershipEditable: Bool { isAdmin && !(state?.mlsAuthoritative ?? false) }

    var body: some View {
        List {
            headerSection
            if let state {
                if isAdmin { settingsSection(state) } else { readOnlySettings(state) }
                membersSection(state)
                if isAdmin { moderationSection(state) }
                if isAdmin && !state.joinRequests.isEmpty { requestsSection(state) }
                if membershipEditable { invitesSection(state) }
                leaveSection
            } else if model.isBusy {
                Section { ProgressView("Loading group…") }
            } else {
                Section {
                    Text("Couldn't load this group.")
                        .foregroundStyle(palette.textSecondary)
                    Button("Try again") {
                        Task { await model.refreshGroupState(chat.conversationID) }
                    }
                }
            }
        }
        .accessibilityIdentifier(GroupAdminA11y.panel)
        .navigationTitle(chat.isGroup ? "Group" : "Details")
        .inlineNavigationTitle()
        .task { await model.refreshGroupState(chat.conversationID) }
        .refreshable { await model.refreshGroupState(chat.conversationID) }
        .sheet(isPresented: $showAddMembers) {
            AddGroupMembersView(model: model, conversationID: chat.conversationID)
        }
        .sheet(isPresented: $showRename) { renameSheet }
        .confirmationDialog(
            "Leave this group?", isPresented: $confirmLeave, titleVisibility: .visible
        ) {
            Button("Leave group", role: .destructive) {
                Task {
                    await model.leaveGroup(chat.conversationID)
                    dismiss()
                }
            }
            .accessibilityIdentifier(GroupAdminA11y.leaveConfirm)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "You stop receiving messages here immediately. If you are the only admin, the "
                    + "earliest remaining member becomes admin so the group is never left unmanaged.")
        }
        .alert(
            "Invite link", isPresented: Binding(
                get: { newInviteToken != nil }, set: { if !$0 { newInviteToken = nil } })
        ) {
            Button("Copy") {
                #if canImport(UIKit)
                    UIPasteboard.general.string = newInviteToken
                #endif
                newInviteToken = nil
            }
            Button("Done", role: .cancel) { newInviteToken = nil }
        } message: {
            Text(
                "Anyone with this token can join"
                    + ((state?.joinApproval ?? false) ? " after an admin approves them" : "")
                    + ". It expires in 7 days.\n\n\(newInviteToken ?? "")")
        }
    }

    private var renameSheet: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Group name", text: $draftName)
                        .accessibilityIdentifier(GroupAdminA11y.renameField)
                } footer: {
                    Text(
                        "The name is encrypted for the group like any message — the Nedwons server "
                            + "never learns what this group is called. Everyone here sees the change."
                            + "\n\nRenaming is offered to admins, but the server cannot enforce that "
                            + "on a message it cannot read: treat the name as something any member "
                            + "could change.")
                }
            }
            .navigationTitle("Group name")
            .inlineNavigationTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { showRename = false }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        Task {
                            if await model.renameGroup(chat.conversationID, to: draftName) {
                                showRename = false
                            }
                        }
                    }
                    .accessibilityIdentifier(GroupAdminA11y.renameSave)
                    .disabled(
                        draftName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                            || model.isBusy)
                }
            }
        }
    }

    // MARK: Sections

    private var headerSection: some View {
        Section {
            VStack(spacing: Nedwons.Spacing.sm) {
                Avatar(label: model.groupName(for: chat.conversationID) ?? "G", palette: palette, isGroup: true)
                    .scaleEffect(1.4)
                    .frame(height: 72)
                Text(model.conversationTitle(for: chat))
                    .font(Nedwons.TypeScale.headline)
                    .foregroundStyle(palette.textPrimary)
                    .multilineTextAlignment(.center)
                    .accessibilityIdentifier(GroupAdminA11y.title)
                Text("\(state?.members.count ?? chat.memberCount) people")
                    .font(Nedwons.TypeScale.caption)
                    .foregroundStyle(palette.textSecondary)
                if isAdmin {
                    Button {
                        draftName = model.groupName(for: chat.conversationID) ?? ""
                        showRename = true
                    } label: {
                        Label(
                            model.groupName(for: chat.conversationID) == nil ? "Name this group" : "Change name",
                            systemImage: "pencil")
                    }
                    .font(Nedwons.TypeScale.caption)
                    .accessibilityIdentifier(GroupAdminA11y.rename)
                }
                if let state, state.announcementsOnly {
                    Label("Announcement mode — only admins can send", systemImage: "megaphone.fill")
                        .font(Nedwons.TypeScale.caption)
                        .foregroundStyle(.orange)
                        .accessibilityIdentifier(GroupAdminA11y.headerAnnouncementsOnly)
                }
                if let lock = model.composerLock(for: chat.conversationID),
                    case .muted = lock
                {
                    Label(lock.text, systemImage: "speaker.slash.fill")
                        .font(Nedwons.TypeScale.caption)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                }
            }
            .frame(maxWidth: .infinity)
        }
    }

    private func settingsSection(_ state: GroupState) -> some View {
        Section {
            Toggle(
                isOn: Binding(
                    get: { state.announcementsOnly },
                    set: { on in Task { await model.setAnnouncementsOnly(on, in: chat.conversationID) } })
            ) {
                Label("Only admins can send", systemImage: "megaphone")
            }
            .accessibilityIdentifier(GroupAdminA11y.toggleAnnouncementsOnly)
            .disabled(model.isBusy)

            Toggle(
                isOn: Binding(
                    get: { state.joinApproval },
                    set: { on in Task { await model.setJoinApproval(on, in: chat.conversationID) } })
            ) {
                Label("Approve new members", systemImage: "person.badge.shield.checkmark")
            }
            .accessibilityIdentifier(GroupAdminA11y.toggleJoinApproval)
            .disabled(model.isBusy || state.mlsAuthoritative)
        } header: {
            Text("Group settings")
        } footer: {
            Text(
                "\"Only admins can send\" mutes everyone else at once and lifts the moment you turn it "
                    + "off. Mutes are enforced by the Nedwons server, which refuses to deliver a muted "
                    + "member's messages; it cannot read them.")
        }
    }

    private func readOnlySettings(_ state: GroupState) -> some View {
        Section("Group settings") {
            LabeledContent("Who can send", value: state.announcementsOnly ? "Admins only" : "Everyone")
            LabeledContent("New members", value: state.joinApproval ? "Need admin approval" : "Join by invite")
        }
    }

    private func membersSection(_ state: GroupState) -> some View {
        Section {
            ForEach(state.members) { member in
                NavigationLink {
                    GroupMemberDetailView(model: model, conversationID: chat.conversationID, member: member)
                } label: {
                    GroupMemberRow(model: model, member: member, palette: palette)
                }
                .accessibilityIdentifier(GroupAdminA11y.memberRow(member.accountID))
            }
            if membershipEditable {
                Button {
                    showAddMembers = true
                } label: {
                    Label("Add members", systemImage: "person.badge.plus")
                }
                .accessibilityIdentifier(GroupAdminA11y.addMembers)
            }
        } header: {
            Text("Members · \(state.members.count)")
        } footer: {
            if state.mlsAuthoritative {
                Text("This group's membership changes only through signed updates from its members' devices.")
            } else if isAdmin {
                Text("You can add people you're friends with. Others join with an invite link — their own choice.")
            }
        }
    }

    private func moderationSection(_ state: GroupState) -> some View {
        Section {
            if state.mutedMembers.isEmpty {
                Text("Nobody is muted.")
                    .foregroundStyle(palette.textSecondary)
            } else {
                Text("\(state.mutedMembers.count) muted")
                    .foregroundStyle(palette.textSecondary)
                Button {
                    Task { await model.unmuteAllGroupMembers(in: chat.conversationID) }
                } label: {
                    Label("Unmute everyone", systemImage: "speaker.wave.2")
                }
                .accessibilityIdentifier(GroupAdminA11y.unmuteAll)
                .disabled(model.isBusy)
            }
        } header: {
            Text("Mutes")
        } footer: {
            Text("Tap a member to mute or unmute them. Admins can't be muted — remove their admin role first.")
        }
    }

    private func requestsSection(_ state: GroupState) -> some View {
        Section("Join requests · \(state.joinRequests.count)") {
            ForEach(state.joinRequests, id: \.self) { accountID in
                HStack {
                    Text(model.displayName(for: accountID, username: model.username(forAccountID: accountID) ?? shortID(accountID)))
                        .lineLimit(1)
                    Spacer()
                    Button("Approve") {
                        Task { await model.approveJoinRequest(accountID, in: chat.conversationID) }
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier(GroupAdminA11y.requestApprove(accountID))
                    Button("Decline", role: .destructive) {
                        Task { await model.denyJoinRequest(accountID, in: chat.conversationID) }
                    }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier(GroupAdminA11y.requestDeny(accountID))
                }
                .disabled(model.isBusy)
            }
        }
    }

    private func invitesSection(_ state: GroupState) -> some View {
        Section {
            Button {
                Task { newInviteToken = await model.createGroupInvite(in: chat.conversationID) }
            } label: {
                Label("Create invite link", systemImage: "link.badge.plus")
            }
            .accessibilityIdentifier(GroupAdminA11y.createInvite)
            .disabled(model.isBusy)
            ForEach(state.invites) { invite in
                HStack {
                    VStack(alignment: .leading, spacing: Nedwons.Spacing.xxs) {
                        Text(String(invite.inviteToken.prefix(8)) + "…")
                            .font(.system(.callout, design: .monospaced))
                        Text("\(invite.uses)/\(invite.maxUses) uses · expires \(Date(timeIntervalSince1970: TimeInterval(invite.expiresAt)).formatted(date: .abbreviated, time: .omitted))")
                            .font(Nedwons.TypeScale.caption)
                            .foregroundStyle(palette.textSecondary)
                    }
                    Spacer()
                    Button("Revoke", role: .destructive) {
                        Task { await model.revokeGroupInvite(invite.inviteToken, in: chat.conversationID) }
                    }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier(GroupAdminA11y.inviteRevoke(invite.inviteToken))
                }
            }
        } header: {
            Text("Invite links")
        } footer: {
            Text("An invite is the joiner's own consent: nobody is force-added by a link. Links expire, are use-limited, and can be revoked here.")
        }
    }

    private var leaveSection: some View {
        Section {
            Button("Leave group", role: .destructive) { confirmLeave = true }
                .accessibilityIdentifier(GroupAdminA11y.leave)
        }
    }

    private func shortID(_ id: String) -> String {
        id.count > 8 ? String(id.prefix(8)) + "…" : id
    }
}

/// One member line: name, then the badges that make moderation legible — admin, muted, you.
struct GroupMemberRow: View {
    @ObservedObject var model: AppModel
    let member: GroupMember
    let palette: Nedwons.Palette

    var body: some View {
        HStack(spacing: Nedwons.Spacing.md) {
            Avatar(label: member.username.isEmpty ? "?" : member.username, palette: palette)
            VStack(alignment: .leading, spacing: Nedwons.Spacing.xxs) {
                HStack(spacing: Nedwons.Spacing.xs) {
                    Text(title)
                        .font(Nedwons.TypeScale.body)
                        .foregroundStyle(palette.textPrimary)
                        .lineLimit(1)
                    if isMe {
                        Text("You")
                            .font(Nedwons.TypeScale.caption)
                            .foregroundStyle(palette.textSecondary)
                    }
                }
                if !member.username.isEmpty && title != "@\(member.username)" {
                    Text("@\(member.username)")
                        .font(Nedwons.TypeScale.caption)
                        .foregroundStyle(palette.textSecondary)
                        .lineLimit(1)
                }
            }
            Spacer()
            if member.muted {
                Image(systemName: "speaker.slash.fill")
                    .foregroundStyle(.red)
                    .accessibilityLabel("Muted")
            }
            if member.isAdmin {
                Text("Admin")
                    .font(Nedwons.TypeScale.caption)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(palette.accentPrimary.opacity(0.15), in: Capsule())
                    .foregroundStyle(palette.accentPrimary)
            }
        }
        .padding(.vertical, Nedwons.Spacing.xxs)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibilityText)
    }

    private var isMe: Bool { member.accountID == model.session?.accountID }

    /// Alias > display name > @username — the registered handle stays visible underneath when an
    /// alias or display name is shown, so no one can be disguised as someone else.
    private var title: String {
        if let alias = model.alias(for: member.accountID) { return alias }
        if !member.displayName.isEmpty { return member.displayName }
        return member.username.isEmpty ? "Unknown" : "@\(member.username)"
    }

    private var accessibilityText: String {
        var parts = [title]
        if isMe { parts.append("you") }
        if member.isAdmin { parts.append("admin") }
        if member.muted { parts.append("muted") }
        return parts.joined(separator: ", ")
    }
}

/// One member's page: identity, role controls, mute controls, removal. Admin-only controls are
/// hidden (not merely disabled) for ordinary members — offering a button the server will refuse
/// is a worse experience than not offering it.
struct GroupMemberDetailView: View {
    @ObservedObject var model: AppModel
    let conversationID: String
    let member: GroupMember

    @Environment(\.colorScheme) private var scheme
    @Environment(\.dismiss) private var dismiss
    @State private var duration: MuteDuration = .oneHour
    @State private var confirmRemove = false
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    /// Live member state: after an action the panel reloads and this page must reflect it.
    private var current: GroupMember {
        model.groupState(for: conversationID)?.member(member.accountID) ?? member
    }
    private var state: GroupState? { model.groupState(for: conversationID) }
    private var isAdmin: Bool { state?.isAdmin ?? false }
    private var isMe: Bool { member.accountID == model.session?.accountID }
    private var membershipEditable: Bool { isAdmin && !(state?.mlsAuthoritative ?? false) }

    var body: some View {
        List {
            Section {
                VStack(spacing: Nedwons.Spacing.sm) {
                    Avatar(label: current.username.isEmpty ? "?" : current.username, palette: palette)
                        .scaleEffect(1.6)
                        .frame(height: 80)
                    Text(current.displayName.isEmpty ? "@\(current.username)" : current.displayName)
                        .font(Nedwons.TypeScale.headline)
                        .foregroundStyle(palette.textPrimary)
                    if !current.displayName.isEmpty {
                        Text("@\(current.username)")
                            .font(Nedwons.TypeScale.caption)
                            .foregroundStyle(palette.textSecondary)
                    }
                    Text(statusText)
                        .font(Nedwons.TypeScale.caption)
                        .foregroundStyle(current.muted ? .red : palette.textSecondary)
                        .multilineTextAlignment(.center)
                        .accessibilityIdentifier(GroupAdminA11y.memberStatus)
                }
                .frame(maxWidth: .infinity)
            }

            if isAdmin && !isMe {
                roleSection
                muteSection
                if membershipEditable { removeSection }
            } else if isMe {
                Section {
                    Text(isAdmin ? "You administer this group." : "You're a member of this group.")
                        .foregroundStyle(palette.textSecondary)
                }
            }
        }
        .navigationTitle("Member")
        .inlineNavigationTitle()
        .confirmationDialog(
            "Remove from group?", isPresented: $confirmRemove, titleVisibility: .visible
        ) {
            Button("Remove", role: .destructive) {
                Task {
                    if await model.removeGroupMember(member.accountID, from: conversationID) {
                        dismiss()
                    }
                }
            }
            .accessibilityIdentifier(GroupAdminA11y.memberRemoveConfirm)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("They stop receiving messages here immediately and can only return by invitation.")
        }
    }

    private var statusText: String {
        var parts: [String] = []
        if current.isAdmin { parts.append("Admin") }
        if current.muted {
            if let until = current.muteExpiresAt {
                parts.append("Muted until \(Date(timeIntervalSince1970: TimeInterval(until)).formatted(date: .abbreviated, time: .shortened))")
            } else {
                parts.append("Muted until an admin unmutes them")
            }
        }
        return parts.isEmpty ? "Member" : parts.joined(separator: " · ")
    }

    private var roleSection: some View {
        Section {
            if current.isAdmin {
                Button("Remove admin role", role: .destructive) {
                    Task { await model.demoteGroupAdmin(member.accountID, in: conversationID) }
                }
                .accessibilityIdentifier(GroupAdminA11y.memberDemote)
            } else {
                Button {
                    Task { await model.promoteGroupAdmin(member.accountID, in: conversationID) }
                } label: {
                    Label("Make admin", systemImage: "person.badge.key")
                }
                .accessibilityIdentifier(GroupAdminA11y.memberPromote)
            }
        } header: {
            Text("Role")
        } footer: {
            Text(
                current.isAdmin
                    ? "A group always keeps at least one admin."
                    : "Admins can add and remove people, mute members, and change group settings. Making someone an admin also unmutes them.")
        }
        .disabled(model.isBusy)
    }

    private var muteSection: some View {
        Section {
            if current.muted {
                Button {
                    Task { await model.unmuteGroupMember(member.accountID, in: conversationID) }
                } label: {
                    Label("Unmute", systemImage: "speaker.wave.2")
                }
                .accessibilityIdentifier(GroupAdminA11y.memberUnmute)
            } else if current.isAdmin {
                Text("Admins can't be muted. Remove their admin role first.")
                    .foregroundStyle(palette.textSecondary)
            } else {
                Picker("Duration", selection: $duration) {
                    ForEach(MuteDuration.allCases) { d in Text(d.label).tag(d) }
                }
                .accessibilityIdentifier(GroupAdminA11y.memberMuteDuration)
                Button {
                    Task { await model.muteGroupMember(member.accountID, in: conversationID, for: duration) }
                } label: {
                    Label("Mute", systemImage: "speaker.slash")
                }
                .accessibilityIdentifier(GroupAdminA11y.memberMute)
            }
        } header: {
            Text("Mute")
        } footer: {
            Text("A muted member still sees the conversation. The server refuses to deliver their messages until the mute ends.")
        }
        .disabled(model.isBusy)
    }

    private var removeSection: some View {
        Section {
            Button("Remove from group", role: .destructive) { confirmRemove = true }
                .accessibilityIdentifier(GroupAdminA11y.memberRemove)
        }
        .disabled(model.isBusy)
    }
}

/// Pick friends who are not yet in the group. Direct adds are consent-by-proxy, so the server
/// only allows friends; anyone else needs an invite link.
struct AddGroupMembersView: View {
    @ObservedObject var model: AppModel
    let conversationID: String

    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var scheme
    @State private var selected: Set<String> = []
    private var palette: Nedwons.Palette { .forScheme(scheme) }

    private var candidates: [ProfileSummary] {
        let members = Set(model.groupState(for: conversationID)?.members.map(\.accountID) ?? [])
        return model.friends.filter { !members.contains($0.accountID) }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if candidates.isEmpty {
                        Text("All your friends are already here. Others can join with an invite link.")
                            .font(Nedwons.TypeScale.callout)
                            .foregroundStyle(palette.textSecondary)
                    }
                    ForEach(candidates) { friend in
                        Button {
                            toggle(friend.accountID)
                        } label: {
                            HStack {
                                PersonRow(person: friend)
                                Spacer()
                                Image(systemName: selected.contains(friend.accountID) ? "checkmark.circle.fill" : "circle")
                                    .foregroundStyle(selected.contains(friend.accountID) ? palette.accentPrimary : palette.textSecondary)
                            }
                            // A plain-style button hit-tests only its drawn content; without this
                            // a tap in the empty middle of the row (where a thumb lands) is lost.
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityIdentifier(GroupAdminA11y.addMemberRow(friend.accountID))
                        .accessibilityAddTraits(selected.contains(friend.accountID) ? .isSelected : [])
                    }
                } header: {
                    Text("Friends")
                }
            }
            .navigationTitle("Add members")
            .inlineNavigationTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        Task {
                            if await model.addGroupMembers(Array(selected), to: conversationID) {
                                dismiss()
                            }
                        }
                    }
                    .accessibilityIdentifier(GroupAdminA11y.addMembersConfirm)
                    .disabled(selected.isEmpty || model.isBusy)
                }
            }
            .task { await model.refreshFriends() }
        }
    }

    private func toggle(_ id: String) {
        if selected.contains(id) { selected.remove(id) } else { selected.insert(id) }
    }
}
