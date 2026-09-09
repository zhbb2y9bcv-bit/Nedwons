import XCTest

@testable import NedwonsKit
@testable import NedwonsUI

/// `AppModel`'s group-administration surface against the same in-process fixture the on-simulator
/// XCUITests use (`UITestHarness.swift`), so the two suites share one definition of what the relay
/// does. Every action here goes through the real `NedwonsClient` and reloads the panel from the
/// fixture — nothing asserts on locally patched state.
@MainActor
final class GroupAdminModelTests: XCTestCase {
    private let conv = GroupAdminFixture.conversationID
    private let bob = GroupAdminFixture.bob.accountID
    private let carol = GroupAdminFixture.carol.accountID

    /// Boot through the REAL launch path: stored session → whoami → initial load → authenticated.
    private func booted(_ scenario: UITestScenario = .admin) async -> (AppModel, GroupAdminFixture) {
        let (model, fixture) = AppModel.uiTestHarness(scenario: scenario)
        await model.restoreSession()
        XCTAssertEqual(model.phase, .authenticated, "harness boots through the real launch path")
        XCTAssertEqual(model.conversations.map(\.conversationID), [conv])
        return (model, fixture)
    }

    func testPanelLoadsRolesAndUsernames() async {
        let (model, _) = await booted()
        await model.refreshGroupState(conv)
        let state = try! XCTUnwrap(model.groupState(for: conv))
        XCTAssertTrue(state.isAdmin)
        XCTAssertTrue(state.canSend)
        XCTAssertEqual(state.members.count, 4)
        XCTAssertEqual(Set(state.admins.map(\.accountID)), [GroupAdminFixture.me.accountID, bob])
        XCTAssertEqual(model.username(forAccountID: carol), "carol", "member usernames are remembered for the rest of the UI")
        XCTAssertNil(model.composerLock(for: conv))
    }

    func testMuteThenUnmuteRoundTripsThroughTheServer() async {
        let (model, fixture) = await booted()
        let r1 = await model.muteGroupMember(carol, in: conv, for: .oneHour)
        XCTAssertTrue(r1)
        var carolView = model.groupState(for: conv)?.member(carol)
        XCTAssertEqual(carolView?.muted, true)
        XCTAssertNotNil(carolView?.muteExpiresAt, "a timed mute reports its end")
        XCTAssertEqual(carolView?.mutedBy, GroupAdminFixture.me.accountID)
        XCTAssertEqual(model.banner, "Muted for 1 hour.")

        let r2 = await model.muteGroupMember(carol, in: conv, for: .untilUnmuted)
        XCTAssertTrue(r2)
        carolView = model.groupState(for: conv)?.member(carol)
        XCTAssertEqual(carolView?.muted, true)
        XCTAssertNil(carolView?.muteExpiresAt, "re-muting replaced the expiry with indefinite")

        let r3 = await model.unmuteGroupMember(carol, in: conv)
        XCTAssertTrue(r3)
        XCTAssertEqual(model.groupState(for: conv)?.member(carol)?.muted, false)
        XCTAssertTrue(fixture.requestLog.contains("POST /v1/conversations/\(conv)/mutes/remove"))
    }

    func testAnnouncementModeAndUnmuteAll() async {
        let (model, _) = await booted()
        let r4 = await model.setAnnouncementsOnly(true, in: conv)
        XCTAssertTrue(r4)
        XCTAssertEqual(model.groupState(for: conv)?.announcementsOnly, true)
        XCTAssertNil(model.composerLock(for: conv), "admins keep sending in announcement mode")

        _ = await model.muteGroupMember(carol, in: conv, for: .oneDay)
        _ = await model.muteGroupMember(GroupAdminFixture.dave.accountID, in: conv, for: .oneDay)
        XCTAssertEqual(model.groupState(for: conv)?.mutedMembers.count, 2)
        let r5 = await model.unmuteAllGroupMembers(in: conv)
        XCTAssertTrue(r5)
        XCTAssertEqual(model.groupState(for: conv)?.mutedMembers.count, 0)

        let r6 = await model.setAnnouncementsOnly(false, in: conv)
        XCTAssertTrue(r6)
        XCTAssertEqual(model.groupState(for: conv)?.announcementsOnly, false)
    }

    /// The refusals the server can answer with become specific, actionable banners.
    func testRefusalsBecomeSpecificBanners() async {
        let (model, _) = await booted()

        // Muting an admin: demote first.
        let r7 = await model.muteGroupMember(bob, in: conv, for: .oneHour)
        XCTAssertFalse(r7)
        XCTAssertEqual(model.banner, GroupRefusal.targetIsAdmin.userFacingText)
        XCTAssertEqual(model.groupState(for: conv)?.member(bob)?.muted, false)

        // Demoting the last admin.
        let r8 = await model.demoteGroupAdmin(bob, in: conv)
        XCTAssertTrue(r8)
        let r9 = await model.demoteGroupAdmin(GroupAdminFixture.me.accountID, in: conv)
        XCTAssertFalse(r9)
        XCTAssertEqual(model.banner, GroupRefusal.lastAdmin.userFacingText)
        XCTAssertEqual(model.groupState(for: conv)?.admins.count, 1)

        // Promotion lifts a mute, then the admin can no longer be muted.
        _ = await model.muteGroupMember(bob, in: conv, for: .untilUnmuted)
        XCTAssertEqual(model.groupState(for: conv)?.member(bob)?.muted, true)
        let r10 = await model.promoteGroupAdmin(bob, in: conv)
        XCTAssertTrue(r10)
        let bobView = model.groupState(for: conv)?.member(bob)
        XCTAssertEqual(bobView?.isAdmin, true)
        XCTAssertEqual(bobView?.muted, false, "promotion lifted the mute")
    }

    func testAddAndRemoveMembers() async {
        let (model, _) = await booted()
        let erin = GroupAdminFixture.erin.accountID
        let r11 = await model.addGroupMembers([erin], to: conv)
        XCTAssertTrue(r11)
        XCTAssertNotNil(model.groupState(for: conv)?.member(erin))
        XCTAssertEqual(model.conversations.first?.memberAccountIDs.count, 5, "the Chats list reflects the add")

        let r12 = await model.removeGroupMember(erin, from: conv)
        XCTAssertTrue(r12)
        XCTAssertNil(model.groupState(for: conv)?.member(erin))
        XCTAssertEqual(model.conversations.first?.memberAccountIDs.count, 4)
        XCTAssertEqual(model.banner, "Removed from the group.")

        // Adding a stranger is refused by the server (direct adds need friendship).
        let r13 = await model.addGroupMembers(["ff" + String(repeating: "0", count: 30)], to: conv)
        XCTAssertFalse(r13)
        XCTAssertEqual(model.banner, GroupRefusal.notFriends.userFacingText)
    }

    /// An ordinary member sees the panel without admin lists and gets the admin-only wording when
    /// they try anything the server reserves for admins.
    func testOrdinaryMemberIsRefusedWithAdminWording() async {
        let (model, _) = await booted(.member)
        await model.refreshGroupState(conv)
        let state = try! XCTUnwrap(model.groupState(for: conv))
        XCTAssertFalse(state.isAdmin)
        XCTAssertTrue(state.canSend)
        XCTAssertTrue(state.invites.isEmpty)

        let r14 = await model.muteGroupMember(carol, in: conv, for: .oneHour)
        XCTAssertFalse(r14)
        XCTAssertEqual(model.banner, GroupRefusal.forbidden.userFacingText)
        let r15 = await model.setAnnouncementsOnly(true, in: conv)
        XCTAssertFalse(r15)
        XCTAssertEqual(model.banner, GroupRefusal.forbidden.userFacingText)
    }

    /// The composer lock is derived from `can_send` plus WHY, so the wording matches the cause.
    func testComposerLocksForMutedAndAnnouncementModeMembers() async {
        let (muted, _) = await booted(.muted)
        await muted.refreshGroupState(conv)
        XCTAssertEqual(muted.composerLock(for: conv), .muted(until: nil))

        let (locked, _) = await booted(.announcementsOnly)
        await locked.refreshGroupState(conv)
        XCTAssertEqual(locked.composerLock(for: conv), .announcementsOnly)
    }

    /// The race the lock cannot prevent: muted while typing. The refused send becomes the mute
    /// banner (not "will retry"), and the panel reloads so the composer locks now.
    func testSendRefusedByMuteLocksTheComposer() async {
        let (model, fixture) = AppModel.uiTestHarness(scenario: .muted)
        await model.restoreSession()
        // No panel loaded yet ⇒ the composer is unlocked on a stale view; the send hits the gate.
        XCTAssertNil(model.composerLock(for: conv))
        await model.sendMessage("hello?", to: conv)
        XCTAssertEqual(model.banner, GroupRefusal.muted.userFacingText)
        XCTAssertEqual(
            model.composerLock(for: conv), .muted(until: nil),
            "the refusal reloaded the panel and locked the composer")
        XCTAssertTrue(fixture.deliveredMessages.isEmpty, "nothing was delivered")
    }

    /// Titles: the E2EE group name wins; without one a group is described by its size and a 1:1
    /// thread by the other person (alias first, real username otherwise).
    func testConversationTitlePrefersTheGroupName() async {
        let (model, _) = await booted()
        let group = ChatSummary(conversationID: conv, memberCount: 4)
        XCTAssertEqual(model.conversationTitle(for: group), "Group · 4 people")
        let renamed = await model.renameGroup(conv, to: "  Weekend Trip ")
        XCTAssertTrue(renamed)
        XCTAssertEqual(model.conversationTitle(for: group), "Weekend Trip", "trimmed")
        XCTAssertEqual(model.banner, "Group renamed.")
        let empty = await model.renameGroup(conv, to: "   ")
        XCTAssertFalse(empty, "a blank name is not a rename")
        XCTAssertEqual(model.groupName(for: conv), "Weekend Trip")

        let direct = ChatSummary(
            conversationID: "d", peerAccountID: GroupAdminFixture.bob.accountID, peerUsername: "bob",
            memberCount: 2)
        XCTAssertEqual(model.conversationTitle(for: direct), "bob")
    }

    /// Unread counts come from local thread state and clear when the conversation is opened.
    func testUnreadCountClearsOnRead() async {
        let (model, _) = await booted()
        XCTAssertEqual(model.unreadCount(for: conv), 3, "the harness seeds a backlog")
        await model.markConversationRead(conv)
        XCTAssertEqual(model.unreadCount(for: conv), 0)
        XCTAssertEqual(model.localPreview(for: conv), "see you at 6", "reading keeps the preview")
    }

    func testAcceptedSendBecomesALocalLine() async {
        let (model, fixture) = await booted()
        await model.sendMessage("first", to: conv)
        XCTAssertEqual(fixture.deliveredMessages, ["first"])
        XCTAssertEqual(model.threadLines[conv]?.count, 1)
        XCTAssertNil(model.banner)
    }
}
