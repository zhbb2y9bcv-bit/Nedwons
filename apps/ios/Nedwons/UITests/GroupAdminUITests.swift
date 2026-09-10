import XCTest

/// On-simulator UI tests for group administration. These drive the REAL app — real `@main`, real
/// `AppModel`, real `NedwonsClient`, real SwiftUI screens — launched with the Debug-only harness
/// flag that swaps the network for an in-process fixture (`NedwonsUI/UITestHarness.swift`). The
/// fixture applies the relay's own rules (admin-only, an admin is never muted, last admin cannot be
/// demoted, muted members cannot send), so what these tests see is what a user would see against a
/// server in the same state.
///
/// Element lookup goes through the accessibility identifiers in `GroupAdminA11y`; those are the
/// contract between the screens and this suite.
///
/// `@MainActor` is load-bearing, not decoration. Every XCUI API — `tap()`, `exists`, `label`,
/// `value`, `waitForExistence` — is main-actor isolated, so a nonisolated test method touching one
/// is a Swift 6 concurrency violation. Toolchains disagree about the severity: Xcode 26.6 emits
/// warnings, while the macos-15 runner's Xcode 26 emits ERRORS, which is why this suite compiled
/// locally and failed CI with `exit code 65` and nothing in the console summary to explain it.
/// Isolating the class to the main actor is also simply correct — XCUITest drives the UI, and the
/// UI lives on the main thread.
@MainActor
final class GroupAdminUITests: XCTestCase {
    private let conversationID = "c0" + String(repeating: "1", count: 30)
    private let bob = "bb" + String(repeating: "0", count: 30)
    private let carol = "cc" + String(repeating: "0", count: 30)
    private let erin = "ee" + String(repeating: "0", count: 30)

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    // MARK: Assertions

    // `XCTAssertTrue` and friends take their expression as an `@autoclosure`, and that closure is
    // NONISOLATED. Every XCUI API — `exists`, `label`, `value`, `waitForExistence` — is
    // `@MainActor`, so writing `XCTAssertTrue(app.buttons["x"].exists)` asks a nonisolated closure
    // to touch main-actor state. Under Swift 6 that is an error:
    //
    //     error: main actor-isolated property 'staticTexts' can not be referenced from a
    //            nonisolated autoclosure
    //
    // Newer toolchains let an autoclosure inherit its caller's isolation and accept it, which is
    // why this compiled locally on Xcode 26.6 while failing the macos-15 runner. Rather than
    // depend on that leniency, these wrappers take values that are ALREADY EVALUATED: an ordinary
    // parameter is computed at the call site, inside the main-actor test body, where touching XCUI
    // is legal on every toolchain. The message is eager for the same reason — several call sites
    // interpolate an element's label into it.
    private func expectTrue(_ value: Bool, _ message: String = "",
                            file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(value, message, file: file, line: line)
    }

    private func expectFalse(_ value: Bool, _ message: String = "",
                             file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertFalse(value, message, file: file, line: line)
    }

    private func expectEqual<T: Equatable>(_ actual: T, _ expected: T, _ message: String = "",
                                           file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(actual, expected, message, file: file, line: line)
    }

    // MARK: Launch + navigation helpers

    private func launch(scenario: String = "admin") -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["-nedwons-ui-test-harness", "-nedwons-ui-test-scenario", scenario]
        app.launch()
        return app
    }

    /// Any element carrying `identifier`, regardless of the element type SwiftUI chose for it.
    private func element(_ app: XCUIApplication, _ identifier: String) -> XCUIElement {
        app.descendants(matching: .any).matching(identifier: identifier).firstMatch
    }

    @discardableResult
    private func waitFor(_ element: XCUIElement, _ timeout: TimeInterval = 10,
                         file: StaticString = #filePath, line: UInt = #line) -> XCUIElement {
        let appeared = element.waitForExistence(timeout: timeout)
        expectTrue(appeared, "expected \(element) to appear", file: file, line: line)
        return element
    }

    /// Wait until a predicate holds for an element (value flipped, enabled, gone…).
    private func wait(_ predicate: String, on element: XCUIElement, _ timeout: TimeInterval = 10,
                      file: StaticString = #filePath, line: UInt = #line) {
        let expectation = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: predicate), object: element)
        let outcome = XCTWaiter().wait(for: [expectation], timeout: timeout)
        expectEqual(outcome, .completed, "expected '\(predicate)' on \(element)",
                    file: file, line: line)
    }

    /// Rows in a SwiftUI `List` exist only while rendered, so a row below the fold is scrolled to.
    @discardableResult
    private func waitForRow(_ app: XCUIApplication, _ identifier: String,
                            file: StaticString = #filePath, line: UInt = #line) -> XCUIElement {
        let row = element(app, identifier)
        for _ in 0..<4 where !row.waitForExistence(timeout: 3) {
            app.swipeUp()
        }
        expectTrue(row.exists, "expected row \(identifier)", file: file, line: line)
        return row
    }

    /// A SwiftUI `Toggle` row's accessibility frame spans label + switch; tapping its centre lands
    /// on the label, which does not flip it. Tap the trailing edge, where the switch is.
    private func flip(_ toggle: XCUIElement) {
        toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.92, dy: 0.5)).tap()
    }

    private func openConversation(_ app: XCUIApplication) {
        waitFor(element(app, "chats.row.\(conversationID)")).tap()
        waitFor(element(app, "conversation.groupInfo"))
    }

    private func openGroupPanel(_ app: XCUIApplication) {
        openConversation(app)
        element(app, "conversation.groupInfo").tap()
        waitFor(element(app, "group.panel"))
    }

    private func openMember(_ app: XCUIApplication, _ accountID: String) {
        waitForRow(app, "group.member.\(accountID)").tap()
        waitFor(element(app, "group.member.status"))
    }

    private func status(_ app: XCUIApplication) -> String {
        element(app, "group.member.status").label
    }

    /// Confirmation dialogs render as UIKit alerts/sheets whose buttons ignore SwiftUI identifiers,
    /// so they are found by title.
    private func confirm(_ app: XCUIApplication, _ title: String) {
        let button = app.buttons[title].firstMatch
        waitFor(button, 5).tap()
    }

    private func waitForStatus(_ app: XCUIApplication, contains needle: String,
                               file: StaticString = #filePath, line: UInt = #line) {
        wait("label CONTAINS[c] '\(needle)'", on: element(app, "group.member.status"),
             file: file, line: line)
    }

    // MARK: Tests

    /// Mute → the member's status says so → unmute → back to a plain member. Round-trips through
    /// the real client and the fixture's mute table; the screen re-reads state after each action.
    func testAdminMutesAndUnmutesAMember() {
        let app = launch()
        openGroupPanel(app)
        openMember(app, carol)
        expectEqual(status(app), "Member")

        waitFor(element(app, "group.member.mute")).tap()
        waitForStatus(app, contains: "Muted until")
        expectFalse(element(app, "group.member.mute").exists, "a muted member offers Unmute, not Mute")

        waitFor(element(app, "group.member.unmute")).tap()
        waitForStatus(app, contains: "Member")
        expectTrue(element(app, "group.member.mute").exists)
    }

    /// Announcement mode ("mute all") flips from the panel: the switch reads on, and the header
    /// badge — a distinct element from the switch's own caption — appears.
    func testAdminTogglesAnnouncementMode() {
        let app = launch()
        openGroupPanel(app)
        let toggle = waitFor(app.switches["group.toggle.announcementsOnly"].firstMatch)
        expectEqual(toggle.value as? String, "0")
        expectFalse(element(app, "group.header.announcementsOnly").exists)

        flip(toggle)
        wait("value == '1'", on: toggle)
        waitFor(element(app, "group.header.announcementsOnly"))

        flip(toggle)
        wait("value == '0'", on: toggle)
        wait("exists == false", on: element(app, "group.header.announcementsOnly"))
    }

    /// The other side of announcement mode: an ordinary member's composer is replaced by an
    /// explanation, and there is no text field to type into.
    func testAnnouncementModeLocksTheComposerForMembers() {
        let app = launch(scenario: "announcements_only")
        openConversation(app)
        let locked = waitFor(element(app, "conversation.composer.locked"))
        expectTrue(locked.label.localizedCaseInsensitiveContains("only admins"))
        expectFalse(element(app, "conversation.composer.field").exists)
    }

    /// A muted member is told they are muted — not shown a generic failure — and cannot type.
    func testMutedMemberSeesWhyTheyCannotSend() {
        let app = launch(scenario: "muted")
        openConversation(app)
        let locked = waitFor(element(app, "conversation.composer.locked"))
        expectTrue(locked.label.localizedCaseInsensitiveContains("muted"))
        expectFalse(element(app, "conversation.composer.field").exists)

        // The panel says the same thing, and offers none of the admin controls.
        element(app, "conversation.groupInfo").tap()
        waitFor(element(app, "group.panel"))
        expectFalse(element(app, "group.addMembers").exists)
        expectFalse(app.switches["group.toggle.announcementsOnly"].exists)
    }

    /// Roles: promote, then demote. The screen re-reads state after each action, so the button that
    /// is offered always matches the role the server holds.
    func testAdminPromotesAndDemotesAMember() {
        let app = launch()
        openGroupPanel(app)
        openMember(app, carol)
        waitFor(element(app, "group.member.promote")).tap()
        waitForStatus(app, contains: "Admin")
        expectFalse(element(app, "group.member.mute").exists, "admins cannot be muted")

        waitFor(element(app, "group.member.demote")).tap()
        waitForStatus(app, contains: "Member")
        expectTrue(element(app, "group.member.promote").exists)
    }

    /// Demoting another admin while one remains is allowed, and the role round-trips. The
    /// last-admin REFUSAL is not reachable from this screen by construction — the app never offers
    /// self-demotion, and the only way to be the last admin is to be "me" — so that refusal is
    /// covered at the model layer instead (`GroupAdminModelTests.testRefusalsBecomeSpecificBanners`).
    func testDemotingAnotherAdminIsAllowedWhileOneRemains() {
        let app = launch()
        openGroupPanel(app)
        openMember(app, bob)
        waitForStatus(app, contains: "Admin")
        waitFor(element(app, "group.member.demote")).tap()
        waitForStatus(app, contains: "Member")
        waitFor(element(app, "group.member.promote")).tap()
        waitForStatus(app, contains: "Admin")
    }

    /// Add a friend, see them in the member list, remove them, see them gone.
    func testAdminAddsAndRemovesAMember() {
        let app = launch()
        openGroupPanel(app)
        expectFalse(element(app, "group.member.\(erin)").exists)

        waitForRow(app, "group.addMembers").tap()
        // Let the sheet finish presenting before tapping inside it: a tap during the animation is
        // dropped, which leaves nothing selected and "Add" disabled.
        waitFor(app.navigationBars["Add members"].firstMatch)
        let erinRow = waitFor(element(app, "group.addMembers.row.\(erin)"))
        wait("isHittable == true", on: erinRow)
        erinRow.tap()
        wait("isSelected == true", on: erinRow)
        // "Add" is disabled while the sheet's friend refresh is in flight; wait for it. Toolbar
        // buttons are looked up by title: like dialog buttons, their SwiftUI identifier does not
        // reliably land on the hittable element.
        let add = waitFor(app.buttons["Add"].firstMatch)
        wait("isEnabled == true", on: add)
        add.tap()
        wait("exists == false", on: app.navigationBars["Add members"].firstMatch)
        waitForRow(app, "group.member.\(erin)")

        openMember(app, erin)
        // Below the fold since the member page gained verify + encryption-setup sections.
        waitForRow(app, "group.member.remove").tap()
        confirm(app, "Remove")
        // Removal pops back to the panel, where the row is gone.
        waitFor(element(app, "group.panel"))
        wait("exists == false", on: element(app, "group.member.\(erin)"))
    }

    /// Renaming from the panel retitles the panel, the conversation header, and the chat list —
    /// the name is one piece of state read everywhere, not three copies.
    func testAdminRenamesTheGroup() {
        let app = launch()
        openGroupPanel(app)
        expectEqual(element(app, "group.title").label, "Group · 4 people")

        waitFor(element(app, "group.rename")).tap()
        let field = waitFor(element(app, "group.rename.field"))
        field.tap()
        field.typeText("Weekend Trip")
        waitFor(app.buttons["Save"].firstMatch).tap()
        // Let the sheet finish dismissing before navigating: the title predicate below turns true
        // the moment the model updates, while the sheet is still mid-flight.
        wait("exists == false", on: app.navigationBars["Group name"].firstMatch)
        wait("label == 'Weekend Trip'", on: element(app, "group.title"))

        app.navigationBars.buttons.element(boundBy: 0).tap()  // back to the conversation
        wait("label BEGINSWITH 'Weekend Trip'", on: element(app, "conversation.title"))
        app.navigationBars.buttons.element(boundBy: 0).tap()  // back to the list
        expectTrue(app.staticTexts["Weekend Trip"].firstMatch.waitForExistence(timeout: 5),
                      "the chat list shows the new name")
    }

    /// The unread badge reflects local state and clears when the conversation is opened.
    func testUnreadBadgeClearsWhenTheConversationIsOpened() {
        let app = launch()
        let badge = waitFor(element(app, "chats.unread.\(conversationID)"))
        expectEqual(badge.label, "3 unread")
        openConversation(app)
        app.navigationBars.buttons.element(boundBy: 0).tap()  // back to the list
        wait("exists == false", on: element(app, "chats.unread.\(conversationID)"))
    }

    /// Reply and react are offered on a message, and the reply bar shows what is being answered.
    /// (The harness has no MLS core, so this covers the interaction UI's own behaviour — the
    /// end-to-end semantics are proven in ConversationCoordinatorTests against the real core.)
    func testMessageOffersReplyAndReactions() {
        let app = launch()
        openConversation(app)

        // Send something so there is a message to act on.
        let field = waitFor(element(app, "conversation.composer.field"))
        field.tap()
        field.typeText("hello there")
        app.buttons["arrow.up.circle.fill"].firstMatch.tap()
        let bubble = waitFor(app.staticTexts["hello there"].firstMatch)

        // Long-press offers Reply and the quick reactions.
        bubble.press(forDuration: 1.2)
        let reply = waitFor(app.buttons["Reply"].firstMatch, 5)
        expectTrue(app.buttons["👍"].firstMatch.exists, "quick reactions are offered")
        reply.tap()

        // The reply bar names what is being answered, and cancelling clears it.
        let bar = waitFor(element(app, "conversation.reply.bar"))
        expectTrue(
            bar.label.localizedCaseInsensitiveContains("hello there"),
            "the composer names what is being answered, was: \(bar.label)")
        waitFor(element(app, "conversation.reply.cancel")).tap()
        wait("exists == false", on: element(app, "conversation.reply.bar"))

        // And a reaction attaches to the message it names.
        bubble.press(forDuration: 1.2)
        waitFor(app.buttons["👍"].firstMatch, 5).tap()
        waitFor(element(app, "thread.reaction.00000000000000000000000000000001.👍"))
    }

    /// An ordinary member gets the read-only panel: members and roles visible, no admin controls.
    func testOrdinaryMemberSeesNoAdminControls() {
        let app = launch(scenario: "member")
        openGroupPanel(app)
        waitFor(element(app, "group.member.\(bob)"))
        expectFalse(element(app, "group.addMembers").exists)
        expectFalse(app.switches["group.toggle.announcementsOnly"].exists)
        expectFalse(element(app, "group.createInvite").exists)
        expectTrue(app.staticTexts["Who can send"].firstMatch.waitForExistence(timeout: 5))

        openMember(app, carol)
        expectFalse(element(app, "group.member.mute").exists)
        expectFalse(element(app, "group.member.promote").exists)
        expectFalse(element(app, "group.member.remove").exists)
    }

    /// An admin's composer stays usable in announcement mode, and a sent message renders. The mode
    /// is verified to be ON (switch value) before going back, so this proves the admin exemption
    /// rather than sending in an unlocked group.
    func testAdminCanStillSendInAnnouncementMode() {
        let app = launch()
        openGroupPanel(app)
        let toggle = waitFor(app.switches["group.toggle.announcementsOnly"].firstMatch)
        flip(toggle)
        wait("value == '1'", on: toggle)
        app.navigationBars.buttons.element(boundBy: 0).tap()  // back to the conversation

        let field = waitFor(element(app, "conversation.composer.field"))
        expectFalse(element(app, "conversation.composer.locked").exists, "admins are exempt")
        field.tap()
        field.typeText("announcement")
        app.buttons["arrow.up.circle.fill"].firstMatch.tap()
        expectTrue(app.staticTexts["announcement"].firstMatch.waitForExistence(timeout: 10))
    }
}
