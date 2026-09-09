import XCTest

@testable import NedwonsKit
@testable import NedwonsUI

private func tempAliasStore() -> ContactAliasStore {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("alias-\(UUID().uuidString).bin")
    return ContactAliasStore(fileURL: url, atRestKey: Data(repeating: 9, count: 32))
}

final class AliasValidationTests: XCTestCase {
    func testPlainNameIsAccepted() {
        XCTAssertEqual(ContactAlias.validate("  Mum  "), .valid("Mum"))
    }

    func testEmptyIsRejected() {
        XCTAssertEqual(ContactAlias.validate("   "), .empty)
    }

    func testOverlongIsRejected() {
        let long = String(repeating: "a", count: AliasValidation.maxLength + 1)
        XCTAssertEqual(ContactAlias.validate(long), .tooLong)
    }

    /// Bidi overrides could make an alias render as though it were a different account's handle.
    func testBidiOverrideIsRejected() {
        XCTAssertEqual(ContactAlias.validate("evil\u{202E}name"), .unsafeCharacters)
    }

    func testControlCharacterIsRejected() {
        XCTAssertEqual(ContactAlias.validate("na\u{0007}me"), .unsafeCharacters)
    }

    func testEmojiIsAllowed() {
        XCTAssertEqual(ContactAlias.validate("Mum 💚"), .valid("Mum 💚"))
    }
}

final class ContactAliasStoreTests: XCTestCase {
    func testAliasIsKeyedByImmutableAccountIDNotUsername() {
        let store = tempAliasStore()
        store.setAlias("Nickname", for: "account-abc")
        XCTAssertEqual(store.alias(for: "account-abc"), "Nickname")
        XCTAssertNil(store.alias(for: "someusername"))
    }

    func testDisplayNameFallsBackToRealUsername() {
        let store = tempAliasStore()
        XCTAssertEqual(store.displayName(for: "acct", username: "realname"), "realname")
        store.setAlias("Nick", for: "acct")
        XCTAssertEqual(store.displayName(for: "acct", username: "realname"), "Nick")
    }

    func testRemovingAliasRestoresTheRealUsername() {
        let store = tempAliasStore()
        store.setAlias("Nick", for: "acct")
        store.removeAlias(for: "acct")
        XCTAssertNil(store.alias(for: "acct"))
        XCTAssertEqual(store.displayName(for: "acct", username: "realname"), "realname")
    }

    func testAliasesPersistEncryptedAcrossReopen() {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("alias-\(UUID().uuidString).bin")
        let key = Data(repeating: 3, count: 32)
        ContactAliasStore(fileURL: url, atRestKey: key).setAlias("Nick", for: "acct")

        XCTAssertEqual(ContactAliasStore(fileURL: url, atRestKey: key).alias(for: "acct"), "Nick")

        // The blob on disk must not contain the plaintext alias.
        let raw = try? Data(contentsOf: url)
        XCTAssertNotNil(raw)
        XCTAssertFalse(
            raw!.range(of: Data("Nick".utf8)) != nil, "alias must not be stored in plaintext")
    }

    func testWrongKeyCannotReadAliases() {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("alias-\(UUID().uuidString).bin")
        ContactAliasStore(fileURL: url, atRestKey: Data(repeating: 1, count: 32))
            .setAlias("Nick", for: "acct")
        let wrong = ContactAliasStore(fileURL: url, atRestKey: Data(repeating: 2, count: 32))
        XCTAssertNil(wrong.alias(for: "acct"))
    }

    func testInvalidAliasIsNotStored() {
        let store = tempAliasStore()
        XCTAssertEqual(store.setAlias("bad\u{202E}", for: "acct"), .unsafeCharacters)
        XCTAssertNil(store.alias(for: "acct"))
    }
}

@MainActor
final class AliasModelTests: XCTestCase {
    private func model() -> AppModel {
        let m = AppModel(
            baseURL: URL(string: "http://127.0.0.1:1")!,
            deviceIdentity: DeviceIdentity(
                store: InMemoryDeviceKeyStore(), secureEnclaveAvailable: false),
            sessionStore: SessionStore(store: FakeSecretStore()))
        m.aliasStore = tempAliasStore()
        return m
    }

    func testAliasChangesDisplayNameOnlyForItsOwner() {
        let m = model()
        m.setAlias("Nick", for: "peer-1")
        XCTAssertEqual(m.displayName(for: "peer-1", username: "realname"), "Nick")
        // A different viewer (a separate model with its own store) sees the real username.
        XCTAssertEqual(model().displayName(for: "peer-1", username: "realname"), "realname")
    }

    func testRemovingAliasRestoresRealUsername() {
        let m = model()
        m.setAlias("Nick", for: "peer-1")
        m.removeAlias(for: "peer-1")
        XCTAssertEqual(m.displayName(for: "peer-1", username: "realname"), "realname")
    }

    /// An alias is display-only: it must never become a lookup key or identity.
    func testAliasDoesNotAffectIdentityLookup() {
        let m = model()
        m.rememberUsernames([
            ProfileSummary(accountID: "peer-1", username: "realname", displayName: "")
        ])
        m.setAlias("Nick", for: "peer-1")
        XCTAssertEqual(m.username(forAccountID: "peer-1"), "realname")
    }
}

final class SearchOrderingTests: XCTestCase {
    private func summary(_ username: String) -> ProfileSummary {
        ProfileSummary(accountID: "id-\(username)", username: username, displayName: "")
    }

    func testExactMatchIsPrioritized() {
        let results = [summary("alice_b"), summary("alice_c"), summary("alice")]
        let ordered = AppModel.prioritizeExactMatch(results, query: "alice")
        XCTAssertEqual(ordered.first?.username, "alice")
        XCTAssertEqual(ordered.count, 3, "prioritizing must not drop results")
    }

    /// Usernames are stored case-normalized, so matching must be case-folded.
    func testExactMatchIsCaseInsensitive() {
        let ordered = AppModel.prioritizeExactMatch([summary("bob_x"), summary("bob")], query: "BOB")
        XCTAssertEqual(ordered.first?.username, "bob")
    }

    func testNoExactMatchPreservesBackendOrder() {
        let results = [summary("carol_1"), summary("carol_2")]
        let ordered = AppModel.prioritizeExactMatch(results, query: "carol")
        XCTAssertEqual(ordered.map(\.username), ["carol_1", "carol_2"])
    }
}

final class ChatSortingTests: XCTestCase {
    func testMostRecentActivitySortsFirst() {
        let old = ChatSummary(conversationID: "a", lastActivity: Date(timeIntervalSince1970: 100))
        let new = ChatSummary(conversationID: "b", lastActivity: Date(timeIntervalSince1970: 900))
        XCTAssertEqual(sortedByRecency([old, new]).map(\.conversationID), ["b", "a"])
    }

    /// A conversation with no activity yet must still be listed, just last.
    func testThreadsWithoutActivityStayListed() {
        let active = ChatSummary(conversationID: "a", lastActivity: Date())
        let quiet = ChatSummary(conversationID: "b", lastActivity: nil)
        XCTAssertEqual(sortedByRecency([quiet, active]).map(\.conversationID), ["a", "b"])
    }
}

@MainActor
final class ComposeDraftTests: XCTestCase {
    private func model() -> AppModel {
        AppModel(
            baseURL: URL(string: "http://127.0.0.1:1")!,
            deviceIdentity: DeviceIdentity(
                store: InMemoryDeviceKeyStore(), secureEnclaveAvailable: false),
            sessionStore: SessionStore(store: FakeSecretStore()))
    }

    /// A draft is remembered per conversation and does not bleed between them.
    func testDraftsAreRememberedPerConversation() {
        let m = model()
        m.setComposeDraft("half a message", for: "c1")
        m.setComposeDraft("something else", for: "c2")
        XCTAssertEqual(m.composeDrafts["c1"], "half a message")
        XCTAssertEqual(m.composeDrafts["c2"], "something else")
    }

    /// Sending (or clearing) empties the draft rather than leaving a stale one to reappear.
    func testClearingADraftForgetsIt() {
        let m = model()
        m.setComposeDraft("typed then sent", for: "c1")
        m.setComposeDraft("", for: "c1")
        XCTAssertNil(m.composeDrafts["c1"], "an emptied draft is forgotten, not stored as empty")
    }
}

@MainActor
final class ConversationDeletionTests: XCTestCase {
    private func model() -> AppModel {
        AppModel(
            baseURL: URL(string: "http://127.0.0.1:1")!,
            deviceIdentity: DeviceIdentity(
                store: InMemoryDeviceKeyStore(), secureEnclaveAvailable: false),
            sessionStore: SessionStore(store: FakeSecretStore()))
    }

    func testDeleteHidesThreadAndClearsPreview() async {
        let m = model()
        m.conversations = [Conversation(conversationID: "c1", memberAccountIDs: ["me", "peer"])]
        m.localThreads["c1"] = AppModel.LocalThreadState(preview: "secret plan", lastActivity: Date())

        await m.deleteConversationLocally("c1")

        XCTAssertTrue(m.visibleConversations.isEmpty)
        XCTAssertNil(m.localPreview(for: "c1"), "the cached preview must not survive deletion")
    }

    /// Deletion is local: it must invoke the history-clear action and send nothing.
    func testDeleteClearsLocalHistoryOnly() async {
        let m = model()
        var cleared: [String] = []
        m.clearHistoryAction = { cleared.append($0) }
        var sends = 0
        m.sendMessageAction = { _, _ in sends += 1 }

        m.conversations = [Conversation(conversationID: "c1", memberAccountIDs: ["me", "peer"])]
        await m.deleteConversationLocally("c1")

        XCTAssertEqual(cleared, ["c1"])
        XCTAssertEqual(sends, 0, "deletion must not transmit anything")
    }

    /// Deleting must not remove the person or their alias.
    func testDeleteKeepsAliasAndContact() async {
        let m = model()
        m.aliasStore = tempAliasStore()
        m.setAlias("Nick", for: "peer")
        m.friends = [ProfileSummary(accountID: "peer", username: "peer", displayName: "")]
        m.conversations = [Conversation(conversationID: "c1", memberAccountIDs: ["me", "peer"])]

        await m.deleteConversationLocally("c1")

        XCTAssertEqual(m.alias(for: "peer"), "Nick")
        XCTAssertEqual(m.friends.count, 1)
        XCTAssertTrue(m.blocked.isEmpty, "deleting a thread must not block anyone")
    }

    /// A later legitimate message brings the thread back — without restoring deleted history.
    func testThreadReturnsOnNewActivityWithoutOldHistory() async {
        let m = model()
        m.conversations = [Conversation(conversationID: "c1", memberAccountIDs: ["me", "peer"])]
        m.localThreads["c1"] = AppModel.LocalThreadState(preview: "old", lastActivity: Date())
        await m.deleteConversationLocally("c1")
        XCTAssertTrue(m.visibleConversations.isEmpty)

        m.unhideConversation("c1")

        XCTAssertEqual(m.visibleConversations.map(\.conversationID), ["c1"])
        XCTAssertNil(m.localPreview(for: "c1"), "deleted history must not come back")
    }

    func testDeletingOneThreadLeavesOthersVisible() async {
        let m = model()
        m.conversations = [
            Conversation(conversationID: "c1", memberAccountIDs: ["me", "a"]),
            Conversation(conversationID: "c2", memberAccountIDs: ["me", "b"]),
        ]
        await m.deleteConversationLocally("c1")
        XCTAssertEqual(m.visibleConversations.map(\.conversationID), ["c2"])
    }
}

/// Media helpers (voice notes + file sending, arc E): small pure pieces of the media surface.
@MainActor
final class MediaHelperTests: XCTestCase {
    func testVoiceClockFormatting() {
        XCTAssertEqual(VoiceNoteBubbleView.clock(0), "0:00")
        XCTAssertEqual(VoiceNoteBubbleView.clock(65), "1:05")
        XCTAssertEqual(VoiceNoteBubbleView.clock(599.9), "9:59")
    }

    func testAttachmentKindHelpers() {
        let voice = AttachmentLine(
            blobID: "b", mime: "audio/mp4", filename: "", size: 10, caption: "")
        XCTAssertTrue(voice.isAudio)
        XCTAssertEqual(voice.displayName, "Voice message")
        let clip = AttachmentLine(
            blobID: "b", mime: "video/mp4", filename: "", size: 10, caption: "")
        XCTAssertTrue(clip.isVideo)
        XCTAssertEqual(clip.displayName, "Video")
    }

    func testMimeFromExtensionIsAdvisoryButSane() {
        XCTAssertEqual(
            ConversationView.mimeType(for: URL(fileURLWithPath: "/tmp/report.pdf")),
            "application/pdf")
        XCTAssertEqual(
            ConversationView.mimeType(for: URL(fileURLWithPath: "/tmp/mystery.zzz9")),
            "application/octet-stream")
    }

    /// The temp copy used for viewing is created inside its own directory and fully removed.
    func testMediaTempFileLifecycle() throws {
        let file = try XCTUnwrap(
            MediaTempFile(data: Data([1, 2, 3]), filename: "../sneaky/name.mp4"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.url.path))
        XCTAssertFalse(file.url.path.contains(".."), "traversal neutralized")
        file.remove()
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.url.path))
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: file.url.deletingLastPathComponent().path))
    }

    /// The 25 MB cap is refused client-side with honest copy, before any sealing work.
    func testOversizedAttachmentIsRefusedUpFront() async {
        let model = AppModel(baseURL: URL(string: "http://127.0.0.1:1")!)
        model.sendAttachmentAction = { _, _, _, _, _ in
            XCTFail("must not reach the send path")
        }
        await model.sendAttachment(
            Data(count: 26 * 1024 * 1024), mime: "video/mp4", filename: "big.mp4", caption: "",
            to: "conv")
        XCTAssertEqual(model.banner?.contains("25 MB") , true)
    }
}

/// Chat-list preferences (arc H): local, per-account, and the ordering they produce.
@MainActor
final class ChatPrefsTests: XCTestCase {
    private func chat(_ id: String, activity: TimeInterval) -> ChatSummary {
        ChatSummary(conversationID: id, lastActivity: Date(timeIntervalSince1970: activity))
    }

    func testPinnedFloatAndArchivedHide() {
        var prefs = ChatPrefs()
        prefs.pinned = ["old-pinned"]
        prefs.archived = ["archived"]
        let ordered = sortedForChatList(
            [
                chat("newest", activity: 300),
                chat("old-pinned", activity: 100),
                chat("archived", activity: 400),
                chat("middle", activity: 200),
            ],
            prefs: prefs)
        XCTAssertEqual(
            ordered.map(\.conversationID), ["old-pinned", "newest", "middle"],
            "pins float above recency; archived never appears")
    }

    func testPrefsPersistPerAccountAndToggleCleanly() {
        let store = MemoryChatPrefsStore()
        let model = AppModel(baseURL: URL(string: "http://127.0.0.1:1")!)
        model.chatPrefsStore = store
        model.session = NedwonsClient.Session(
            accountID: "acct-a", deviceID: "d", accessToken: "t", accessExpiresAt: .max,
            refreshToken: "r", refreshExpiresAt: .max)

        model.togglePinned("c1")
        model.toggleMuted("c2")
        model.toggleArchived("c3")
        XCTAssertEqual(store.byAccount["acct-a"]?.pinned, ["c1"])
        XCTAssertEqual(store.byAccount["acct-a"]?.muted, ["c2"])
        XCTAssertEqual(store.byAccount["acct-a"]?.archived, ["c3"])
        model.togglePinned("c1")
        XCTAssertEqual(store.byAccount["acct-a"]?.pinned, [])

        // A different account loads a clean slate.
        model.session = NedwonsClient.Session(
            accountID: "acct-b", deviceID: "d", accessToken: "t", accessExpiresAt: .max,
            refreshToken: "r", refreshExpiresAt: .max)
        model.loadChatPrefs()
        XCTAssertEqual(model.chatPrefs, ChatPrefs())
    }
}

/// Diagnostics are OFF by default and the toggle persists (arc K).
@MainActor
final class DiagnosticsPrefTests: XCTestCase {
    func testOffByDefaultAndTogglePersists() {
        let suite = "diag-test-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        let client = NedwonsClient(baseURL: URL(string: "http://127.0.0.1:1")!)
        let reporter = DiagnosticsReporter(client: client, defaults: defaults)
        XCTAssertFalse(reporter.enabled, "opt-IN means off until the user says otherwise")
        reporter.setEnabled(true)
        XCTAssertTrue(DiagnosticsReporter(client: client, defaults: defaults).enabled)
        reporter.setEnabled(false)
        XCTAssertFalse(DiagnosticsReporter(client: client, defaults: defaults).enabled)
        defaults.removePersistentDomain(forName: suite)
    }
}
