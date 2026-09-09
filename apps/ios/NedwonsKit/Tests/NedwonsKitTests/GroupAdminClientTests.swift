import XCTest

@testable import NedwonsKit

/// The group-administration client surface: request shapes the relay expects, decoding of the
/// one-round-trip panel state, and the refusal-code parsing the UI keys its wording off.
final class GroupAdminClientTests: XCTestCase {
    private let token = "t"
    private let conv = "c0" + String(repeating: "1", count: 30)

    private func client() -> NedwonsClient {
        StubURLProtocol.statusCode = 204
        StubURLProtocol.responseBody = Data()
        return NedwonsClient(baseURL: URL(string: "https://example.invalid")!, session: StubURLProtocol.session())
    }

    /// `URLSession` moves `httpBody` into `httpBodyStream` before any protocol sees the request,
    /// so the body has to be drained from the stream.
    private func sentJSON() throws -> [String: Any] {
        let request = try XCTUnwrap(StubURLProtocol.lastRequest)
        var body = request.httpBody ?? Data()
        if body.isEmpty, let stream = request.httpBodyStream {
            stream.open()
            defer { stream.close() }
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let read = stream.read(&buffer, maxLength: buffer.count)
                if read <= 0 { break }
                body.append(buffer, count: read)
            }
        }
        XCTAssertFalse(body.isEmpty, "request carries a JSON body")
        return try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
    }

    /// The panel decodes exactly the server's DTO, including the deliberately-absent optional keys
    /// (an indefinite mute has no `mute_expires_at`; an unmuted member has no `muted_by`).
    func testGroupStateDecodesTheServerShape() async throws {
        let json = """
            {
              "conversation_id": "\(conv)",
              "is_admin": true,
              "can_send": true,
              "join_approval": false,
              "announcements_only": true,
              "mls_authoritative": false,
              "members": [
                {"account_id": "aa", "username": "me", "display_name": "Me", "is_admin": true, "muted": false},
                {"account_id": "bb", "username": "bob", "display_name": "", "is_admin": false,
                 "muted": true, "muted_by": "aa"},
                {"account_id": "cc", "username": "carol", "display_name": "", "is_admin": false,
                 "muted": true, "mute_expires_at": 1800000000, "muted_by": "aa"}
              ],
              "join_requests": ["dd"],
              "invites": [{"invite_token": "ff", "expires_at": 1700000000, "max_uses": 100, "uses": 3}]
            }
            """
        StubURLProtocol.statusCode = 200
        StubURLProtocol.responseBody = Data(json.utf8)
        let client = NedwonsClient(baseURL: URL(string: "https://example.invalid")!, session: StubURLProtocol.session())

        let state = try await client.groupState(accessToken: token, conversationID: conv)

        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/v1/conversations/\(conv)/group")
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "GET")
        XCTAssertTrue(state.isAdmin)
        XCTAssertTrue(state.announcementsOnly)
        XCTAssertEqual(state.members.count, 3)
        XCTAssertEqual(state.admins.map(\.accountID), ["aa"])
        XCTAssertEqual(state.mutedMembers.map(\.accountID), ["bb", "cc"])
        let bob = try XCTUnwrap(state.member("bb"))
        XCTAssertTrue(bob.muted)
        XCTAssertNil(bob.muteExpiresAt, "indefinite mute carries no expiry")
        XCTAssertEqual(bob.mutedBy, "aa")
        XCTAssertEqual(state.member("cc")?.muteExpiresAt, 1_800_000_000)
        XCTAssertEqual(state.joinRequests, ["dd"])
        XCTAssertEqual(state.invites.first?.uses, 3)
    }

    /// An indefinite mute must OMIT `duration_secs` (the server reads absence as "until unmuted"),
    /// and a timed one carries the seconds.
    func testMuteBodyOmitsDurationForIndefinite() async throws {
        let client = client()
        try await client.muteGroupMember(accessToken: token, conversationID: conv, accountID: "bb")
        var body = try sentJSON()
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/v1/conversations/\(conv)/mutes")
        XCTAssertEqual(body["account_id"] as? String, "bb")
        XCTAssertNil(body["duration_secs"], "indefinite mute sends no duration key at all")

        try await client.muteGroupMember(
            accessToken: token, conversationID: conv, accountID: "bb", durationSecs: 3600)
        body = try sentJSON()
        XCTAssertEqual(body["duration_secs"] as? Int, 3600)
    }

    /// Settings are partial updates: only the switch being changed is sent, so two admins editing
    /// different switches can never revert each other.
    func testSettingsSendOnlyTheSwitchBeingChanged() async throws {
        let client = client()
        try await client.updateGroupSettings(accessToken: token, conversationID: conv, announcementsOnly: true)
        var body = try sentJSON()
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/v1/conversations/\(conv)/settings")
        XCTAssertEqual(body["announcements_only"] as? Bool, true)
        XCTAssertNil(body["join_approval"])

        try await client.updateGroupSettings(accessToken: token, conversationID: conv, joinApproval: false)
        body = try sentJSON()
        XCTAssertEqual(body["join_approval"] as? Bool, false)
        XCTAssertNil(body["announcements_only"])
    }

    /// Every "do X to this account" call hits its own route with the shared `{account_id}` body
    /// and a bearer token.
    func testAccountRefRoutes() async throws {
        let client = client()
        let calls: [(String, () async throws -> Void)] = [
            ("/members", { try await client.addGroupMember(accessToken: self.token, conversationID: self.conv, accountID: "x") }),
            ("/members/remove", { try await client.removeGroupMember(accessToken: self.token, conversationID: self.conv, accountID: "x") }),
            ("/admins", { try await client.promoteGroupAdmin(accessToken: self.token, conversationID: self.conv, accountID: "x") }),
            ("/admins/demote", { try await client.demoteGroupAdmin(accessToken: self.token, conversationID: self.conv, accountID: "x") }),
            ("/mutes/remove", { try await client.unmuteGroupMember(accessToken: self.token, conversationID: self.conv, accountID: "x") }),
            ("/requests/approve", { try await client.approveJoinRequest(accessToken: self.token, conversationID: self.conv, accountID: "x") }),
            ("/requests/deny", { try await client.denyJoinRequest(accessToken: self.token, conversationID: self.conv, accountID: "x") }),
        ]
        for (suffix, call) in calls {
            try await call()
            let request = try XCTUnwrap(StubURLProtocol.lastRequest)
            XCTAssertEqual(request.url?.path, "/v1/conversations/\(conv)\(suffix)")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer t")
            XCTAssertEqual(try sentJSON()["account_id"] as? String, "x", suffix)
        }

        try await client.unmuteAllGroupMembers(accessToken: token, conversationID: conv)
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/v1/conversations/\(conv)/mutes/clear")
    }

    /// A refusal surfaces as `ClientError.http` carrying the server's `{"error": code}` body, which
    /// `GroupRefusal` parses; unknown or malformed bodies parse to nil rather than to a wrong code.
    func testRefusalCodesParse() async {
        StubURLProtocol.statusCode = 409
        StubURLProtocol.responseBody = Data(#"{"error":"target_is_admin"}"#.utf8)
        let client = NedwonsClient(baseURL: URL(string: "https://example.invalid")!, session: StubURLProtocol.session())
        do {
            try await client.muteGroupMember(accessToken: token, conversationID: conv, accountID: "bb")
            XCTFail("expected a refusal")
        } catch let NedwonsClient.ClientError.http(status, body) {
            XCTAssertEqual(status, 409)
            XCTAssertEqual(GroupRefusal.from(errorBody: body), .targetIsAdmin)
        } catch {
            XCTFail("unexpected \(error)")
        }

        XCTAssertEqual(GroupRefusal.from(errorBody: #"{"error":"muted"}"#), .muted)
        XCTAssertEqual(GroupRefusal.from(errorBody: #"{"error":"announcements_only"}"#), .announcementsOnly)
        XCTAssertEqual(GroupRefusal.from(errorBody: #"{"error":"last_admin"}"#), .lastAdmin)
        XCTAssertNil(GroupRefusal.from(errorBody: #"{"error":"something_new"}"#))
        XCTAssertNil(GroupRefusal.from(errorBody: "not json"))
        XCTAssertTrue(GroupRefusal.muted.isSendRefusal)
        XCTAssertTrue(GroupRefusal.announcementsOnly.isSendRefusal)
        XCTAssertFalse(GroupRefusal.forbidden.isSendRefusal)
    }
}
