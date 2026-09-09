#if DEBUG
    import Foundation
    import NedwonsKit

    // UI-test harness (Debug builds only).
    //
    // The XCUITest suite in `apps/ios/Nedwons/UITests` drives the REAL app: real `@main`, real
    // `AppModel`, real `NedwonsClient`, real SwiftUI screens. The only thing replaced is the
    // network — `URLSession` is served by an in-process fixture that behaves like the relay's group
    // endpoints (same routes, same JSON, same refusal codes, same invariants), so a test can mute a
    // member and watch the composer lock without a server, and CI can run it on any simulator.
    //
    // Compiled under `#if DEBUG` on purpose. Selecting the harness adopts a session WITHOUT a device
    // proof, which in a Release binary would be an authentication bypass. It does not exist there.
    //
    // The unit tests in `NedwonsUITests/GroupAdminModelTests.swift` reuse the same fixture, so the
    // model-level tests and the on-simulator UI tests cannot drift apart on server semantics.

    /// Which starting state the fixture boots into.
    public enum UITestScenario: String, Sendable {
        /// The user administers a 4-person group. Default.
        case admin
        /// The user is an ordinary member (someone else is admin).
        case member
        /// The user is a member and already muted, indefinitely.
        case muted
        /// The user is a member and the group is in announcement mode.
        case announcementsOnly = "announcements_only"
    }

    /// Reads the launch arguments the UI tests pass. `nil` = not a UI-test launch.
    public enum UITestLaunch {
        public static let harnessFlag = "-nedwons-ui-test-harness"
        public static let scenarioFlag = "-nedwons-ui-test-scenario"

        public static func scenario(from arguments: [String] = ProcessInfo.processInfo.arguments)
            -> UITestScenario?
        {
            guard arguments.contains(harnessFlag) else { return nil }
            if let index = arguments.firstIndex(of: scenarioFlag), index + 1 < arguments.count,
                let scenario = UITestScenario(rawValue: arguments[index + 1])
            {
                return scenario
            }
            return .admin
        }
    }

    /// An in-memory `SecretStore`, so the harness never touches the device Keychain.
    public final class InMemorySecretStore: SecretStore, @unchecked Sendable {
        private var items: [String: Data] = [:]
        private let lock = NSLock()

        public init() {}

        public func save(_ data: Data, account: String, accessible: CFString) throws {
            lock.lock()
            defer { lock.unlock() }
            items[account] = data
        }

        public func load(account: String) throws -> Data? {
            lock.lock()
            defer { lock.unlock() }
            return items[account]
        }

        public func delete(account: String) throws {
            lock.lock()
            defer { lock.unlock() }
            items.removeValue(forKey: account)
        }
    }

    /// The fixture's mutable world: one account ("me") in one group with three others. Thread-safe;
    /// `URLProtocol` calls arrive on a background queue.
    public final class GroupAdminFixture: @unchecked Sendable {
        public struct Person: Sendable {
            public let accountID: String
            public let username: String
            public let displayName: String
        }

        struct Member {
            let person: Person
            var isAdmin: Bool
            var mutedUntil: Int?  // nil = not muted; Int.max = indefinite
            var mutedBy: String?
            var isMuted: Bool { mutedUntil != nil }
        }

        public static let me = Person(accountID: "aa" + String(repeating: "0", count: 30), username: "me", displayName: "Me")
        public static let bob = Person(accountID: "bb" + String(repeating: "0", count: 30), username: "bob", displayName: "Bob Ortiz")
        public static let carol = Person(accountID: "cc" + String(repeating: "0", count: 30), username: "carol", displayName: "")
        public static let dave = Person(accountID: "dd" + String(repeating: "0", count: 30), username: "dave", displayName: "Dave K")
        /// A friend of "me" who is NOT in the group, so "Add members" has someone to add.
        public static let erin = Person(accountID: "ee" + String(repeating: "0", count: 30), username: "erin", displayName: "Erin")
        public static let conversationID = "c0" + String(repeating: "1", count: 30)
        public static let deviceID = "d0" + String(repeating: "2", count: 30)

        public let session = NedwonsClient.Session(
            accountID: me.accountID, deviceID: deviceID, accessToken: "uitest-access",
            accessExpiresAt: 9_999_999_999, refreshToken: "uitest-refresh",
            refreshExpiresAt: 9_999_999_999)

        private let lock = NSLock()
        private var members: [Member]
        private var announcementsOnly = false
        private var joinApproval = false
        private var invites: [(token: String, expiresAt: Int, maxUses: Int, uses: Int)] = []
        private var joinRequests: [String] = []
        private var left = false
        /// Every message body the fixture accepted, so a test can assert delivery happened.
        public private(set) var deliveredMessages: [String] = []
        /// Every request line the fixture served (method + path), for assertions on call shape.
        public private(set) var requestLog: [String] = []

        public init(scenario: UITestScenario = .admin) {
            let meIsAdmin = scenario == .admin
            members = [
                Member(person: Self.me, isAdmin: meIsAdmin, mutedUntil: scenario == .muted ? Int.max : nil,
                    mutedBy: scenario == .muted ? Self.bob.accountID : nil),
                Member(person: Self.bob, isAdmin: true, mutedUntil: nil, mutedBy: nil),
                Member(person: Self.carol, isAdmin: false, mutedUntil: nil, mutedBy: nil),
                Member(person: Self.dave, isAdmin: false, mutedUntil: nil, mutedBy: nil),
            ]
            announcementsOnly = scenario == .announcementsOnly
        }

        // MARK: Routing

        struct Response {
            let status: Int
            let json: Any
            static func ok(_ json: Any) -> Response { Response(status: 200, json: json) }
            static var noContent: Response { Response(status: 204, json: [String: Any]()) }
            static func error(_ status: Int, _ code: String) -> Response {
                Response(status: status, json: ["error": code])
            }
        }

        func handle(method: String, path: String, body: [String: Any]) -> Response {
            lock.lock()
            defer { lock.unlock() }
            requestLog.append("\(method) \(path)")
            let conv = "/v1/conversations/\(Self.conversationID)"
            switch (method, path) {
            case ("GET", "/v1/session/whoami"):
                return .ok(["account_id": Self.me.accountID, "device_id": Self.deviceID])
            case ("GET", "/v1/profile"):
                return .ok([
                    "account_id": Self.me.accountID, "username": Self.me.username,
                    "display_name": Self.me.displayName, "bio": "",
                ])
            case ("GET", "/v1/friends"):
                return .ok([Self.bob, Self.carol, Self.erin].map(summary))
            case ("GET", "/v1/friends/requests"), ("GET", "/v1/blocks"):
                return .ok([[String: Any]]())
            case ("GET", "/v1/devices"):
                return .ok([["device_id": Self.deviceID, "revoked": false, "current": true]])
            case ("GET", "/v1/conversations"):
                return .ok(
                    left
                        ? [[String: Any]]()
                        : [[
                            "conversation_id": Self.conversationID,
                            "member_account_ids": members.map(\.person.accountID),
                        ]])
            case ("GET", "\(conv)/group"):
                return groupState()
            case ("POST", "\(conv)/messages"):
                return sendMessage(body)
            case ("POST", "\(conv)/mutes"):
                return mute(body)
            case ("POST", "\(conv)/mutes/remove"):
                return adminOnly { self.setMute(body["account_id"] as? String ?? "", until: nil, by: nil); return .noContent }
            case ("POST", "\(conv)/mutes/clear"):
                return adminOnly {
                    for i in self.members.indices { self.members[i].mutedUntil = nil; self.members[i].mutedBy = nil }
                    return .noContent
                }
            case ("POST", "\(conv)/admins"):
                return adminOnly {
                    guard let i = self.index(body) else { return .error(404, "not_member") }
                    self.members[i].isAdmin = true
                    self.members[i].mutedUntil = nil  // an admin is never muted
                    self.members[i].mutedBy = nil
                    return .noContent
                }
            case ("POST", "\(conv)/admins/demote"):
                return adminOnly {
                    guard let i = self.index(body) else { return .error(404, "not_member") }
                    if self.members[i].isAdmin && self.members.filter(\.isAdmin).count <= 1 {
                        return .error(409, "last_admin")
                    }
                    self.members[i].isAdmin = false
                    return .noContent
                }
            case ("POST", "\(conv)/members"):
                return adminOnly {
                    guard let id = body["account_id"] as? String else { return .error(400, "invalid_input") }
                    guard id == Self.erin.accountID else { return .error(403, "not_friends") }
                    if self.index(body) == nil {
                        self.members.append(Member(person: Self.erin, isAdmin: false, mutedUntil: nil, mutedBy: nil))
                    }
                    return .noContent
                }
            case ("POST", "\(conv)/members/remove"):
                return adminOnly {
                    guard let id = body["account_id"] as? String, id != Self.me.accountID else {
                        return .error(400, "invalid_input")
                    }
                    self.members.removeAll { $0.person.accountID == id }
                    return .noContent
                }
            case ("POST", "\(conv)/settings"):
                return adminOnly {
                    if let on = body["announcements_only"] as? Bool { self.announcementsOnly = on }
                    if let on = body["join_approval"] as? Bool { self.joinApproval = on }
                    return .noContent
                }
            case ("POST", "\(conv)/invites"):
                return adminOnly {
                    let token = (0..<32).map { _ in String(format: "%02x", Int.random(in: 0...255)) }.joined()
                    let invite = (token: token, expiresAt: Int(Date().timeIntervalSince1970) + 7 * 86400,
                        maxUses: 100, uses: 0)
                    self.invites.append(invite)
                    return .ok([
                        "invite_token": token, "expires_at": invite.expiresAt, "max_uses": 100, "uses": 0,
                    ])
                }
            case ("POST", "\(conv)/invites/revoke"):
                return adminOnly {
                    self.invites.removeAll { $0.token == body["invite_token"] as? String }
                    return .noContent
                }
            case ("POST", "\(conv)/requests/approve"), ("POST", "\(conv)/requests/deny"):
                return adminOnly {
                    self.joinRequests.removeAll { $0 == body["account_id"] as? String }
                    return .noContent
                }
            case ("POST", "\(conv)/leave"):
                left = true
                return .noContent
            default:
                return .error(404, "not_found")
            }
        }

        // MARK: Semantics (mirroring services/api)

        private var meMember: Member? { members.first { $0.person.accountID == Self.me.accountID } }

        private func adminOnly(_ body: () -> Response) -> Response {
            guard let me = meMember, me.isAdmin else { return .error(403, "forbidden") }
            return body()
        }

        private func index(_ body: [String: Any]) -> Int? {
            guard let id = body["account_id"] as? String else { return nil }
            return members.firstIndex { $0.person.accountID == id }
        }

        private func setMute(_ id: String, until: Int?, by: String?) {
            guard let i = members.firstIndex(where: { $0.person.accountID == id }) else { return }
            members[i].mutedUntil = until
            members[i].mutedBy = by
        }

        private func mute(_ body: [String: Any]) -> Response {
            adminOnly {
                guard let id = body["account_id"] as? String else { return .error(400, "invalid_input") }
                if id == Self.me.accountID { return .error(400, "invalid_input") }
                guard let i = self.index(body) else { return .error(404, "not_member") }
                if self.members[i].isAdmin { return .error(409, "target_is_admin") }
                let duration = body["duration_secs"] as? Int
                let until = duration.map { Int(Date().timeIntervalSince1970) + max(60, min($0, 365 * 86400)) }
                self.setMute(id, until: until ?? Int.max, by: Self.me.accountID)
                return .noContent
            }
        }

        private func sendMessage(_ body: [String: Any]) -> Response {
            guard let me = meMember else { return .error(403, "forbidden") }
            if me.isMuted { return .error(403, "muted") }
            if announcementsOnly && !me.isAdmin { return .error(403, "announcements_only") }
            if let hex = body["ciphertext"] as? String, let data = Hex.decode(hex) {
                deliveredMessages.append(String(decoding: data, as: UTF8.self))
            }
            return .ok(["delivered": members.count - 1])
        }

        private func groupState() -> Response {
            guard let me = meMember else { return .error(403, "forbidden") }
            let memberJSON: [[String: Any]] = members.map { m in
                var json: [String: Any] = [
                    "account_id": m.person.accountID, "username": m.person.username,
                    "display_name": m.person.displayName, "is_admin": m.isAdmin, "muted": m.isMuted,
                ]
                if let until = m.mutedUntil, until != Int.max { json["mute_expires_at"] = until }
                if let by = m.mutedBy { json["muted_by"] = by }
                return json
            }
            return .ok([
                "conversation_id": Self.conversationID,
                "is_admin": me.isAdmin,
                "can_send": !me.isMuted && (me.isAdmin || !announcementsOnly),
                "join_approval": joinApproval,
                "announcements_only": announcementsOnly,
                "mls_authoritative": false,
                "members": memberJSON,
                "join_requests": me.isAdmin ? joinRequests : [],
                "invites": me.isAdmin
                    ? invites.map {
                        ["invite_token": $0.token, "expires_at": $0.expiresAt, "max_uses": $0.maxUses, "uses": $0.uses]
                    } : [],
            ])
        }

        private func summary(_ p: Person) -> [String: Any] {
            ["account_id": p.accountID, "username": p.username, "display_name": p.displayName]
        }
    }

    /// Serves `GroupAdminFixture` to a `URLSession`. One fixture per process, installed by
    /// `AppModel.uiTestHarness`.
    public final class UITestFixtureProtocol: URLProtocol {
        nonisolated(unsafe) public static var fixture: GroupAdminFixture?

        public override class func canInit(with request: URLRequest) -> Bool {
            request.url?.host == "uitest.invalid"
        }

        public override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

        public override func startLoading() {
            guard let fixture = Self.fixture, let url = request.url else {
                client?.urlProtocol(self, didFailWithError: URLError(.cannotConnectToHost))
                return
            }
            let response = fixture.handle(
                method: request.httpMethod ?? "GET", path: url.path, body: Self.body(of: request))
            let data = (try? JSONSerialization.data(withJSONObject: response.json)) ?? Data()
            let http = HTTPURLResponse(
                url: url, statusCode: response.status, httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"])!
            client?.urlProtocol(self, didReceive: http, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: response.status == 204 ? Data() : data)
            client?.urlProtocolDidFinishLoading(self)
        }

        public override func stopLoading() {}

        /// `URLSession` moves `httpBody` into `httpBodyStream` before a protocol sees the request.
        private static func body(of request: URLRequest) -> [String: Any] {
            var data = request.httpBody ?? Data()
            if data.isEmpty, let stream = request.httpBodyStream {
                stream.open()
                defer { stream.close() }
                var buffer = [UInt8](repeating: 0, count: 4096)
                while stream.hasBytesAvailable {
                    let read = stream.read(&buffer, maxLength: buffer.count)
                    if read <= 0 { break }
                    data.append(buffer, count: read)
                }
            }
            return (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
        }

        public static func session() -> URLSession {
            let config = URLSessionConfiguration.ephemeral
            config.protocolClasses = [UITestFixtureProtocol.self]
            return URLSession(configuration: config)
        }
    }

    extension AppModel {
        /// A model wired to the in-process fixture instead of a server. The launch path is the real
        /// one (`restoreSession` → whoami → initial load), with a stored session and an enrolled
        /// software device key already in place, so the app boots straight into the group.
        @MainActor
        public static func uiTestHarness(scenario: UITestScenario = .admin) -> (AppModel, GroupAdminFixture) {
            let fixture = GroupAdminFixture(scenario: scenario)
            UITestFixtureProtocol.fixture = fixture
            let client = NedwonsClient(
                baseURL: URL(string: "https://uitest.invalid")!, session: UITestFixtureProtocol.session())
            let identity = DeviceIdentity(store: InMemoryDeviceKeyStore(), secureEnclaveAvailable: false)
            _ = try? identity.provision(policy: .allowSoftwareFallback)
            let sessionStore = SessionStore(store: InMemorySecretStore())
            try? sessionStore.save(fixture.session)
            let model = AppModel(client: client, deviceIdentity: identity, sessionStore: sessionStore)
            model.provisionPolicy = .allowSoftwareFallback
            // Enough of a send path for the composer to be exercised: the fixture applies the same
            // mute gate the relay does, and an accepted message becomes a local line.
            model.sendMessageAction = { [weak model] body, conversationID in
                guard let model, let token = model.session?.accessToken else { return }
                _ = try await client.sendMessage(
                    accessToken: token, conversationID: conversationID, ciphertext: Data(body.utf8),
                    idempotencyKey: Data((0..<16).map { _ in UInt8.random(in: 0...255) }))
                let next = UInt64((model.threadLines[conversationID]?.count ?? 0) + 1)
                model.threadLines[conversationID, default: []].append(
                    ThreadLine(id: next, kind: .text(body), mine: true))
            }
            return (model, fixture)
        }
    }
#endif
