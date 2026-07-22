import Foundation
import NedwonsKit

// Live smoke test proving the Swift client interoperates with the real Rust backend over real
// HTTP. Run by scripts/swift_backend_smoke.sh, which boots the server.
//
//   NEDWONS_URL=http://127.0.0.1:8080 swift run --package-path apps/ios/NedwonsKit NedwonsSmoke
//
// Prints SMOKE_OK on success (exit 0) or SMOKE_FAIL: <reason> (exit 1).

@main
struct NedwonsSmoke {
    static func fail(_ reason: String) -> Never {
        FileHandle.standardError.write(Data("SMOKE_FAIL: \(reason)\n".utf8))
        exit(1)
    }

    static func randomName(_ prefix: String) -> String {
        var rnd = [UInt8](repeating: 0, count: 5)
        for i in rnd.indices { rnd[i] = UInt8.random(in: 0 ... 255) }
        return prefix + rnd.map { String(format: "%02x", $0) }.joined()
    }

    static func main() async {
        let urlString = ProcessInfo.processInfo.environment["NEDWONS_URL"]
            ?? "http://127.0.0.1:8080"
        guard let baseURL = URL(string: urlString) else { fail("bad NEDWONS_URL \(urlString)") }

        // Unique username per run so repeated smokes don't collide.
        var rnd = [UInt8](repeating: 0, count: 5)
        for i in rnd.indices { rnd[i] = UInt8.random(in: 0 ... 255) }
        let username = "smoke" + rnd.map { String(format: "%02x", $0) }.joined()
        let password = "battery staple orbit lantern"

        let client = NedwonsClient(baseURL: baseURL)
        // On device this is a SecureEnclaveDeviceSigner; the smoke tool uses the software one.
        let signer = SoftwareDeviceSigner()

        do {
            let registered = try await client.register(
                username: username, password: password, signer: signer
            )
            let who1 = try await client.whoami(accessToken: registered.accessToken)
            guard who1.accountID == registered.accountID else { fail("whoami mismatch after register") }

            let loggedIn = try await client.login(
                username: username, password: password, signer: signer
            )
            guard loggedIn.accountID == registered.accountID else { fail("login account mismatch") }

            let who2 = try await client.whoami(accessToken: loggedIn.accessToken)
            guard who2.deviceID == registered.deviceID else { fail("device mismatch after login") }

            // Negative check: a different device with the SAME credentials must NOT log in
            // (INV-2, device binding) — its signature won't verify against the enrolled key.
            let attacker = SoftwareDeviceSigner()
            do {
                _ = try await client.login(username: username, password: password, signer: attacker)
                fail("a different device logged in with the correct password (INV-2 violated!)")
            } catch let NedwonsClient.ClientError.http(status, _) where status == 401 {
                // expected: denied
            } catch {
                fail("unexpected error on attacker login: \(error)")
            }

            // --- Key transparency (R-201): the client self-monitors its own enrolled key ---
            // In production the log public key is pinned in the app; here we take it from a first
            // STH fetch to demonstrate the verification mechanism end to end.
            let firstSTH = try await client.transparencySignedTreeHead(
                accessToken: registered.accessToken
            )
            guard let pinnedLogKey = Hex.decode(firstSTH.logPublicKey) else {
                fail("transparency: bad log public key")
            }
            let monitor = try await client.selfMonitorKeyTransparency(
                accessToken: registered.accessToken,
                accountID: registered.accountID,
                deviceID: registered.deviceID,
                expectedPublicKeyX963: signer.publicKeyX963,
                pinnedLogPublicKeyX963: pinnedLogKey
            )
            guard monitor == .ok else {
                fail("key-transparency self-monitor did not pass: \(monitor)")
            }

            // --- Social + group + messaging over the live server ---

            // A second real user, Bob.
            let bobSigner = SoftwareDeviceSigner()
            let bob = try await client.register(
                username: randomName("smokebob"), password: password, signer: bobSigner
            )

            // Alice profile update + search finds Bob by username prefix.
            try await client.updateProfile(
                accessToken: registered.accessToken, displayName: "Alice", bio: "smoke"
            )

            // Alice befriends Bob (request + accept).
            let status = try await client.sendFriendRequest(
                accessToken: registered.accessToken, accountID: bob.accountID
            )
            guard status == "requested" else { fail("unexpected friend status: \(status)") }
            try await client.acceptFriend(accessToken: bob.accessToken, accountID: registered.accountID)
            let aliceFriends = try await client.listFriends(accessToken: registered.accessToken)
            guard aliceFriends.contains(where: { $0.accountID == bob.accountID }) else {
                fail("Bob not listed among Alice's friends")
            }

            // Create a group (clique of Alice + Bob), send a message, Bob receives it.
            let group = try await client.createGroup(
                accessToken: registered.accessToken, memberAccountIDs: [bob.accountID]
            )
            let delivered = try await client.sendMessage(
                accessToken: registered.accessToken,
                conversationID: group.conversationID,
                ciphertext: Data("hello-bob".utf8),
                idempotencyKey: Data(repeating: 9, count: 16)
            )
            guard delivered == 1 else { fail("group message delivered to \(delivered), expected 1") }

            let inbox = try await client.fetchInbox(accessToken: bob.accessToken)
            guard inbox.count == 1,
                  let ciphertext = Hex.decode(inbox[0].ciphertext),
                  ciphertext == Data("hello-bob".utf8)
            else {
                fail("Bob did not receive the group message")
            }
            try await client.ackInbox(accessToken: bob.accessToken, ids: [inbox[0].id])

            // The group shows up in both members' conversation lists (Chats tab).
            let aliceConvos = try await client.listConversations(accessToken: registered.accessToken)
            let bobConvos = try await client.listConversations(accessToken: bob.accessToken)
            guard aliceConvos.contains(where: { $0.conversationID == group.conversationID }),
                  bobConvos.contains(where: { $0.conversationID == group.conversationID })
            else {
                fail("group missing from a member's conversation list")
            }

            // Directly listing a NON-friend is refused (ADR-0009: direct add = consent by proxy,
            // so it requires friendship with the adder). Strangers join via invite links instead.
            let strangerSigner = SoftwareDeviceSigner()
            let stranger = try await client.register(
                username: randomName("smokestr"), password: password, signer: strangerSigner
            )
            do {
                _ = try await client.createGroup(
                    accessToken: registered.accessToken,
                    memberAccountIDs: [bob.accountID, stranger.accountID]
                )
                fail("directly adding a non-friend must be refused")
            } catch let NedwonsClient.ClientError.http(status, _) where status == 403 {
                // expected: not_friends
            } catch {
                fail("unexpected error on non-friend direct add: \(error)")
            }

            // The admin (Alice) mints an invite link; the stranger joins by their OWN consent.
            let inviteToken = try await client.createInvite(
                accessToken: registered.accessToken, conversationID: group.conversationID
            )
            let joined = try await client.acceptInvite(
                accessToken: stranger.accessToken, inviteToken: inviteToken
            )
            guard joined.status == "joined", joined.conversationID == group.conversationID else {
                fail("stranger failed to join via invite link")
            }

            // …and then leaves (consent withdrawal): the group disappears from their Chats list
            // but remains for the others.
            try await client.leaveConversation(
                accessToken: stranger.accessToken, conversationID: group.conversationID
            )
            let strangerConvos = try await client.listConversations(accessToken: stranger.accessToken)
            guard !strangerConvos.contains(where: { $0.conversationID == group.conversationID })
            else {
                fail("left conversation still listed for the leaver")
            }
            let aliceConvosAfterLeave = try await client.listConversations(
                accessToken: registered.accessToken
            )
            guard aliceConvosAfterLeave.contains(where: { $0.conversationID == group.conversationID })
            else {
                fail("conversation should remain for the other members")
            }

            // --- Abuse controls: block + report ---

            // Alice blocks Bob → Bob leaves her friends and appears in her block list.
            try await client.blockUser(accessToken: registered.accessToken, accountID: bob.accountID)
            let blockedList = try await client.listBlocked(accessToken: registered.accessToken)
            guard blockedList.contains(where: { $0.accountID == bob.accountID }) else {
                fail("Bob missing from Alice's block list")
            }
            let friendsAfterBlock = try await client.listFriends(accessToken: registered.accessToken)
            guard !friendsAfterBlock.contains(where: { $0.accountID == bob.accountID }) else {
                fail("block did not sever the friendship")
            }

            // With Bob blocked (which also severed the friendship), a new group listing Bob is
            // refused with 403 (not_friends/blocked_member — both gates protect here, ADR-0009).
            do {
                _ = try await client.createGroup(
                    accessToken: registered.accessToken, memberAccountIDs: [bob.accountID]
                )
                fail("a group containing a blocked member must be rejected")
            } catch let NedwonsClient.ClientError.http(status, _) where status == 403 {
                // expected
            } catch {
                fail("unexpected error on blocked-member group: \(error)")
            }

            // A blocked user cannot send a friend request (server enforces, 403).
            do {
                _ = try await client.sendFriendRequest(
                    accessToken: bob.accessToken, accountID: registered.accountID
                )
                fail("a blocked user was able to send a friend request")
            } catch let NedwonsClient.ClientError.http(status, _) where status == 403 {
                // expected: blocked
            } catch {
                fail("unexpected error on blocked friend request: \(error)")
            }

            // Alice reports Bob; evidence is reporter-chosen (the server can't read E2EE content).
            let reportID = try await client.reportUser(
                accessToken: registered.accessToken,
                accountID: bob.accountID,
                reason: "spam",
                evidence: "reporter-chosen excerpt"
            )
            guard reportID >= 1 else { fail("report id not assigned") }

            print("SMOKE_OK")
        } catch {
            fail("\(error)")
        }
    }
}
