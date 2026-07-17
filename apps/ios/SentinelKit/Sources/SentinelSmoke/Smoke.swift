import Foundation
import SentinelKit

// Live end-to-end smoke test: registers a device, logs in, and calls whoami against a
// running sentinel-api server. Proves the Swift client interoperates with the real Rust
// backend over real HTTP. Run by scripts/swift_backend_smoke.sh, which boots the server.
//
//   SENTINEL_URL=http://127.0.0.1:8080 swift run --package-path apps/ios/SentinelKit SentinelSmoke
//
// Prints SMOKE_OK on success (exit 0) or SMOKE_FAIL: <reason> (exit 1).

@main
struct SentinelSmoke {
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
        let urlString = ProcessInfo.processInfo.environment["SENTINEL_URL"]
            ?? "http://127.0.0.1:8080"
        guard let baseURL = URL(string: urlString) else { fail("bad SENTINEL_URL \(urlString)") }

        // Unique username per run so repeated smokes don't collide.
        var rnd = [UInt8](repeating: 0, count: 5)
        for i in rnd.indices { rnd[i] = UInt8.random(in: 0 ... 255) }
        let username = "smoke" + rnd.map { String(format: "%02x", $0) }.joined()
        let password = "battery staple orbit lantern"

        let client = SentinelClient(baseURL: baseURL)
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
            } catch let SentinelClient.ClientError.http(status, _) where status == 401 {
                // expected: denied
            } catch {
                fail("unexpected error on attacker login: \(error)")
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

            // A group including a NON-friend must be rejected (clique gate).
            let strangerSigner = SoftwareDeviceSigner()
            let stranger = try await client.register(
                username: randomName("smokestr"), password: password, signer: strangerSigner
            )
            do {
                _ = try await client.createGroup(
                    accessToken: registered.accessToken,
                    memberAccountIDs: [bob.accountID, stranger.accountID]
                )
                fail("a group with a non-friend must be rejected (clique gate)")
            } catch let SentinelClient.ClientError.http(status, _) where status == 403 {
                // expected: not_all_friends
            } catch {
                fail("unexpected error on non-friend group: \(error)")
            }

            print("SMOKE_OK")
        } catch {
            fail("\(error)")
        }
    }
}
