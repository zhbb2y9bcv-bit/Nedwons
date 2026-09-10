import Foundation
import MlsFfi
import NedwonsAppKit
import NedwonsKit
import NedwonsUI

// Live end-to-end run for MLS-commit-authoritative membership (ADR-0010, R-506), over the FULL
// shipping stack: the real `ConversationCoordinator` (the app's messaging pipeline) driving the real
// `NedwonsClient` over real HTTP against a running `nedwons-api`, with the real Rust MLS core
// underneath. No test doubles anywhere in the path.
//
// What it proves, with real MLS bytes and real signatures crossing the real relay:
//
//   1. an authoritative group starts with ONLY its creator routed — everyone else is a membership
//      intent, which grants nothing;
//   2. the creator's ordinary reconcile pass turns an intent into routing by posting a
//      device-signed manifest + commit, and the server's epoch CAS accepts exactly one;
//   3. the added member redeems the Welcome and real application traffic flows;
//   4. an EXISTING member receiving a later add-commit verifies it against the live transparency
//      log — signed tree head under the pinned key, the actor's device binding included under the
//      signed root, the manifest signature under THAT key — and the correspondence check, before
//      merging. This is the half that cannot be faked in a unit test;
//   5. an authorized removal cuts the removed member's delivery.
//
// Booted by scripts/authoritative_live_run.sh. Prints LIVE_OK (exit 0) or LIVE_FAIL: <reason> (1).

@main
struct AuthoritativeLiveRun {
    static func fail(_ reason: String) -> Never {
        FileHandle.standardError.write(Data("LIVE_FAIL: \(reason)\n".utf8))
        exit(1)
    }

    static func rnd(_ n: Int) -> Data {
        var b = [UInt8](repeating: 0, count: n)
        for i in b.indices { b[i] = .random(in: 0 ... 255) }
        return Data(b)
    }

    static func name(_ prefix: String) -> String {
        prefix + rnd(5).map { String(format: "%02x", $0) }.joined()
    }

    static let password = "battery staple orbit lantern"
    /// No Keychain in a CLI harness; a device uses `KeychainStore`.
    static let keys = AtRestKeyHierarchy(store: InMemorySecretStore())

    /// One participant: a real account, a real enrolled signer, and the real app pipeline.
    @MainActor
    struct Peer {
        let name: String
        let signer: SoftwareDeviceSigner
        let session: NedwonsClient.Session
        let model: AppModel
        let coordinator: ConversationCoordinator

        var accountID: String { session.accountID }
        var deviceID: String { session.deviceID }
        var token: String { session.accessToken }

        init(_ name: String, baseURL: URL, pinnedLogKey: @escaping @Sendable () async throws -> Data)
            async throws
        {
            self.name = name
            signer = SoftwareDeviceSigner()
            let client = NedwonsClient(baseURL: baseURL)
            session = try await client.register(
                username: AuthoritativeLiveRun.name(name), password: AuthoritativeLiveRun.password,
                signer: signer)
            model = AppModel(client: client)
            model.session = session
            let directory = URL(fileURLWithPath: NSTemporaryDirectory())
                .appendingPathComponent("authlive-\(name)-\(UUID().uuidString)", isDirectory: true)
            let signerForClosure = signer
            coordinator = ConversationCoordinator(
                model: model, relay: client, storeDirectory: directory,
                keyProvider: { try AuthoritativeLiveRun.keys.atRestKey(forStore: $0) },
                minimumKeyPackages: 2)
            coordinator.membershipSignerProvider = { signerForClosure }
            coordinator.pinnedLogKeyProvider = pinnedLogKey
            coordinator.attach(aliasStore: nil)
        }

        func texts(in conversation: String) -> [String] {
            (model.threadLines[conversation] ?? []).compactMap { line in
                if case .text(let t) = line.kind { return t }
                return nil
            }
        }
    }

    static func main() async {
        let urlString = ProcessInfo.processInfo.environment["NEDWONS_URL"] ?? "http://127.0.0.1:8080"
        guard let baseURL = URL(string: urlString) else { fail("bad NEDWONS_URL \(urlString)") }
        let client = NedwonsClient(baseURL: baseURL)

        do {
            try await run(baseURL: baseURL, client: client)
        } catch {
            fail("threw: \(error)")
        }
        print("LIVE_OK")
    }

    @MainActor
    static func run(baseURL: URL, client: NedwonsClient) async throws {
        // The pinned transparency-log key, trust-on-first-use from this live server — the anchor
        // every recipient verification below is rooted in.
        let bootstrapSession = try await client.register(
            username: name("authpin"), password: password, signer: SoftwareDeviceSigner())
        let sth = try await client.transparencySignedTreeHead(
            accessToken: bootstrapSession.accessToken)
        guard let logKey = Hex.decode(sth.logPublicKey) else { fail("bad log public key") }
        let pinnedLogKey: @Sendable () async throws -> Data = { logKey }

        let alice = try await Peer("authalice", baseURL: baseURL, pinnedLogKey: pinnedLogKey)
        let bob = try await Peer("authbob", baseURL: baseURL, pinnedLogKey: pinnedLogKey)
        let carol = try await Peer("authcarol", baseURL: baseURL, pinnedLogKey: pinnedLogKey)

        // ADR-0009: listing someone in a group is a direct add, so the creator must be friends with
        // each of them. This is the consent check that mints the intents.
        for peer in [bob, carol] {
            _ = try await client.sendFriendRequest(
                accessToken: alice.token, accountID: peer.accountID)
            try await client.acceptFriend(accessToken: peer.token, accountID: alice.accountID)
        }
        // Prekeys, so a commit can actually add them.
        await bob.coordinator.ensureKeyPackages()
        await carol.coordinator.ensureKeyPackages()

        // --- 1. An authoritative group routes ONLY its creator -------------------------------
        let created = try await client.createGroup(
            accessToken: alice.token, memberAccountIDs: [bob.accountID], mlsAuthoritative: true)
        let conv = created.conversationID
        guard try await client.conversationEpoch(accessToken: alice.token, conversationID: conv) == 0
        else { fail("a new authoritative group must start at epoch 0") }
        // Bob is authorized but NOT a member: he cannot even read the epoch.
        do {
            _ = try await client.conversationEpoch(accessToken: bob.token, conversationID: conv)
            fail("bob must not be routed before a commit adds him")
        } catch NedwonsClient.ClientError.http(let status, _) where status == 403 {
            // expected
        }

        // --- 2. The reconcile pass turns the intent into routing, by signed commit -------------
        try await alice.coordinator.bootstrap(conversationID: conv, memberAccountIDs: [])
        await alice.coordinator.reconcileSetup()
        let epochAfterAdd = try await client.conversationEpoch(
            accessToken: alice.token, conversationID: conv)
        guard epochAfterAdd == 1 else { fail("expected epoch 1 after the add commit, got \(epochAfterAdd)") }
        guard (try? await client.conversationEpoch(accessToken: bob.token, conversationID: conv)) == 1
        else { fail("bob should be routed at epoch 1 after the commit") }

        // --- 3. Real traffic over the commit-created routing ------------------------------------
        _ = try await bob.coordinator.syncOnce()
        await alice.model.sendMessage("hello over a committed membership", to: conv)
        _ = try await bob.coordinator.syncOnce()
        guard bob.texts(in: conv).contains("hello over a committed membership") else {
            fail("bob did not receive the first message; got \(bob.texts(in: conv))")
        }

        // --- 4. An existing member verifies a LATER commit against the live log -----------------
        // Carol is authorized through the consent-checked endpoint, then added by Alice's commit.
        try await client.addGroupMember(
            accessToken: alice.token, conversationID: conv, accountID: carol.accountID)
        await alice.coordinator.reconcileSetup()
        let epochAfterCarol = try await client.conversationEpoch(
            accessToken: alice.token, conversationID: conv)
        guard epochAfterCarol == 2 else { fail("expected epoch 2, got \(epochAfterCarol)") }

        // Bob is the one that matters: he must fetch the manifest, verify the signed tree head under
        // the pinned key, verify Alice's device binding is included under the signed root, verify her
        // signature under THAT key, and require the commit's real adds to equal the manifest's —
        // before merging. All against the live server.
        _ = try await bob.coordinator.syncOnce()
        guard bob.model.securityNotice == nil else {
            fail("an honest commit must not raise a security notice: \(bob.model.securityNotice!)")
        }
        _ = try await carol.coordinator.syncOnce()
        await alice.model.sendMessage("carol can read this", to: conv)
        _ = try await bob.coordinator.syncOnce()
        _ = try await carol.coordinator.syncOnce()
        guard bob.texts(in: conv).contains("carol can read this") else {
            fail("bob fell out of sync after verifying the add-commit: \(bob.texts(in: conv))")
        }
        guard carol.texts(in: conv).contains("carol can read this") else {
            fail("carol did not join the group properly: \(carol.texts(in: conv))")
        }

        // --- 5. An authorized removal cuts delivery ---------------------------------------------
        try await client.removeGroupMember(
            accessToken: alice.token, conversationID: conv, accountID: carol.accountID)
        await alice.coordinator.reconcileSetup()
        let epochAfterRemoval = try await client.conversationEpoch(
            accessToken: alice.token, conversationID: conv)
        guard epochAfterRemoval == 3 else {
            fail("expected epoch 3 after the remove commit, got \(epochAfterRemoval)")
        }
        do {
            _ = try await client.conversationEpoch(accessToken: carol.token, conversationID: conv)
            fail("carol must be out of routing after the remove commit")
        } catch NedwonsClient.ClientError.http(let status, _) where status == 403 {
            // expected
        }
        _ = try await bob.coordinator.syncOnce()
        await alice.model.sendMessage("after carol was removed", to: conv)
        _ = try await bob.coordinator.syncOnce()
        _ = try await carol.coordinator.syncOnce()
        guard bob.texts(in: conv).contains("after carol was removed") else {
            fail("bob lost sync across the remove commit: \(bob.texts(in: conv))")
        }
        guard !carol.texts(in: conv).contains("after carol was removed") else {
            fail("a removed member still received mail")
        }
    }
}
