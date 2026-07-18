import Foundation
import MlsFfi
import SentinelKit

// Live end-to-end run (ADR-0015 option 3): the REAL Swift app stack — `SentinelClient` over real
// HTTP + `MlsClient` over the real Rust MLS core — driven against a running `sentinel-api` server.
// It proves, with real MLS bytes crossing the real relay:
//
//   1. auth: register + trusted-device enrollment (ADR-0008),
//   2. a real secret delivered sender -> phone through a conversation (the phone holds it sealed),
//   3. self-group establishment phone <-> tablet: real `addSelfDevice` Welcome delivered over
//      /v1/self-group/deliver, and the tablet ACTUALLY `joinSelfGroup`s it (real MLS Welcome
//      survives the live round trip),
//   4. the consumption round trip: the phone reveals, produces a real `SecretConsumed` envelope,
//      fans it out over the live self-group, and the tablet DECRYPTS it with its real self-group
//      ratchet (`processSelfInbound` -> SecretConsumedRemotely) — while the sender never receives it.
//
// Booted by scripts/self_group_live_run.sh. Prints LIVE_OK (exit 0) or LIVE_FAIL: <reason> (exit 1).
//
// Honest scope: the phone (not the tablet) holds the original secret here — seeding BOTH of an
// account's devices with the SAME secret needs multi-device conversation membership (the
// MLS-authoritative commit path), which is objective #3. This run proves the self-group control
// channel end to end over the live relay; #3 makes the tablet consume its own held copy.

@main
struct SelfGroupLiveRun {
    static func fail(_ reason: String) -> Never {
        FileHandle.standardError.write(Data("LIVE_FAIL: \(reason)\n".utf8))
        exit(1)
    }


    static func rnd(_ n: Int) -> Data {
        var b = [UInt8](repeating: 0, count: n)
        for i in b.indices { b[i] = .random(in: 0 ... 255) }
        return Data(b)
    }

    static func name(_ prefix: String) -> String { prefix + rnd(5).map { String(format: "%02x", $0) }.joined() }

    static func tmpDB(_ tag: String) -> String {
        NSTemporaryDirectory() + "live-\(tag)-\(UUID().uuidString)"
    }

    static let password = "battery staple orbit lantern"

    // At-rest keys are HKDF-derived from a Keychain-held root (#5). This CLI harness has no Keychain,
    // so it uses the in-memory store; a device uses `KeychainStore`. Each store gets an independent key.
    static let keys = AtRestKeyHierarchy(store: InMemorySecretStore())

    static func main() async {
        let urlString = ProcessInfo.processInfo.environment["SENTINEL_URL"] ?? "http://127.0.0.1:8080"
        guard let baseURL = URL(string: urlString) else { fail("bad SENTINEL_URL \(urlString)") }
        let client = SentinelClient(baseURL: baseURL)

        do {
            // --- 1. Accounts + devices over live HTTP -------------------------------------------
            // Sender S (a different account).
            let sSigner = SoftwareDeviceSigner()
            let s = try await client.register(username: name("lives"), password: password, signer: sSigner)
            // Recipient account R, primary device "phone".
            let phoneSigner = SoftwareDeviceSigner()
            let r = try await client.register(username: name("liver"), password: password, signer: phoneSigner)
            // Enroll device "tablet" onto R (trusted-device ceremony; phone authorizes it).
            let tabletSigner = SoftwareDeviceSigner()
            let tablet = try await client.enrollDevice(
                accessToken: r.accessToken, accountID: r.accountID,
                trustedSigner: phoneSigner, newDevicePublicKeyX963: tabletSigner.publicKeyX963)
            guard tablet.accountID == r.accountID, tablet.deviceID != r.deviceID else {
                fail("tablet enrollment produced a wrong identity")
            }

            // S and R must be friends for S to add R to a conversation (ADR-0009).
            _ = try await client.sendFriendRequest(accessToken: s.accessToken, accountID: r.accountID)
            try await client.acceptFriend(accessToken: r.accessToken, accountID: s.accountID)

            // --- 2. Real MLS clients ------------------------------------------------------------
            let sMls = try MlsClient.createGroup(
                identity: Data("s-mls".utf8), dbPath: tmpDB("s"),
                atRestKey: try keys.atRestKey(forStore: "s"))
            let phoneMls = try MlsClient.newJoiner(
                identity: Data("phone-mls".utf8), dbPath: tmpDB("phone"),
                atRestKey: try keys.atRestKey(forStore: "phone"))
            // The tablet holds its own durable session (so it is Active and can carry a self-group).
            let tabletMls = try MlsClient.createGroup(
                identity: Data("tablet-mls".utf8), dbPath: tmpDB("tablet"),
                atRestKey: try keys.atRestKey(forStore: "tablet"))

            // Phone publishes a key package so S can add it.
            try await client.publishKeyPackage(accessToken: r.accessToken, keyPackage: try phoneMls.keyPackage())

            // --- 3. S delivers a real secret to the phone over a conversation -------------------
            let phoneClaim = try await client.claimKeyPackage(accessToken: s.accessToken, accountID: r.accountID)
            guard phoneClaim.deviceID == r.deviceID, let phoneKP = Hex.decode(phoneClaim.keyPackage) else {
                fail("claimed the wrong device's key package")
            }
            let addPhone = try sMls.addMember(keyPackage: phoneKP)  // MLS: S -> {S, phone}
            let group = try await client.createGroup(accessToken: s.accessToken, memberAccountIDs: [r.accountID])
            try await client.sendWelcome(
                accessToken: s.accessToken, conversationID: group.conversationID,
                recipientDevice: r.deviceID, ciphertext: addPhone.welcome, idempotencyKey: rnd(16))

            let secretText = "the vault code is 7788"
            let secret = try sMls.enqueueSecret(body: Data(secretText.utf8))
            let secretEnv = try sMls.encrypt(localId: secret.localId)
            try sMls.markSent(localId: secret.localId)
            let delivered = try await client.sendMessage(
                accessToken: s.accessToken, conversationID: group.conversationID,
                ciphertext: secretEnv, idempotencyKey: rnd(16))
            guard delivered == 1 else { fail("secret fanned out to \(delivered), expected 1") }

            // Phone pulls the Welcome (joins S's group) then the secret (holds it sealed).
            let phoneInbox = try await client.fetchInbox(accessToken: r.accessToken)
            let identified = phoneInbox.filter { !$0.selfGroup && !$0.sealed }.sorted { $0.id < $1.id }
            guard identified.count == 2, let welcomeBytes = Hex.decode(identified[0].ciphertext),
                let secretBytes = Hex.decode(identified[1].ciphertext)
            else { fail("phone inbox expected welcome+secret, got \(phoneInbox.count)") }
            try phoneMls.joinGroup(welcome: welcomeBytes)
            switch try phoneMls.processInbound(envelopeId: UInt64(identified[1].id), ciphertext: secretBytes) {
            case .secretSealed(let sid):
                guard sid == secret.secretId else { fail("phone sealed a different secret id") }
            case let other: fail("phone expected SecretSealed, got \(other)")
            }
            try await client.ackInbox(accessToken: r.accessToken, ids: identified.map { $0.id })

            // --- 4. Self-group establishment over the live relay -------------------------------
            try phoneMls.createSelfGroup()
            try await client.registerSelfGroupMember(accessToken: r.accessToken)
            try await client.publishKeyPackage(accessToken: tablet.accessToken, keyPackage: try tabletMls.keyPackage())

            let pending = try await client.pendingSelfGroupDevices(accessToken: r.accessToken)
            guard pending.contains(tablet.deviceID) else { fail("tablet not listed as a pending sibling") }
            let sgClaim = try await client.claimSelfGroupKeyPackage(accessToken: r.accessToken, deviceID: tablet.deviceID)
            guard sgClaim.deviceID == tablet.deviceID, let tabletKP = Hex.decode(sgClaim.keyPackage) else {
                fail("self-group claim returned the wrong device")
            }
            let addTablet = try phoneMls.addSelfDevice(keyPackage: tabletKP)  // real MLS Welcome
            let sgDelivered = try await client.deliverSelfGroup(
                accessToken: r.accessToken, recipientDevice: tablet.deviceID,
                ciphertext: addTablet.welcome, idempotencyKey: rnd(16))
            guard sgDelivered == 1 else { fail("self-group welcome delivered to \(sgDelivered)") }

            // Tablet pulls the Welcome from the self-group channel and ACTUALLY joins it.
            let tabletInbox1 = try await client.fetchInbox(accessToken: tablet.accessToken)
            let sgWelcomes = tabletInbox1.filter { $0.selfGroup }
            guard sgWelcomes.count == 1, let sgWelcomeBytes = Hex.decode(sgWelcomes[0].ciphertext) else {
                fail("tablet did not receive exactly one self-group Welcome")
            }
            try tabletMls.joinSelfGroup(welcome: sgWelcomeBytes)
            try await client.registerSelfGroupMember(accessToken: tablet.accessToken)
            try await client.ackInbox(accessToken: tablet.accessToken, ids: [], selfGroupIds: sgWelcomes.map { $0.id })
            guard try phoneMls.hasSelfGroup(), try tabletMls.hasSelfGroup() else {
                fail("self-group not established on both devices")
            }

            // --- 5. Consumption round trip over the live self-group ----------------------------
            try phoneMls.beginSecretReveal(secretId: secret.secretId, nowMs: 0)
            guard let consumption = try phoneMls.secretConsumptionEnvelope(secretId: secret.secretId) else {
                fail("phone produced no consumption envelope after revealing")
            }
            let fanned = try await client.deliverSelfGroup(
                accessToken: r.accessToken, recipientDevice: nil,
                ciphertext: consumption, idempotencyKey: rnd(16))
            guard fanned == 1 else { fail("consumption fanned out to \(fanned), expected 1 (tablet)") }

            // Tablet decrypts the consumption control message with its real self-group ratchet.
            let tabletInbox2 = try await client.fetchInbox(accessToken: tablet.accessToken)
            let sgConsume = tabletInbox2.filter { $0.selfGroup }
            guard sgConsume.count == 1, let consumeBytes = Hex.decode(sgConsume[0].ciphertext) else {
                fail("tablet did not receive the consumption message")
            }
            switch try tabletMls.processSelfInbound(envelopeId: UInt64(sgConsume[0].id), ciphertext: consumeBytes) {
            case .secretConsumedRemotely(let sid):
                guard sid == secret.secretId else { fail("consumption carried a different secret id") }
            case let other: fail("tablet expected SecretConsumedRemotely, got \(other)")
            }
            try await client.ackInbox(accessToken: tablet.accessToken, ids: [], selfGroupIds: sgConsume.map { $0.id })

            // --- 6. The sender never receives the read signal ---------------------------------
            let senderInbox = try await client.fetchInbox(accessToken: s.accessToken)
            guard !senderInbox.contains(where: { $0.selfGroup }) else {
                fail("the sender received a self-group message it must never see")
            }

            print("LIVE_OK")
        } catch {
            fail("\(error)")
        }
    }
}
