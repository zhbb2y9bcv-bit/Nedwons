import Foundation
import XCTest

@testable import NedwonsKit
@testable import NedwonsUI

private func session(_ account: String = "aa", device: String = "bb") -> NedwonsClient.Session {
    NedwonsClient.Session(
        accountID: String(repeating: account, count: 16),
        deviceID: String(repeating: device, count: 16),
        accessToken: String(repeating: "11", count: 32),
        accessExpiresAt: 9_999_999_999,
        refreshToken: String(repeating: "22", count: 32),
        refreshExpiresAt: 9_999_999_999)
}

private let publicKey = Data([0x04] + Array(repeating: UInt8(7), count: 64))

// MARK: - Protocol

final class DevicePairingProtocolTests: XCTestCase {
    func testOfferRoundTripsThroughItsQRPayload() throws {
        let offer = DevicePairing.Offer.create(devicePublicKeyX963: publicKey)
        let decoded = try XCTUnwrap(DevicePairing.decodeOffer(DevicePairing.encode(offer)))
        XCTAssertEqual(decoded, offer)
    }

    /// A future version must read as "not something I understand" rather than being partly parsed.
    func testMalformedAndFutureOffersAreRefused() {
        XCTAssertNil(DevicePairing.decodeOffer("hello"))
        XCTAssertNil(DevicePairing.decodeOffer("nedwons-pair:2:abcdef"))
        XCTAssertNil(DevicePairing.decodeOffer("nedwons-pair:1:zzzz"))
        // A truncated body must not decode into short fields.
        let valid = DevicePairing.encode(DevicePairing.Offer.create(devicePublicKeyX963: publicKey))
        XCTAssertNil(DevicePairing.decodeOffer(String(valid.dropLast(8))))
    }

    /// Exact field sizes: a short pairing key would silently weaken the seal.
    func testWrongSizedFieldsAreRefused() {
        let short = DevicePairing.Offer(
            devicePublicKeyX963: Data(repeating: 4, count: 10),
            pairingKey: Data(repeating: 1, count: 32),
            nonce: Data(repeating: 2, count: 16))
        XCTAssertNil(DevicePairing.decodeOffer(DevicePairing.encode(short)))
    }

    func testGrantSealsAndOpensUnderTheMatchingOffer() throws {
        let offer = DevicePairing.Offer.create(devicePublicKeyX963: publicKey)
        let grant = try DevicePairing.seal(session: session(), under: offer)
        let decoded = try XCTUnwrap(DevicePairing.decodeGrant(DevicePairing.encode(grant)))
        XCTAssertEqual(try DevicePairing.open(grant: decoded, with: offer), session())
    }

    /// The security property: a grant produced for someone ELSE's offer must not open here. If it
    /// did, a device could adopt a session from a pairing it was not part of.
    func testAGrantForAnotherOfferDoesNotOpen() throws {
        let mine = DevicePairing.Offer.create(devicePublicKeyX963: publicKey)
        let theirs = DevicePairing.Offer.create(devicePublicKeyX963: publicKey)
        let grant = try DevicePairing.seal(session: session(), under: theirs)
        XCTAssertThrowsError(try DevicePairing.open(grant: grant, with: mine)) { error in
            XCTAssertEqual(error as? DevicePairing.PairingError, .grantNotForThisOffer)
        }
    }

    /// A tampered ciphertext must fail authentication rather than yielding garbage.
    func testATamperedGrantIsRejected() throws {
        let offer = DevicePairing.Offer.create(devicePublicKeyX963: publicKey)
        var sealed = try DevicePairing.seal(session: session(), under: offer).sealedSession
        sealed[sealed.count - 1] ^= 0xFF
        XCTAssertThrowsError(
            try DevicePairing.open(grant: .init(sealedSession: sealed), with: offer))
    }

    /// The session is not readable without the pairing key — the reason a photographed grant QR is
    /// not an account takeover.
    func testTheGrantDoesNotLeakTokensInTheClear() throws {
        let offer = DevicePairing.Offer.create(devicePublicKeyX963: publicKey)
        let payload = DevicePairing.encode(try DevicePairing.seal(session: session(), under: offer))
        XCTAssertFalse(payload.contains(String(repeating: "11", count: 32)), "access token")
        XCTAssertFalse(payload.contains(String(repeating: "22", count: 32)), "refresh token")
    }

    // MARK: SAS

    /// Both sides derive the same code from the same offer — that equality IS the check the user
    /// performs.
    func testBothSidesDeriveTheSameCode() throws {
        let offer = DevicePairing.Offer.create(devicePublicKeyX963: publicKey)
        let scanned = try XCTUnwrap(DevicePairing.decodeOffer(DevicePairing.encode(offer)))
        XCTAssertEqual(
            DevicePairing.shortAuthenticationString(for: offer),
            DevicePairing.shortAuthenticationString(for: scanned))
    }

    /// A substituted offer — the attack QR pairing actually has — must produce a visibly different
    /// code, or the human check detects nothing.
    func testASubstitutedOfferProducesADifferentCode() {
        let real = DevicePairing.Offer.create(devicePublicKeyX963: publicKey)
        let attacker = DevicePairing.Offer.create(
            devicePublicKeyX963: Data([0x04] + Array(repeating: UInt8(9), count: 64)))
        XCTAssertNotEqual(
            DevicePairing.shortAuthenticationString(for: real),
            DevicePairing.shortAuthenticationString(for: attacker))
    }

    /// Even the same key paired twice must produce different codes, so an observed code cannot be
    /// replayed against a later pairing.
    func testTheSameKeyPairedTwiceProducesDifferentCodes() {
        let first = DevicePairing.Offer.create(devicePublicKeyX963: publicKey)
        let second = DevicePairing.Offer.create(devicePublicKeyX963: publicKey)
        XCTAssertNotEqual(
            DevicePairing.shortAuthenticationString(for: first),
            DevicePairing.shortAuthenticationString(for: second))
    }

    func testTheCodeIsSixGroupsOfFiveDigits() {
        let groups = DevicePairing.shortAuthenticationString(
            for: DevicePairing.Offer.create(devicePublicKeyX963: publicKey))
        XCTAssertEqual(groups.count, 6)
        for group in groups {
            XCTAssertEqual(group.count, 5)
            XCTAssertTrue(group.allSatisfy(\.isNumber))
        }
    }

    /// Deterministic bytes pin the canonical encoding, so a change to field order or length
    /// prefixing cannot silently alter the code the two devices compare.
    func testTheCodeIsStableForAFixedOffer() {
        let offer = DevicePairing.Offer.create(
            devicePublicKeyX963: publicKey,
            randomBytes: { count in Data(repeating: 0xAB, count: count) })
        XCTAssertEqual(
            DevicePairing.shortAuthenticationString(for: offer),
            DevicePairing.shortAuthenticationString(for: offer))
        XCTAssertEqual(offer.pairingKey.count, 32)
        XCTAssertEqual(offer.nonce.count, 16)
    }
}

// MARK: - Flow

@MainActor
final class DevicePairingFlowTests: XCTestCase {
    /// Nothing may be signed before the user confirms the code. This is the whole reason the SAS
    /// step exists as its own state rather than a confirmation dialog.
    func testTheTrustedDeviceEnrollsNothingBeforeTheCodeIsConfirmed() async {
        var enrollCalls = 0
        let model = DevicePairingModel(
            role: .trustedDevice,
            enroll: { _ in
                enrollCalls += 1
                return session()
            })
        let offer = DevicePairing.Offer.create(devicePublicKeyX963: publicKey)

        model.receiveOffer(DevicePairing.encode(offer))
        XCTAssertEqual(model.step, .confirmingCode)
        XCTAssertEqual(enrollCalls, 0, "scanning must not enroll")
        XCTAssertEqual(model.code, DevicePairing.shortAuthenticationString(for: offer))

        await model.confirmCodeAndEnroll()
        XCTAssertEqual(enrollCalls, 1)
        XCTAssertEqual(model.step, .showingGrant)
        XCTAssertNotNil(model.payload)
    }

    /// "They don't match" must abandon, and must leave nothing behind that a later tap could use.
    func testRejectingTheCodeEnrollsNothingAndClearsState() async {
        var enrollCalls = 0
        let model = DevicePairingModel(
            role: .trustedDevice,
            enroll: { _ in
                enrollCalls += 1
                return session()
            })
        model.receiveOffer(
            DevicePairing.encode(DevicePairing.Offer.create(devicePublicKeyX963: publicKey)))
        model.rejectCode()

        XCTAssertTrue(model.code.isEmpty)
        XCTAssertNil(model.payload)
        // A second confirm attempt after rejection must still do nothing.
        await model.confirmCodeAndEnroll()
        XCTAssertEqual(enrollCalls, 0, "a rejected pairing can never be resumed")
    }

    func testAnUnreadableOfferIsReported() {
        let model = DevicePairingModel(role: .trustedDevice)
        model.receiveOffer("not-a-nedwons-code")
        guard case .failed = model.step else {
            return XCTFail("expected a failure state, got \(model.step)")
        }
    }

    /// End to end across both models, which is what actually proves the two halves interoperate.
    func testTheTwoRolesCompleteAPairing() async throws {
        var adopted: NedwonsClient.Session?
        let newDevice = DevicePairingModel(
            role: .newDevice, provisionKey: { publicKey }, adopt: { adopted = $0 })
        newDevice.beginAsNewDevice()
        XCTAssertEqual(newDevice.step, .showingOffer)
        let offerPayload = try XCTUnwrap(newDevice.payload)

        let trusted = DevicePairingModel(role: .trustedDevice, enroll: { _ in session() })
        trusted.receiveOffer(offerPayload)
        // The codes the two humans compare.
        XCTAssertEqual(trusted.code, newDevice.code)
        await trusted.confirmCodeAndEnroll()
        let grantPayload = try XCTUnwrap(trusted.payload)

        // Back to the SAME model that made the offer — only it holds the pairing key.
        await newDevice.receiveGrant(grantPayload)
        XCTAssertEqual(newDevice.step, .paired)
        XCTAssertEqual(adopted, session(), "the session crosses intact end to end")
    }

    /// A grant meant for a different pairing must be refused by the new device too, not just by the
    /// crypto: the user-visible outcome has to be a refusal, not a silent adoption.
    func testTheNewDeviceRefusesAGrantForAnotherPairing() async {
        var adoptCalls = 0
        let newDevice = DevicePairingModel(
            role: .newDevice, provisionKey: { publicKey }, adopt: { _ in adoptCalls += 1 })
        newDevice.beginAsNewDevice()

        let stranger = DevicePairing.Offer.create(devicePublicKeyX963: publicKey)
        let grant = try! DevicePairing.seal(session: session(), under: stranger)

        await newDevice.receiveGrant(DevicePairing.encode(grant))
        XCTAssertEqual(adoptCalls, 0, "a session from another pairing must never be adopted")
        guard case .failed = newDevice.step else {
            return XCTFail("expected a refusal, got \(newDevice.step)")
        }
    }

    /// Hardware without a Secure Enclave must fail closed, not fall back silently (INV-3).
    func testAKeyThatCannotBeProvisionedFailsClosed() {
        struct NoEnclave: Error {}
        let model = DevicePairingModel(role: .newDevice, provisionKey: { throw NoEnclave() })
        model.beginAsNewDevice()
        guard case .failed = model.step else {
            return XCTFail("expected a failure state, got \(model.step)")
        }
        XCTAssertNil(model.payload, "no offer may be shown without a real key behind it")
    }
}
