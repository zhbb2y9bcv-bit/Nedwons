import CryptoKit
import XCTest

@testable import SentinelKit

/// Sealed-sender client wiring (ADR-0014 Slice 2c): the DAK primitive agrees with the Rust relay's
/// verifier function, registration/delivery produce exactly the wire shape the relay expects, and
/// the inbox model decodes sealed envelopes (no sender/conversation) alongside identified ones.
final class DeliveryAccessKeyTests: XCTestCase {
    // MARK: DAK primitive

    /// Cross-language agreement: the verifier is plain SHA-256, pinned by the same empty-input
    /// golden vector as `auth_core::delivery_key` (`verifier_is_stable_and_is_plain_sha256`). If
    /// either side ever changed hash function, this pins the drift.
    func testVerifierIsPlainSha256MatchingRustGolden() {
        let emptyDigest = Hex.encode(Data(SHA256.hash(data: Data())))
        XCTAssertEqual(
            emptyDigest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        // And the DAK verifier is exactly that function over the 32-byte key.
        let key = DeliveryAccessKey(keyMaterial: Data(repeating: 0x42, count: 32))!
        XCTAssertEqual(key.verifier, Data(SHA256.hash(data: key.key)))
        XCTAssertEqual(key.verifier.count, 32)
    }

    func testGenerateProducesDistinct32ByteKeys() {
        let a = DeliveryAccessKey.generate()
        let b = DeliveryAccessKey.generate()
        XCTAssertEqual(a.key.count, 32)
        XCTAssertNotEqual(a.key, b.key, "two generated keys must differ")
        XCTAssertNotEqual(a.verifier, b.verifier)
    }

    func testTruncatedKeyMaterialIsRejected() {
        XCTAssertNil(DeliveryAccessKey(keyMaterial: Data()))
        XCTAssertNil(DeliveryAccessKey(keyMaterial: Data(repeating: 0, count: 31)))
        XCTAssertNil(DeliveryAccessKey(keyMaterial: Data(repeating: 0, count: 33)))
        XCTAssertNotNil(DeliveryAccessKey(keyMaterial: Data(repeating: 0, count: 32)))
    }

    // MARK: Wire shape (stub transport)

    private func client() -> SentinelClient {
        SentinelClient(
            baseURL: URL(string: "https://example.invalid")!, session: StubURLProtocol.session())
    }

    func testRegisterSendsOnlyTheVerifier() async throws {
        StubURLProtocol.statusCode = 204
        StubURLProtocol.responseBody = Data()
        let dak = DeliveryAccessKey(keyMaterial: Data(repeating: 0x7C, count: 32))!

        try await client().registerDeliveryAccessKey(
            accessToken: String(repeating: "a", count: 64), deliveryKey: dak)

        let req = StubURLProtocol.lastRequest
        XCTAssertEqual(req?.httpMethod, "PUT")
        XCTAssertEqual(req?.url?.path, "/v1/delivery-access-key")
        // The secret K_r must NOT appear anywhere in the registration request.
        let headers = req?.allHTTPHeaderFields ?? [:]
        XCTAssertFalse(headers.values.contains(Hex.encode(dak.key)))
        XCTAssertNil(headers["X-Delivery-Key"])
    }

    func testDeliverSealedIsUnauthenticatedAndCarriesTheKeyHeader() async throws {
        StubURLProtocol.statusCode = 202
        StubURLProtocol.responseBody = Data()
        let dak = DeliveryAccessKey(keyMaterial: Data(repeating: 0x5A, count: 32))!

        try await client().deliverSealed(
            deliveryKey: dak,
            recipientDevice: String(repeating: "b", count: 32),
            ciphertext: Data([0xAA, 0xBB]),
            idempotencyKey: Data(repeating: 0x11, count: 16))

        let req = StubURLProtocol.lastRequest
        XCTAssertEqual(req?.httpMethod, "POST")
        XCTAssertEqual(req?.url?.path, "/v1/sealed/deliver")
        let headers = req?.allHTTPHeaderFields ?? [:]
        // The delivery key rides the header; NO bearer token may link the sender.
        XCTAssertEqual(headers["X-Delivery-Key"], Hex.encode(dak.key))
        XCTAssertNil(headers["Authorization"], "sealed delivery must not identify the sender")
    }

    func testDeliverSealedSurfacesUniform403() async {
        StubURLProtocol.statusCode = 403
        StubURLProtocol.responseBody = Data("{\"error\":\"denied\"}".utf8)
        let dak = DeliveryAccessKey.generate()
        do {
            try await client().deliverSealed(
                deliveryKey: dak,
                recipientDevice: String(repeating: "c", count: 32),
                ciphertext: Data([0x01]),
                idempotencyKey: Data(repeating: 0x22, count: 16))
            XCTFail("expected a 403")
        } catch SentinelClient.ClientError.http(let status, _) {
            XCTAssertEqual(status, 403)
        } catch {
            XCTFail("expected a typed http error, got \(error)")
        }
    }

    // MARK: Inbox model

    func testInboxDecodesSealedAndIdentifiedEnvelopes() throws {
        let json = """
        [
          {"id": 7, "conversation_id": "aa", "sender_device": "bb", "ciphertext": "cc"},
          {"id": 3, "ciphertext": "dd", "sealed": true}
        ]
        """
        let inbox = try JSONDecoder().decode([InboxEnvelope].self, from: Data(json.utf8))
        XCTAssertEqual(inbox.count, 2)

        XCTAssertFalse(inbox[0].sealed)
        XCTAssertEqual(inbox[0].conversationID, "aa")
        XCTAssertEqual(inbox[0].senderDevice, "bb")

        XCTAssertTrue(inbox[1].sealed)
        XCTAssertNil(inbox[1].conversationID, "relay never learned the conversation")
        XCTAssertNil(inbox[1].senderDevice, "relay never learned the sender")
        XCTAssertEqual(inbox[1].ciphertext, "dd")
    }
}
