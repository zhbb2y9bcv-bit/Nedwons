import CryptoKit
import XCTest
@testable import NedwonsKit

/// A `URLProtocol` that returns one canned response for any request, so client decoding/verification
/// can be tested without a live server.
final class StubURLProtocol: URLProtocol {
    nonisolated(unsafe) static var responseBody: Data = Data()
    nonisolated(unsafe) static var statusCode: Int = 200
    /// The most recent request, for asserting method/path/headers a client call produced.
    nonisolated(unsafe) static var lastRequest: URLRequest?

    override class func canInit(with request: URLRequest) -> Bool {
        lastRequest = request
        return true
    }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let response = HTTPURLResponse(
            url: request.url!, statusCode: Self.statusCode, httpVersion: nil,
            headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Self.responseBody)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}

    static func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        return URLSession(configuration: config)
    }
}

/// Unit tests for the client that don't need a live server. The full happy-path flow is
/// covered by the `NedwonsSmoke` executable driven against a real backend
/// (scripts/swift_backend_smoke.sh).
final class NedwonsClientTests: XCTestCase {
    /// A connection to a closed port surfaces as a transport error, not a crash — the app
    /// must present this as a recoverable offline state.
    func testTransportErrorWhenServerUnreachable() async {
        // Port 1 is not listening; connection is refused promptly.
        let client = NedwonsClient(baseURL: URL(string: "http://127.0.0.1:1")!)
        do {
            _ = try await client.register(
                username: "nobody",
                password: "battery staple orbit lantern",
                signer: SoftwareDeviceSigner()
            )
            XCTFail("expected a transport error")
        } catch NedwonsClient.ClientError.transport {
            // expected
        } catch {
            XCTFail("expected transport error, got \(error)")
        }
    }

    /// `fetchSenderCertificate` decodes the issuance response into an `IssuedSenderCertificate`
    /// whose signature verifies under the returned cert key and fails under a different key
    /// (ADR-0012 Slice 1b).
    func testFetchSenderCertificateDecodesAndVerifies() async throws {
        // Server-side: a cert signed by a known sender-cert key over the canonical encoding.
        let certKey = P256.Signing.PrivateKey()
        let accountID = Data(repeating: 0x11, count: 16)
        let deviceID = Data(repeating: 0x22, count: 16)
        var senderPub = Data([0x04])
        senderPub.append(Data((0..<64).map { UInt8($0) }))
        let expiresAt: UInt64 = 4_000_000_000
        let cert = SenderCertificate(
            accountID: accountID, deviceID: deviceID, senderPublicKeyX963: senderPub,
            expiresAt: expiresAt)
        let signature = try certKey.signature(for: cert.canonicalBytes())
        let certPub = certKey.publicKey.x963Representation

        let json: [String: Any] = [
            "account_id": accountID.map { String(format: "%02x", $0) }.joined(),
            "device_id": deviceID.map { String(format: "%02x", $0) }.joined(),
            "sender_public_key": senderPub.map { String(format: "%02x", $0) }.joined(),
            "expires_at": expiresAt,
            "signature": signature.rawRepresentation.map { String(format: "%02x", $0) }.joined(),
            "cert_public_key": certPub.map { String(format: "%02x", $0) }.joined(),
        ]
        StubURLProtocol.statusCode = 200
        StubURLProtocol.responseBody = try JSONSerialization.data(withJSONObject: json)

        let client = NedwonsClient(
            baseURL: URL(string: "https://example.invalid")!, session: StubURLProtocol.session())
        let issued = try await client.fetchSenderCertificate(accessToken: String(repeating: "a", count: 64))

        XCTAssertEqual(issued.certificate.accountID, accountID)
        XCTAssertEqual(issued.certificate.senderPublicKeyX963, senderPub)
        XCTAssertTrue(issued.isFresh(now: 1_700_000_000))
        // Verifies under the returned (== the signing) cert key...
        XCTAssertTrue(issued.verify(pinnedCertPublicKeyX963: certPub, now: 1_700_000_000))
        // ...and fails under a different pinned key (a substituted issuer is rejected).
        let otherPub = P256.Signing.PrivateKey().publicKey.x963Representation
        XCTAssertFalse(issued.verify(pinnedCertPublicKeyX963: otherPub, now: 1_700_000_000))
        // ...and fails once expired.
        XCTAssertFalse(issued.verify(pinnedCertPublicKeyX963: certPub, now: expiresAt + 1))
    }
}
