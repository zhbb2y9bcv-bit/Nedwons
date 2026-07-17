import XCTest
@testable import SentinelKit

/// Unit tests for the client that don't need a live server. The full happy-path flow is
/// covered by the `SentinelSmoke` executable driven against a real backend
/// (scripts/swift_backend_smoke.sh).
final class SentinelClientTests: XCTestCase {
    /// A connection to a closed port surfaces as a transport error, not a crash — the app
    /// must present this as a recoverable offline state.
    func testTransportErrorWhenServerUnreachable() async {
        // Port 1 is not listening; connection is refused promptly.
        let client = SentinelClient(baseURL: URL(string: "http://127.0.0.1:1")!)
        do {
            _ = try await client.register(
                username: "nobody",
                password: "battery staple orbit lantern",
                signer: SoftwareDeviceSigner()
            )
            XCTFail("expected a transport error")
        } catch SentinelClient.ClientError.transport {
            // expected
        } catch {
            XCTFail("expected transport error, got \(error)")
        }
    }
}
