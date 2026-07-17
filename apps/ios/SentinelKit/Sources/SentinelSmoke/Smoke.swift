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

            print("SMOKE_OK")
        } catch {
            fail("\(error)")
        }
    }
}
