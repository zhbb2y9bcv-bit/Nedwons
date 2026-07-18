import Foundation
import SentinelKit

/// Build-time configuration the shipped app reads from its `Info.plist` (set per build
/// configuration in the Xcode project), so nothing security-relevant is hardcoded:
///
/// - `SentinelServerURL` — the backend base URL (must be **https** for a device build; iOS ATS
///   blocks plaintext). Falls back to the loopback dev server so the simulator "just works".
/// - `SentinelTransparencyLogKey` — the transparency log's public key (hex, X9.63), **pinned out of
///   band**. When present, the key-transparency audit trusts *this* key rather than TOFU-accepting
///   whatever the server first advertises. Absent ⇒ dev TOFU (a first STH is pinned at runtime).
///
/// An environment override (`SENTINEL_SERVER_URL`) wins over the plist for local runs.
public enum AppConfig {
    /// Default when nothing is configured — the loopback dev server (simulator only).
    public static let devServerURL = URL(string: "http://127.0.0.1:8097")!

    /// The backend base URL for this build.
    public static var serverURL: URL {
        if let env = ProcessInfo.processInfo.environment["SENTINEL_SERVER_URL"],
            let url = URL(string: env)
        {
            return url
        }
        if let s = infoString("SentinelServerURL"), let url = URL(string: s) {
            return url
        }
        return devServerURL
    }

    /// The out-of-band-pinned transparency log public key (hex → bytes), or `nil` for dev TOFU.
    public static var pinnedTransparencyLogKey: Data? {
        infoString("SentinelTransparencyLogKey").flatMap { Hex.decode($0) }
    }

    /// True when the server URL is a secure (https) origin — required for a real device build.
    public static var isServerSecure: Bool {
        serverURL.scheme?.lowercased() == "https"
    }

    private static func infoString(_ key: String) -> String? {
        guard let raw = Bundle.main.object(forInfoDictionaryKey: key) as? String else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        // Treat an empty / unsubstituted build-setting placeholder as absent.
        return (trimmed.isEmpty || trimmed.hasPrefix("$(")) ? nil : trimmed
    }
}
