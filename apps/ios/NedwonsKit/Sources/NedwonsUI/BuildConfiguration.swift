import Foundation
import NedwonsKit

/// Which channel this build is: Debug (local development), Staging (a real signed build against a
/// staging relay), or Release (App Store / TestFlight production).
///
/// The channel decides how strict configuration validation is. Development conveniences — a
/// loopback server, an unpinned transparency log, the development APNs environment — are exactly
/// the things that must NOT survive into a shipped build, and the only reliable way to ensure that
/// is to make the build refuse to run rather than to rely on someone remembering.
public enum BuildChannel: String, Sendable, Equatable {
    case debug
    case staging
    case release

    /// `NedwonsBuildChannel` from the Info.plist; Debug when unset, because an unconfigured build
    /// is a development build by definition and must never be silently treated as production.
    public static func current(bundle: Bundle = .main) -> BuildChannel {
        guard let raw = SharedAppIdentifiers.configured("NedwonsBuildChannel", bundle: bundle),
            let channel = BuildChannel(rawValue: raw.lowercased())
        else { return .debug }
        return channel
    }

    /// Whether this channel ships to real users on real devices.
    var isProductionGrade: Bool { self == .release }

    /// Whether a plaintext/loopback relay is acceptable.
    var allowsLocalDevelopmentServer: Bool { self == .debug }
}

/// One thing wrong with this build's configuration.
public enum ConfigurationFault: Equatable, Sendable, CustomStringConvertible {
    case serverURLMissing
    case serverURLNotHTTPS(String)
    /// A loopback/private address in a channel that ships to a device, where it can only fail.
    case serverURLIsLocalhost(String)
    case transparencyKeyMissing
    case transparencyKeyMalformed
    case developmentPushEntitlement(String)
    case developmentAppAttestEntitlement(String)
    case appGroupMissing
    case keychainAccessGroupMissing
    case teamIdentifierPrefixMissing
    /// The app group does not belong to this bundle id, so the app and its extension would root
    /// their shared store in different containers.
    case appGroupDoesNotMatchBundle(appGroup: String, bundleID: String)
    /// The APNs topic the server pushes to is the app's bundle id; a mismatch means every push is
    /// addressed to an app that does not exist.
    case apnsTopicMismatch(topic: String, bundleID: String)

    public var description: String {
        switch self {
        case .serverURLMissing:
            "NedwonsServerURL is not set."
        case .serverURLNotHTTPS(let url):
            "NedwonsServerURL must be https for a shipped build, got \(url)."
        case .serverURLIsLocalhost(let url):
            "NedwonsServerURL points at the local machine (\(url)), which no device can reach."
        case .transparencyKeyMissing:
            "NedwonsTransparencyLogKey is absent, so key transparency would fall back to "
                + "trust-on-first-use — which defeats the point of the log."
        case .transparencyKeyMalformed:
            "NedwonsTransparencyLogKey is not valid hex."
        case .developmentPushEntitlement(let value):
            "aps-environment is '\(value)'; a Release build must use 'production' or every push "
                + "is addressed to the wrong APNs environment."
        case .developmentAppAttestEntitlement(let value):
            "appattest-environment is '\(value)'; a Release build must use 'production'."
        case .appGroupMissing:
            "NedwonsAppGroup is not set, so the notification extension cannot read the MLS store."
        case .keychainAccessGroupMissing:
            "NedwonsKeychainAccessGroup is not set, so the notification extension cannot read the "
                + "session and every push degrades to a generic wake."
        case .teamIdentifierPrefixMissing:
            "NedwonsTeamIdentifierPrefix is not set, so the fully-qualified Keychain access group "
                + "cannot be built."
        case .appGroupDoesNotMatchBundle(let appGroup, let bundleID):
            "App group '\(appGroup)' does not belong to bundle id '\(bundleID)' "
                + "(expected 'group.\(bundleID)')."
        case .apnsTopicMismatch(let topic, let bundleID):
            "APNs topic '\(topic)' does not match bundle id '\(bundleID)'."
        }
    }
}

/// The inputs validation runs over. A plain value type with no `Bundle` inside, so every rule is
/// unit-testable without building and signing an app.
public struct BuildSettings: Equatable, Sendable {
    public var channel: BuildChannel
    public var serverURL: URL?
    public var transparencyKeyHex: String?
    public var bundleID: String
    public var appGroup: String?
    public var keychainAccessGroupSuffix: String?
    public var teamIdentifierPrefix: String?
    /// The `aps-environment` entitlement value, when readable.
    public var apsEnvironment: String?
    /// The `com.apple.developer.devicecheck.appattest-environment` entitlement value.
    public var appAttestEnvironment: String?
    /// The topic the server is configured to push to (`NEDWONS_APNS_TOPIC`), when the build
    /// records it for cross-checking.
    public var apnsTopic: String?

    public init(
        channel: BuildChannel,
        serverURL: URL?,
        transparencyKeyHex: String?,
        bundleID: String,
        appGroup: String?,
        keychainAccessGroupSuffix: String?,
        teamIdentifierPrefix: String?,
        apsEnvironment: String?,
        appAttestEnvironment: String?,
        apnsTopic: String?
    ) {
        self.channel = channel
        self.serverURL = serverURL
        self.transparencyKeyHex = transparencyKeyHex
        self.bundleID = bundleID
        self.appGroup = appGroup
        self.keychainAccessGroupSuffix = keychainAccessGroupSuffix
        self.teamIdentifierPrefix = teamIdentifierPrefix
        self.apsEnvironment = apsEnvironment
        self.appAttestEnvironment = appAttestEnvironment
        self.apnsTopic = apnsTopic
    }
}

/// Validates a build's configuration and, in a shipped channel, refuses to run a broken one.
public enum BuildConfiguration {
    /// Hostnames that only ever resolve to the machine doing the building.
    static let localHosts: Set<String> = ["localhost", "127.0.0.1", "::1", "0.0.0.0"]

    /// Every fault in `settings`, in a stable order. Empty means the build is coherent.
    ///
    /// Rules are graded by channel rather than applied uniformly: a Debug build SHOULD be allowed
    /// to talk to `http://127.0.0.1:8097` with no pinned log key, and a Release build must not be
    /// able to, and both facts need to hold in the same code.
    public static func faults(in settings: BuildSettings) -> [ConfigurationFault] {
        var faults: [ConfigurationFault] = []

        // ----- relay origin ------------------------------------------------------------------
        guard let serverURL = settings.serverURL else {
            faults.append(.serverURLMissing)
            return faults + identityFaults(in: settings)
        }
        let host = serverURL.host?.lowercased() ?? ""
        let isLoopback = localHosts.contains(host)

        if !settings.channel.allowsLocalDevelopmentServer {
            // Never silently fall back to the dev server outside local development: a build that
            // ships pointing at 127.0.0.1 is not "misconfigured but working", it simply cannot
            // reach anything, and the failure surfaces to users as an app that never connects.
            if isLoopback {
                faults.append(.serverURLIsLocalhost(serverURL.absoluteString))
            }
            if serverURL.scheme?.lowercased() != "https" {
                faults.append(.serverURLNotHTTPS(serverURL.absoluteString))
            }
        }

        // ----- key transparency --------------------------------------------------------------
        // Without a pinned key the client trusts the first log key it is handed, which is exactly
        // the substitution key transparency exists to detect. Tolerable in development, never in a
        // build a user installs.
        if settings.channel.isProductionGrade {
            switch settings.transparencyKeyHex {
            case .none:
                faults.append(.transparencyKeyMissing)
            case .some(let hex) where Hex.decode(hex) == nil:
                faults.append(.transparencyKeyMalformed)
            default:
                break
            }
        } else if let hex = settings.transparencyKeyHex, Hex.decode(hex) == nil {
            // A malformed key is a mistake in every channel — it is silently ignored otherwise.
            faults.append(.transparencyKeyMalformed)
        }

        // ----- entitlements left in development ----------------------------------------------
        if settings.channel.isProductionGrade {
            if let aps = settings.apsEnvironment, aps != "production" {
                faults.append(.developmentPushEntitlement(aps))
            }
            if let attest = settings.appAttestEnvironment, attest != "production" {
                faults.append(.developmentAppAttestEntitlement(attest))
            }
        }

        return faults + identityFaults(in: settings)
    }

    /// The identifiers the app, the extension and the server must all agree on.
    private static func identityFaults(in settings: BuildSettings) -> [ConfigurationFault] {
        var faults: [ConfigurationFault] = []
        let shipped = settings.channel != .debug

        switch settings.appGroup {
        case .none where shipped:
            faults.append(.appGroupMissing)
        case .some(let group) where group != "group.\(settings.bundleID)":
            // The convention is load-bearing, not cosmetic: the extension derives its container
            // from this value, and a mismatch means the two targets open different stores while
            // both appear to work.
            faults.append(
                .appGroupDoesNotMatchBundle(appGroup: group, bundleID: settings.bundleID))
        default:
            break
        }

        if shipped && settings.keychainAccessGroupSuffix == nil {
            faults.append(.keychainAccessGroupMissing)
        }
        if shipped && settings.teamIdentifierPrefix == nil {
            faults.append(.teamIdentifierPrefixMissing)
        }
        if let topic = settings.apnsTopic, topic != settings.bundleID {
            faults.append(.apnsTopicMismatch(topic: topic, bundleID: settings.bundleID))
        }
        return faults
    }

    /// Read this build's settings from its bundle.
    public static func settings(bundle: Bundle = .main) -> BuildSettings {
        BuildSettings(
            channel: BuildChannel.current(bundle: bundle),
            serverURL: SharedAppIdentifiers.configured("NedwonsServerURL", bundle: bundle)
                .flatMap(URL.init(string:)),
            transparencyKeyHex: SharedAppIdentifiers.configured(
                "NedwonsTransparencyLogKey", bundle: bundle),
            bundleID: bundle.bundleIdentifier ?? "",
            appGroup: SharedAppIdentifiers.appGroup(bundle: bundle),
            keychainAccessGroupSuffix: SharedAppIdentifiers.keychainAccessGroupSuffix(
                bundle: bundle),
            teamIdentifierPrefix: SharedAppIdentifiers.teamIdentifierPrefix(bundle: bundle),
            apsEnvironment: entitlement("aps-environment", bundle: bundle),
            appAttestEnvironment: entitlement(
                "com.apple.developer.devicecheck.appattest-environment", bundle: bundle),
            apnsTopic: SharedAppIdentifiers.configured("NedwonsApnsTopic", bundle: bundle)
        )
    }

    /// Entitlement values are not in the Info.plist, so they are mirrored into it by the build for
    /// validation. `nil` when a build does not mirror them — in which case the corresponding rule
    /// simply does not fire, rather than failing a build it cannot actually inspect.
    private static func entitlement(_ key: String, bundle: Bundle) -> String? {
        SharedAppIdentifiers.configured("NedwonsEntitlement." + key, bundle: bundle)
    }

    /// Validate at launch. A Release build with any fault **terminates** rather than running
    /// misconfigured.
    ///
    /// Crashing on launch is a deliberate choice over limping. Every fault checked here produces a
    /// build that is broken in a way the user cannot see and cannot fix: pushes to the wrong APNs
    /// environment, an unpinned transparency log, an unreachable relay. Shipping that quietly is
    /// worse than not launching, and the message names exactly what is wrong.
    ///
    /// Debug and Staging return the faults instead, so development is not blocked by the very
    /// settings that are expected to be absent there.
    @discardableResult
    public static func validateAtLaunch(bundle: Bundle = .main) -> [ConfigurationFault] {
        let settings = settings(bundle: bundle)
        let found = faults(in: settings)
        if settings.channel.isProductionGrade && !found.isEmpty {
            let detail = found.map { "  • \($0.description)" }.joined(separator: "\n")
            preconditionFailure(
                "Nedwons Release build is misconfigured and will not start:\n\(detail)")
        }
        return found
    }
}
