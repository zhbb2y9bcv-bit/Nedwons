import Foundation

/// The identifiers the app and its Notification Service Extension MUST agree on, read from each
/// target's own Info.plist so the two are configured from one place in `project.yml`.
///
/// ## Why this exists
///
/// Three identifiers have to match exactly across the two targets for a contentless push to be
/// decryptable on device:
///
///   * the **app group** — roots the shared MLS store both targets open;
///   * the **Keychain access group** — lets the extension read the session and at-rest root the
///     app wrote;
///   * the **APNs topic** — the app's bundle id, which the server sends as `apns-topic`.
///
/// When they disagree nothing errors. The extension simply finds no session, falls back to the
/// generic "New message" wake, and the bug is invisible in the Simulator (where neither app groups
/// nor Keychain groups are enforced as they are on device) and invisible in logs. Reading them from
/// a single named place, and validating them at launch (see `BuildConfiguration`), turns a silent
/// misconfiguration into a startup failure.
public enum SharedAppIdentifiers {
    /// `NedwonsAppGroup` — e.g. `group.app.nedwons.demo`. `nil` when unset or still a build
    /// placeholder, which means app-private storage and a generic wake.
    public static func appGroup(bundle: Bundle = .main) -> String? {
        configured("NedwonsAppGroup", bundle: bundle)
    }

    /// `NedwonsKeychainAccessGroup` — the shared Keychain group, WITHOUT the team prefix, e.g.
    /// `app.nedwons.shared`. The system resolves `$(AppIdentifierPrefix)` in the entitlement; the
    /// value passed to `SecItem*` must be the fully-qualified `<TEAMID>.app.nedwons.shared`, which
    /// is what `keychainAccessGroup(teamPrefix:)` builds.
    public static func keychainAccessGroupSuffix(bundle: Bundle = .main) -> String? {
        configured("NedwonsKeychainAccessGroup", bundle: bundle)
    }

    /// `NedwonsTeamIdentifierPrefix` — the team prefix the entitlement's `$(AppIdentifierPrefix)`
    /// expands to, so the extension can build the same fully-qualified group the app uses.
    public static func teamIdentifierPrefix(bundle: Bundle = .main) -> String? {
        configured("NedwonsTeamIdentifierPrefix", bundle: bundle)
    }

    /// The fully-qualified Keychain access group, or `nil` when this build has not been provisioned
    /// with one (development/Simulator), in which case each target uses its own private keychain.
    public static func keychainAccessGroup(bundle: Bundle = .main) -> String? {
        guard let suffix = keychainAccessGroupSuffix(bundle: bundle) else { return nil }
        guard let prefix = teamIdentifierPrefix(bundle: bundle) else { return nil }
        return "\(prefix).\(suffix)"
    }

    /// An Info.plist string that is present, non-empty, and not an unexpanded build setting.
    ///
    /// The `$(` check matters: an unset xcconfig variable reaches the built Info.plist verbatim as
    /// `$(SOMETHING)`, and passing that to the Keychain or to `containerURL` yields an obscure
    /// failure rather than an obvious one.
    public static func configured(_ key: String, bundle: Bundle = .main) -> String? {
        guard let raw = bundle.object(forInfoDictionaryKey: key) as? String else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("$(") else { return nil }
        return trimmed
    }
}
