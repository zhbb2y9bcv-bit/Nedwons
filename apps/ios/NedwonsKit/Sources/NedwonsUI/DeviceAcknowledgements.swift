import Foundation

/// Which device ids the user has explicitly recognised as their own, **per account**, across
/// launches.
///
/// This set is a security control, not a UI convenience: `DeviceAuditBanner` raises an alarm for
/// any device in the transparency log the user has not acknowledged, which is how a silently
/// enrolled attacker device is surfaced (ADR-0008, R-201). Holding it only in memory — as the model
/// previously did, with the comment "here it lives for the session" — meant every relaunch
/// re-flagged every legitimate device the user had already recognised. Users learn to dismiss an
/// alarm that fires every time, and an alarm nobody reads detects nothing.
///
/// Keyed by account because a device shared between two accounts must not inherit the other's
/// recognitions.
/// `@unchecked Sendable`: `UserDefaults` is not marked `Sendable`, but it is documented as
/// thread-safe and this type adds no mutable state of its own.
public struct DeviceAcknowledgements: @unchecked Sendable {
    private let defaults: UserDefaults
    private static let prefix = "nedwons.acknowledgedDevices."

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    private func key(for accountID: String) -> String { Self.prefix + accountID }

    public func acknowledged(for accountID: String) -> Set<String> {
        Set(defaults.stringArray(forKey: key(for: accountID)) ?? [])
    }

    public func acknowledge(_ deviceID: String, for accountID: String) {
        var current = acknowledged(for: accountID)
        current.insert(deviceID)
        // Sorted so the stored form is stable and diffable; order carries no meaning.
        defaults.set(current.sorted(), forKey: key(for: accountID))
    }

    public func replace(_ deviceIDs: Set<String>, for accountID: String) {
        defaults.set(deviceIDs.sorted(), forKey: key(for: accountID))
    }

    /// Forget one account's recognitions (account deletion). Deliberately NOT called on ordinary
    /// sign-out: signing out and back in on the same phone must not re-alarm on devices the user
    /// has already vouched for.
    public func clear(for accountID: String) {
        defaults.removeObject(forKey: key(for: accountID))
    }
}
