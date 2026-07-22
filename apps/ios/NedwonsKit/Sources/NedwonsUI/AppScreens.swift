import SwiftUI

/// Unfinished features appear as disabled controls with an explanation, never as dead buttons.
public struct FeatureFlags: Sendable {
    public var backendConfigured: Bool
    public var callsEnabled: Bool
    public var groupsEnabled: Bool

    public init(
        backendConfigured: Bool = false,
        callsEnabled: Bool = false,
        groupsEnabled: Bool = false
    ) {
        self.backendConfigured = backendConfigured
        self.callsEnabled = callsEnabled
        self.groupsEnabled = groupsEnabled
    }

    public static let scaffold = FeatureFlags()
}

