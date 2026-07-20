import SwiftUI

/// Design tokens for Nedwons's visual system: *futuristic precision + modern restraint +
/// visible trust* (see the design section of the product spec). Dark is the default
/// foundation (near-black graphite/obsidian, deep navy surfaces); a complete accessible
/// light theme is provided. Primary accent is a controlled electric cyan/ice blue; the
/// secondary is a restrained violet/indigo. Green means verified/success only; red means
/// destructive/security-alert only.
///
/// These are literal color values so the package type-checks cross-platform. In the Xcode
/// app they map to asset-catalog colors that adapt automatically to the system appearance;
/// `Palette.dark` / `Palette.light` here document the exact intended values.
public enum Nedwons {
    // MARK: Primitive palette

    public struct Palette: Sendable {
        public let background: Color // app base
        public let surface: Color // cards, sheets
        public let surfaceRaised: Color // elevated surfaces
        public let hairline: Color // fine borders
        public let textPrimary: Color
        public let textSecondary: Color
        public let accentPrimary: Color // electric cyan / ice blue
        public let accentSecondary: Color // violet / indigo
        public let verified: Color // green — verified/success ONLY
        public let destructive: Color // red — destructive/security ONLY
        public let outgoingBubbleTop: Color // subtle cyan→indigo gradient stops
        public let outgoingBubbleBottom: Color
        public let incomingBubble: Color // graphite

        public static let dark = Palette(
            background: Color(.sRGB, red: 0.04, green: 0.05, blue: 0.07, opacity: 1), // obsidian
            surface: Color(.sRGB, red: 0.07, green: 0.09, blue: 0.12, opacity: 1),
            surfaceRaised: Color(.sRGB, red: 0.10, green: 0.12, blue: 0.16, opacity: 1),
            hairline: Color(.sRGB, red: 1, green: 1, blue: 1, opacity: 0.08),
            textPrimary: Color(.sRGB, red: 0.94, green: 0.96, blue: 0.98, opacity: 1),
            textSecondary: Color(.sRGB, red: 0.66, green: 0.71, blue: 0.78, opacity: 1),
            accentPrimary: Color(.sRGB, red: 0.29, green: 0.78, blue: 0.92, opacity: 1), // ice cyan
            accentSecondary: Color(.sRGB, red: 0.45, green: 0.42, blue: 0.86, opacity: 1), // indigo
            verified: Color(.sRGB, red: 0.29, green: 0.80, blue: 0.55, opacity: 1),
            destructive: Color(.sRGB, red: 0.90, green: 0.36, blue: 0.38, opacity: 1),
            outgoingBubbleTop: Color(.sRGB, red: 0.20, green: 0.62, blue: 0.85, opacity: 1),
            outgoingBubbleBottom: Color(.sRGB, red: 0.36, green: 0.36, blue: 0.80, opacity: 1),
            incomingBubble: Color(.sRGB, red: 0.13, green: 0.15, blue: 0.19, opacity: 1)
        )

        public static let light = Palette(
            background: Color(.sRGB, red: 0.97, green: 0.98, blue: 0.99, opacity: 1),
            surface: Color(.sRGB, red: 1, green: 1, blue: 1, opacity: 1),
            surfaceRaised: Color(.sRGB, red: 0.98, green: 0.99, blue: 1.0, opacity: 1),
            hairline: Color(.sRGB, red: 0, green: 0, blue: 0, opacity: 0.10),
            textPrimary: Color(.sRGB, red: 0.08, green: 0.10, blue: 0.13, opacity: 1),
            textSecondary: Color(.sRGB, red: 0.35, green: 0.40, blue: 0.47, opacity: 1),
            accentPrimary: Color(.sRGB, red: 0.09, green: 0.51, blue: 0.66, opacity: 1), // darker for AA contrast
            accentSecondary: Color(.sRGB, red: 0.33, green: 0.30, blue: 0.74, opacity: 1),
            verified: Color(.sRGB, red: 0.13, green: 0.55, blue: 0.35, opacity: 1),
            destructive: Color(.sRGB, red: 0.78, green: 0.20, blue: 0.22, opacity: 1),
            outgoingBubbleTop: Color(.sRGB, red: 0.16, green: 0.55, blue: 0.78, opacity: 1),
            outgoingBubbleBottom: Color(.sRGB, red: 0.30, green: 0.30, blue: 0.74, opacity: 1),
            incomingBubble: Color(.sRGB, red: 0.92, green: 0.94, blue: 0.96, opacity: 1)
        )

        public static func forScheme(_ scheme: ColorScheme) -> Palette {
            scheme == .dark ? .dark : .light
        }
    }

    // MARK: Spacing scale (4pt base)

    public enum Spacing {
        public static let xxs: CGFloat = 2
        public static let xs: CGFloat = 4
        public static let sm: CGFloat = 8
        public static let md: CGFloat = 12
        public static let lg: CGFloat = 16
        public static let xl: CGFloat = 24
        public static let xxl: CGFloat = 32
    }

    // MARK: Corner radius

    public enum Radius {
        public static let sm: CGFloat = 8
        public static let md: CGFloat = 14
        public static let lg: CGFloat = 20
        public static let bubble: CGFloat = 18
    }

    // MARK: Typography — system fonts honor Dynamic Type / font scaling.

    public enum TypeScale {
        public static let title = Font.system(.title2, design: .rounded).weight(.semibold)
        public static let headline = Font.system(.headline, design: .rounded)
        public static let body = Font.system(.body)
        public static let callout = Font.system(.callout)
        public static let caption = Font.system(.caption)
        public static let monoSmall = Font.system(.caption, design: .monospaced) // safety numbers
    }

    // MARK: Minimum touch target (Apple HIG / WCAG 2.2)

    public static let minTouchTarget: CGFloat = 44
}
