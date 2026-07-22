import SwiftUI

/// Trust state is shown quietly, never as a fear-based warning for normal operation. Always
/// carries a non-color cue (icon + label) for accessibility.
public struct SecurityBadge: View {
    public enum State: Sendable {
        case encrypted // normal E2EE state
        case verified // safety number confirmed
        case unverifiedChange // identity key changed — needs attention (not alarm)

        var systemImage: String {
            switch self {
            case .encrypted: "lock.fill"
            case .verified: "checkmark.shield.fill"
            case .unverifiedChange: "exclamationmark.shield.fill"
            }
        }

        var label: String {
            switch self {
            case .encrypted: "End-to-end encrypted"
            case .verified: "Verified"
            case .unverifiedChange: "Safety number changed"
            }
        }
    }

    private let state: State
    private let palette: Nedwons.Palette

    public init(_ state: State, palette: Nedwons.Palette) {
        self.state = state
        self.palette = palette
    }

    private var tint: Color {
        switch state {
        case .encrypted: palette.accentPrimary
        case .verified: palette.verified
        case .unverifiedChange: palette.destructive
        }
    }

    public var body: some View {
        HStack(spacing: Nedwons.Spacing.xs) {
            Image(systemName: state.systemImage)
                .imageScale(.small)
            Text(state.label)
                .font(Nedwons.TypeScale.caption)
        }
        .foregroundStyle(tint)
        .padding(.horizontal, Nedwons.Spacing.sm)
        .padding(.vertical, Nedwons.Spacing.xxs)
        .background(
            RoundedRectangle(cornerRadius: Nedwons.Radius.sm, style: .continuous)
                .fill(tint.opacity(0.12))
        )
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(state.label)
    }
}

/// The primary call-to-action. Subtle cyan→indigo treatment, meets the minimum touch
/// target, and disables cleanly (a disabled control, never a dead one).
public struct PrimaryButton: View {
    private let title: String
    private let palette: Nedwons.Palette
    private let isEnabled: Bool
    private let action: () -> Void

    public init(
        _ title: String,
        palette: Nedwons.Palette,
        isEnabled: Bool = true,
        action: @escaping () -> Void
    ) {
        self.title = title
        self.palette = palette
        self.isEnabled = isEnabled
        self.action = action
    }

    public var body: some View {
        Button(action: action) {
            Text(title)
                .font(Nedwons.TypeScale.headline)
                .foregroundStyle(.white)
                .frame(maxWidth: .infinity, minHeight: Nedwons.minTouchTarget)
                .background(
                    RoundedRectangle(cornerRadius: Nedwons.Radius.md, style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: [palette.outgoingBubbleTop, palette.outgoingBubbleBottom],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                        .opacity(isEnabled ? 1 : 0.4)
                )
        }
        .buttonStyle(.plain)
        .disabled(!isEnabled)
        .accessibilityLabel(title)
    }
}

/// A refined, compact message bubble: graphite incoming, subtle cyan→indigo outgoing, both
/// with accessible text contrast.
public struct MessageBubble: View {
    private let text: String
    private let isOutgoing: Bool
    private let palette: Nedwons.Palette

    public init(text: String, isOutgoing: Bool, palette: Nedwons.Palette) {
        self.text = text
        self.isOutgoing = isOutgoing
        self.palette = palette
    }

    public var body: some View {
        HStack {
            if isOutgoing { Spacer(minLength: Nedwons.Spacing.xxl) }
            Text(text)
                .font(Nedwons.TypeScale.body)
                .foregroundStyle(isOutgoing ? Color.white : palette.textPrimary)
                .padding(.horizontal, Nedwons.Spacing.md)
                .padding(.vertical, Nedwons.Spacing.sm)
                .background(bubbleBackground)
                .clipShape(RoundedRectangle(cornerRadius: Nedwons.Radius.bubble, style: .continuous))
            if !isOutgoing { Spacer(minLength: Nedwons.Spacing.xxl) }
        }
    }

    @ViewBuilder
    private var bubbleBackground: some View {
        if isOutgoing {
            LinearGradient(
                colors: [palette.outgoingBubbleTop, palette.outgoingBubbleBottom],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        } else {
            palette.incomingBubble
        }
    }
}
