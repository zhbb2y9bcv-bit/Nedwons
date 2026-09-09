import NedwonsKit
import SwiftUI

#if canImport(UIKit)
    import UIKit
#endif

/// A group's photo when it has one (decrypted from the E2EE state), else the letter avatar.
struct GroupAvatarView: View {
    @ObservedObject var model: AppModel
    let conversationID: String
    let fallbackLabel: String
    let palette: Nedwons.Palette

    var body: some View {
        if let data = model.groupAvatars[conversationID], let image = platformImage(data) {
            image
                .resizable()
                .scaledToFill()
                .frame(width: 44, height: 44)
                .clipShape(Circle())
                .accessibilityLabel("Group photo")
        } else {
            Avatar(label: fallbackLabel, palette: palette, isGroup: true)
        }
    }

    private func platformImage(_ data: Data) -> Image? {
        #if canImport(UIKit)
            guard let ui = UIImage(data: data) else { return nil }
            return Image(uiImage: ui)
        #else
            return nil
        #endif
    }
}

/// Downscales a picked photo into the wire-bounded thumbnail the E2EE avatar kind carries
/// (≤16 KB): 128 px on the long edge, then JPEG quality stepped down until it fits.
enum AvatarScaler {
    static let maxBytes = 15_000  // headroom under the 16 KB content cap

    static func thumbnail(from data: Data) -> Data? {
        #if canImport(UIKit)
            guard let image = UIImage(data: data) else { return nil }
            let maxEdge: CGFloat = 128
            let scale = min(1, maxEdge / max(image.size.width, image.size.height))
            let size = CGSize(width: image.size.width * scale, height: image.size.height * scale)
            let renderer = UIGraphicsImageRenderer(size: size)
            let scaled = renderer.image { _ in image.draw(in: CGRect(origin: .zero, size: size)) }
            for quality in [0.7, 0.5, 0.3, 0.15] {
                if let jpeg = scaled.jpegData(compressionQuality: quality), jpeg.count <= maxBytes {
                    return jpeg
                }
            }
            return nil
        #else
            return nil
        #endif
    }
}
