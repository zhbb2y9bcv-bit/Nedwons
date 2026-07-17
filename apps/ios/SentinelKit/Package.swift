// swift-tools-version: 6.0
import PackageDescription

// SentinelKit is the platform-neutral client crypto/protocol layer (ADR-0005 keeps it free
// of app-specific coupling). It builds and tests on the command line with `swift test`,
// which is why the interop guarantee against the Rust backend can be verified in CI without
// an iOS simulator. The SwiftUI app and iOS-only integrations (App Attest, Keychain UI)
// live in the separate Xcode project under apps/ios/Sentinel and consume this package.
let package = Package(
    name: "SentinelKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "SentinelKit", targets: ["SentinelKit"]),
        .library(name: "SentinelUI", targets: ["SentinelUI"]),
    ],
    targets: [
        .target(name: "SentinelKit"),
        // The SwiftUI design system + app screens. Kept free of iOS-only APIs so it
        // type-checks with `swift build` on macOS; the app wires these tokens to
        // asset-catalog colors in Xcode. The `@main` entry point lives in the Xcode project.
        .target(name: "SentinelUI"),
        .executableTarget(name: "InteropEmit", dependencies: ["SentinelKit"]),
        .testTarget(name: "SentinelKitTests", dependencies: ["SentinelKit"]),
    ]
)
