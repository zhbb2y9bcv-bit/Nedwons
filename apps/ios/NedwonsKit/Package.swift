// swift-tools-version: 6.0
import PackageDescription

// NedwonsKit is the platform-neutral client crypto/protocol layer (ADR-0005 keeps it free
// of app-specific coupling). It builds and tests on the command line with `swift test`,
// which is why the interop guarantee against the Rust backend can be verified in CI without
// an iOS simulator. The SwiftUI app and iOS-only integrations (App Attest, Keychain UI)
// live in the separate Xcode project under apps/ios/Nedwons and consume this package.
let package = Package(
    name: "NedwonsKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "NedwonsKit", targets: ["NedwonsKit"]),
        .library(name: "NedwonsUI", targets: ["NedwonsUI"]),
    ],
    targets: [
        .target(name: "NedwonsKit"),
        // The SwiftUI design system + app screens + view model. Kept free of iOS-only APIs
        // so it type-checks with `swift build` on macOS; the app wires these tokens to
        // asset-catalog colors in Xcode. The `@main` entry point lives in the Xcode project.
        .target(name: "NedwonsUI", dependencies: ["NedwonsKit"]),
        .executableTarget(name: "InteropEmit", dependencies: ["NedwonsKit"]),
        // Live end-to-end smoke test against a running nedwons-api server.
        .executableTarget(name: "NedwonsSmoke", dependencies: ["NedwonsKit"]),
        .testTarget(name: "NedwonsKitTests", dependencies: ["NedwonsKit"]),
        .testTarget(name: "NedwonsUITests", dependencies: ["NedwonsUI"]),
    ]
)
