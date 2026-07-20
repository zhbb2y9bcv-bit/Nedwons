// swift-tools-version: 6.0
import PackageDescription

// NedwonsApp is the composition layer: it is the ONLY place that links BOTH the pure-Swift UI
// (NedwonsUI, from the NedwonsKit package) AND the native MLS core (MlsFfi, from the NedwonsMLS
// package, which links the Rust xcframework). It hosts the real `SecretEngine` adapter over the
// generated `MlsClient`, so the view-model is proven against the actual Rust core (not a fake), and
// it provides the app scaffolding the `@main` Xcode target imports. `swift test` builds + runs its
// integration tests on the macOS slice of the xcframework (no simulator required for CI).
let package = Package(
    name: "NedwonsApp",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "NedwonsAppKit", targets: ["NedwonsAppKit"]),
        // Extension-safe: links only NedwonsKit (HTTP) + MlsFfi (MLS core), NOT NedwonsUI, so the
        // Notification Service Extension can link it (app extensions forbid app-only API / SwiftUI App).
        .library(name: "NedwonsPush", targets: ["NedwonsPush"]),
    ],
    dependencies: [
        .package(path: "../NedwonsKit"),
        .package(path: "../NedwonsMLS"),
    ],
    targets: [
        // Extension-safe push decode logic (no NedwonsUI): the Notification Service Extension and
        // the app both use it. Unit-tested against the real MLS core.
        .target(
            name: "NedwonsPush",
            dependencies: [
                .product(name: "NedwonsKit", package: "NedwonsKit"),
                .product(name: "MlsFfi", package: "NedwonsMLS"),
            ]),
        .target(
            name: "NedwonsAppKit",
            dependencies: [
                "NedwonsPush",
                .product(name: "NedwonsUI", package: "NedwonsKit"),
                .product(name: "NedwonsKit", package: "NedwonsKit"),
                .product(name: "MlsFfi", package: "NedwonsMLS"),
            ]),
        // A runnable live-integration client: links BOTH the HTTP client (NedwonsKit) and the real
        // MLS core (MlsFfi), driven against a booted nedwons-api server by
        // scripts/self_group_live_run.sh. This is the only composition point that can prove the whole
        // Swift app stack — networking + MLS — against the real relay in one process.
        .executableTarget(
            name: "SelfGroupLiveRun",
            dependencies: [
                "NedwonsAppKit",
                .product(name: "NedwonsKit", package: "NedwonsKit"),
                .product(name: "MlsFfi", package: "NedwonsMLS"),
            ]),
        .testTarget(
            name: "NedwonsAppKitTests", dependencies: ["NedwonsAppKit", "NedwonsPush"]),
    ]
)
