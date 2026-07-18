// swift-tools-version: 6.0
import PackageDescription

// SentinelApp is the composition layer: it is the ONLY place that links BOTH the pure-Swift UI
// (SentinelUI, from the SentinelKit package) AND the native MLS core (MlsFfi, from the SentinelMLS
// package, which links the Rust xcframework). It hosts the real `SecretEngine` adapter over the
// generated `MlsClient`, so the view-model is proven against the actual Rust core (not a fake), and
// it provides the app scaffolding the `@main` Xcode target imports. `swift test` builds + runs its
// integration tests on the macOS slice of the xcframework (no simulator required for CI).
let package = Package(
    name: "SentinelApp",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "SentinelAppKit", targets: ["SentinelAppKit"]),
    ],
    dependencies: [
        .package(path: "../SentinelKit"),
        .package(path: "../SentinelMLS"),
    ],
    targets: [
        .target(
            name: "SentinelAppKit",
            dependencies: [
                .product(name: "SentinelUI", package: "SentinelKit"),
                .product(name: "SentinelKit", package: "SentinelKit"),
                .product(name: "MlsFfi", package: "SentinelMLS"),
            ]),
        // A runnable live-integration client: links BOTH the HTTP client (SentinelKit) and the real
        // MLS core (MlsFfi), driven against a booted sentinel-api server by
        // scripts/self_group_live_run.sh. This is the only composition point that can prove the whole
        // Swift app stack — networking + MLS — against the real relay in one process.
        .executableTarget(
            name: "SelfGroupLiveRun",
            dependencies: [
                .product(name: "SentinelKit", package: "SentinelKit"),
                .product(name: "MlsFfi", package: "SentinelMLS"),
            ]),
        .testTarget(name: "SentinelAppKitTests", dependencies: ["SentinelAppKit"]),
    ]
)
