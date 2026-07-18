// swift-tools-version: 6.0
import PackageDescription

// SentinelMLS wraps the Rust `mls-core` (via the `mls-ffi` UniFFI boundary, ADR-0007) as a Swift
// package the iOS app links for on-device MLS. It is a SIBLING of SentinelKit rather than a target
// inside it, so SentinelKit's pure-Swift tests keep building/running with no native dependency; the
// app composes both. Building this package requires the XCFramework produced by
// `scripts/build_mls_ffi.sh` (see MlsFfi.xcframework / ARTIFACTS.md) — it is a large derived binary
// and is not committed.
let package = Package(
    name: "SentinelMLS",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "MlsFfi", targets: ["MlsFfi"]),
    ],
    targets: [
        // Prebuilt Rust core wrapped by UniFFI: macOS (host tests) + iOS device + iOS simulator
        // slices, exposing the C module `mls_ffiFFI`.
        .binaryTarget(name: "MlsFfiBinary", path: "MlsFfi.xcframework"),
        // Generated Swift bindings (committed artifact) that call into the binary. Regenerate with
        // scripts/build_mls_ffi.sh; CI verifies they are not stale (`--check`).
        .target(name: "MlsFfi", dependencies: ["MlsFfiBinary"]),
        .testTarget(name: "MlsFfiBridgeTests", dependencies: ["MlsFfi"]),
    ]
)
