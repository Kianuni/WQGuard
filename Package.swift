// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "WQGuard",
    defaultLocalization: "en",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "WQGuardCore",
            targets: ["WQGuardCore"]
        ),
        .executable(
            name: "wqguard-cli",
            targets: ["wqguard-cli"]
        ),
        .executable(
            name: "wqguard",
            targets: ["wqguard-cli"]
        )
    ],
    dependencies: [
        // Zero external dependencies (pure Swift + Darwin / Mach-O APIs)
    ],
    targets: [
        .target(
            name: "WQGuardCore",
            dependencies: [],
            path: "Sources/WQGuardCore"
        ),
        .executableTarget(
            name: "wqguard-cli",
            dependencies: ["WQGuardCore"],
            path: "Sources/wqguard-cli"
        ),
        .testTarget(
            name: "WQGuardCoreTests",
            dependencies: ["WQGuardCore"],
            path: "Tests/WQGuardCoreTests"
        )
    ]
)
