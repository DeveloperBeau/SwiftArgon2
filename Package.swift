// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftArgon2",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6),
        .visionOS(.v1)
    ],
    products: [
        .library(
            name: "Argon2",
            targets: ["Argon2"]
        ),
    ],
    dependencies: [
        // C reference implementation for comparison tests
        .package(url: "https://github.com/P-H-C/phc-winner-argon2.git", branch: "master"),
    ],
    targets: [
        // Public API
        .target(
            name: "Argon2",
            dependencies: ["Argon2Core", "Encoding"],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        // Benchmark executable
        .executableTarget(
            name: "Benchmark",
            dependencies: [
                "Argon2",
                .product(name: "argon2", package: "phc-winner-argon2")
            ],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        // Internal core implementation
        .target(
            name: "Argon2Core",
            dependencies: ["Blake2b"],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        // BLAKE2b implementation
        .target(
            name: "Blake2b",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        // PHC string format encoding
        .target(
            name: "Encoding",
            dependencies: ["Argon2Core"],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        // Tests
        .testTarget(
            name: "Argon2Tests",
            dependencies: ["Argon2", "Argon2Core", "Blake2b", "Encoding"]
        ),
        .testTarget(
            name: "Blake2bTests",
            dependencies: ["Blake2b"]
        ),
        // C reference comparison tests
        .testTarget(
            name: "CReferenceTests",
            dependencies: [
                "Argon2",
                .product(name: "argon2", package: "phc-winner-argon2")
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
