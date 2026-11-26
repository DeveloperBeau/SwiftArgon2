// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftArgon2",
    // Minimum deployment targets supported by Xcode 27.2.
    // Non-Apple platforms (Linux, Android) are not listed here and need no entry.
    platforms: [
        .macOS(.v12),
        .iOS(.v15),
        .tvOS(.v15),
        .watchOS(.v9),
        .visionOS(.v1)
    ],
    products: [
        .library(
            name: "SwiftArgon2",
            targets: ["SwiftArgon2"]
        ),
    ],
    dependencies: [
        // C reference implementation, used only by Benchmark and CReferenceTests.
        // Pinned to the latest upstream commit; the repo has had no release since 20190702.
        .package(url: "https://github.com/P-H-C/phc-winner-argon2.git", revision: "f57e61e19229e23c4445b85494dbf7c07de721cb"),
    ],
    targets: [
        // Public API. Module is named SwiftArgon2 (not Argon2) so its build outputs
        // do not collide with the C reference module `argon2` on case-insensitive
        // file systems under the Swift Build engine.
        .target(
            name: "SwiftArgon2",
            dependencies: ["Argon2Core", "Encoding"]
        ),
        // Benchmark executable
        .executableTarget(
            name: "Benchmark",
            dependencies: [
                "SwiftArgon2",
                .product(name: "argon2", package: "phc-winner-argon2")
            ]
        ),
        // Internal core implementation
        .target(
            name: "Argon2Core",
            dependencies: ["Blake2b"]
        ),
        // BLAKE2b implementation
        .target(
            name: "Blake2b"
        ),
        // PHC string format encoding
        .target(
            name: "Encoding",
            dependencies: ["Argon2Core"]
        ),
        // Tests
        .testTarget(
            name: "Argon2Tests",
            dependencies: ["SwiftArgon2", "Argon2Core", "Blake2b", "Encoding"]
        ),
        .testTarget(
            name: "Blake2bTests",
            dependencies: ["Blake2b"]
        ),
        // C reference comparison tests
        .testTarget(
            name: "CReferenceTests",
            dependencies: [
                "SwiftArgon2",
                .product(name: "argon2", package: "phc-winner-argon2")
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
