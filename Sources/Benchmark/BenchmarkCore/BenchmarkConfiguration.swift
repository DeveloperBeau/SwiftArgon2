import Argon2

/// Configuration for benchmark test parameters
public struct BenchmarkConfiguration: Sendable {
    /// Memory costs to test in KiB
    public let memoryCosts: [UInt32]

    /// Time costs (iterations) to test
    public let timeCosts: [UInt32]

    /// Parallelism values to test
    public let parallelisms: [UInt32]

    /// Argon2 variants to test
    public let variants: [Argon2Variant]

    /// Hash length in bytes
    public let hashLength: UInt32

    /// Salt length in bytes
    public let saltLength: Int

    /// Password length in bytes
    public let passwordLength: Int

    /// Number of warmup runs before timing
    public let warmupRuns: Int

    /// Number of timed iterations per configuration
    public let timedIterations: Int

    /// Default benchmark configuration
    public static let `default` = BenchmarkConfiguration(
        memoryCosts: [64, 256, 1024, 4096, 16384, 65536],
        timeCosts: [1, 2, 3, 4],
        parallelisms: [1, 2, 4, 8],
        variants: [.argon2d, .argon2i, .argon2id],
        hashLength: 32,
        saltLength: 16,
        passwordLength: 32,
        warmupRuns: 2,
        timedIterations: 5
    )

    /// Quick benchmark configuration for testing
    public static let quick = BenchmarkConfiguration(
        memoryCosts: [64, 1024, 4096],
        timeCosts: [1, 2],
        parallelisms: [1, 4],
        variants: [.argon2id],
        hashLength: 32,
        saltLength: 16,
        passwordLength: 32,
        warmupRuns: 1,
        timedIterations: 3
    )

    public init(
        memoryCosts: [UInt32],
        timeCosts: [UInt32],
        parallelisms: [UInt32],
        variants: [Argon2Variant],
        hashLength: UInt32 = 32,
        saltLength: Int = 16,
        passwordLength: Int = 32,
        warmupRuns: Int = 2,
        timedIterations: Int = 5
    ) {
        self.memoryCosts = memoryCosts
        self.timeCosts = timeCosts
        self.parallelisms = parallelisms
        self.variants = variants
        self.hashLength = hashLength
        self.saltLength = saltLength
        self.passwordLength = passwordLength
        self.warmupRuns = warmupRuns
        self.timedIterations = timedIterations
    }

    /// Generate all valid test cases
    public func generateTestCases() -> [BenchmarkTestCase] {
        var testCases: [BenchmarkTestCase] = []

        for variant in variants {
            for memoryCost in memoryCosts {
                for timeCost in timeCosts {
                    for parallelism in parallelisms {
                        // Skip invalid combinations (memory must be >= 8 * parallelism)
                        guard memoryCost >= 8 * parallelism else { continue }

                        testCases.append(BenchmarkTestCase(
                            variant: variant,
                            memoryCost: memoryCost,
                            timeCost: timeCost,
                            parallelism: parallelism,
                            hashLength: hashLength
                        ))
                    }
                }
            }
        }

        return testCases
    }
}

/// A single benchmark test case
public struct BenchmarkTestCase: Sendable {
    public let variant: Argon2Variant
    public let memoryCost: UInt32
    public let timeCost: UInt32
    public let parallelism: UInt32
    public let hashLength: UInt32

    public init(
        variant: Argon2Variant,
        memoryCost: UInt32,
        timeCost: UInt32,
        parallelism: UInt32,
        hashLength: UInt32
    ) {
        self.variant = variant
        self.memoryCost = memoryCost
        self.timeCost = timeCost
        self.parallelism = parallelism
        self.hashLength = hashLength
    }

    public var description: String {
        "\(variant.name) m=\(memoryCost) t=\(timeCost) p=\(parallelism)"
    }
}
