import Argon2Core

/// Configuration for Argon2 hashing
public struct Argon2Configuration: Sendable {
    /// Argon2 variant (d, i, or id)
    public var variant: Argon2Variant

    /// Algorithm version
    public var version: Argon2Version

    /// Number of iterations (time cost)
    public var timeCost: UInt32

    /// Memory usage in KiB (memory cost)
    public var memoryCost: UInt32

    /// Degree of parallelism (number of lanes)
    public var parallelism: UInt32

    /// Output hash length in bytes
    public var hashLength: UInt32

    /// Initialize with default secure parameters
    public init(
        variant: Argon2Variant = .argon2id,
        version: Argon2Version = .v13,
        timeCost: UInt32 = 3,
        memoryCost: UInt32 = 65536,  // 64 MiB
        parallelism: UInt32 = 4,
        hashLength: UInt32 = 32
    ) {
        self.variant = variant
        self.version = version
        self.timeCost = timeCost
        self.memoryCost = memoryCost
        self.parallelism = parallelism
        self.hashLength = hashLength
    }

    /// Minimum output length (4 bytes)
    public static let minOutputLength: UInt32 = 4

    /// Maximum output length
    public static let maxOutputLength: UInt32 = UInt32.max

    /// Minimum salt length (8 bytes)
    public static let minSaltLength: UInt32 = 8

    /// Maximum salt length
    public static let maxSaltLength: UInt32 = UInt32.max

    /// Minimum time cost (1 iteration)
    public static let minTimeCost: UInt32 = 1

    /// Maximum time cost
    public static let maxTimeCost: UInt32 = UInt32.max

    /// Minimum memory cost (8 * parallelism KiB)
    public static let minMemoryCost: UInt32 = 8

    /// Maximum memory cost
    public static let maxMemoryCost: UInt32 = 0x0FFFFFFF // ~256GB

    /// Minimum parallelism (1 lane)
    public static let minParallelism: UInt32 = 1

    /// Maximum parallelism
    public static let maxParallelism: UInt32 = 0xFFFFFF // ~16 million

    /// Validate configuration
    public func validate(saltLength: Int) throws {
        // Output length
        if hashLength < Self.minOutputLength {
            throw Argon2Error.outputTooShort
        }
        if hashLength > Self.maxOutputLength {
            throw Argon2Error.outputTooLong
        }

        // Salt length
        if saltLength < Self.minSaltLength {
            throw Argon2Error.saltTooShort
        }

        // Time cost
        if timeCost < Self.minTimeCost {
            throw Argon2Error.timeCostTooSmall
        }
        if timeCost > Self.maxTimeCost {
            throw Argon2Error.timeCostTooLarge
        }

        // Memory cost
        if memoryCost < Self.minMemoryCost {
            throw Argon2Error.memoryCostTooSmall
        }
        if memoryCost > Self.maxMemoryCost {
            throw Argon2Error.memoryCostTooLarge
        }

        // Memory must be at least 8 * parallelism
        if memoryCost < 8 * parallelism {
            throw Argon2Error.memoryCostTooSmall
        }

        // Parallelism
        if parallelism < Self.minParallelism {
            throw Argon2Error.lanesTooFew
        }
        if parallelism > Self.maxParallelism {
            throw Argon2Error.lanesTooMany
        }
    }
}

/// Predefined configurations for common use cases
extension Argon2Configuration {
    /// Interactive login (low latency)
    /// Suitable for web application login where fast response is needed
    public static let interactive = Argon2Configuration(
        timeCost: 2,
        memoryCost: 65536,   // 64 MiB
        parallelism: 1
    )

    /// Moderate security
    /// Balance between security and performance
    public static let moderate = Argon2Configuration(
        timeCost: 3,
        memoryCost: 65536,   // 64 MiB
        parallelism: 4
    )

    /// Sensitive data
    /// Higher security for sensitive operations
    public static let sensitive = Argon2Configuration(
        timeCost: 4,
        memoryCost: 131072,  // 128 MiB
        parallelism: 4
    )
}
