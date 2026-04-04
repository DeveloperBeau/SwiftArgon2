/// Argon2 variant type
public enum Argon2Variant: UInt32, Sendable, CaseIterable {
    /// Data-dependent addressing (faster but vulnerable to side-channel attacks)
    case argon2d = 0
    /// Data-independent addressing (slower but resistant to side-channel attacks)
    case argon2i = 1
    /// Hybrid: first half uses independent, second half uses dependent
    case argon2id = 2

    /// String representation for encoding
    public var name: String {
        switch self {
        case .argon2d: return "argon2d"
        case .argon2i: return "argon2i"
        case .argon2id: return "argon2id"
        }
    }

    /// Parse from string
    public init?(name: String) {
        switch name.lowercased() {
        case "argon2d": self = .argon2d
        case "argon2i": self = .argon2i
        case "argon2id": self = .argon2id
        default: return nil
        }
    }
}

/// Argon2 version
public enum Argon2Version: UInt32, Sendable {
    /// Version 1.0 (0x10)
    case v10 = 0x10
    /// Version 1.3 (0x13) - current
    case v13 = 0x13

    /// Default version
    public static let current = Argon2Version.v13
}

/// Pre-hash digest length (64 bytes from BLAKE2b)
public let argon2PrehashDigestLength = 64

/// Pre-hash seed length (72 bytes = 64 + 8 for block index and lane)
public let argon2PrehashSeedLength = 72

/// Argon2 instance containing all algorithm state
public final class Instance: @unchecked Sendable {
    /// Argon2 variant type
    public let type: Argon2Variant

    /// Algorithm version
    public let version: Argon2Version

    /// Number of passes
    public let passes: UInt32

    /// Number of memory blocks
    public let memoryBlocks: UInt32

    /// Segment length (blocks per segment)
    public let segmentLength: UInt32

    /// Lane length (blocks per lane)
    public let laneLength: UInt32

    /// Number of lanes (parallelism)
    public let lanes: UInt32

    /// Number of threads to use
    public let threads: UInt32

    /// Bitmask for power-of-2 lane length optimization (nil if not power of 2)
    public let laneLengthMask: UInt32?

    public var memory: Memory?

    public init(
        type: Argon2Variant,
        version: Argon2Version,
        passes: UInt32,
        memoryCost: UInt32,
        lanes: UInt32,
        threads: UInt32
    ) {
        self.type = type
        self.version = version
        self.passes = passes
        self.lanes = lanes
        self.threads = min(threads, lanes) // Can't use more threads than lanes

        // Calculate memory layout
        // Memory cost is in KiB, each block is 1KiB
        var memBlocks = memoryCost

        // Ensure minimum memory (8 blocks per lane for 4 sync points × 2 blocks)
        if memBlocks < 8 * lanes {
            memBlocks = 8 * lanes
        }

        // Round down to multiple of (4 * lanes) for even distribution
        memBlocks = (memBlocks / (argon2SyncPoints * lanes)) * (argon2SyncPoints * lanes)

        self.memoryBlocks = memBlocks
        self.laneLength = memBlocks / lanes
        self.segmentLength = laneLength / argon2SyncPoints

        // Pre-compute lane length mask for power-of-2 optimization
        let ll = self.laneLength
        self.laneLengthMask = (ll & (ll - 1)) == 0 ? (ll - 1) : nil
    }

    /// Allocate memory for the instance
    public func allocateMemory() {
        memory = Memory(blockCount: Int(memoryBlocks), lanes: Int(lanes))
    }

    /// Free memory
    public func freeMemory() {
        memory?.wipe()
        memory = nil
    }

    /// Check if using data-independent addressing at given position
    public func isDataIndependent(at position: Position) -> Bool {
        switch type {
        case .argon2i:
            return true
        case .argon2d:
            return false
        case .argon2id:
            // Data-independent for first pass, first 2 slices
            return position.pass == 0 && position.slice < argon2SyncPoints / 2
        }
    }
}
