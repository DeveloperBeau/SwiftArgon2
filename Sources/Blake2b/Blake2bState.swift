/// BLAKE2b parameter block for initialization
public struct Blake2bParam: Sendable {
    public var digestLength: UInt8 = 0
    public var keyLength: UInt8 = 0
    public var fanout: UInt8 = 1
    public var depth: UInt8 = 1
    public var leafLength: UInt32 = 0
    public var nodeOffset: UInt64 = 0
    public var nodeDepth: UInt8 = 0
    public var innerLength: UInt8 = 0
    public var reserved: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    public var salt: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    public var personal: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    public init() {}

    /// Convert parameter block to bytes for XORing with IV
    func toBytes() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 64)
        bytes[0] = digestLength
        bytes[1] = keyLength
        bytes[2] = fanout
        bytes[3] = depth

        store32(leafLength, to: &bytes, at: 4)
        store64(nodeOffset, to: &bytes, at: 8)

        bytes[16] = nodeDepth
        bytes[17] = innerLength

        // Reserved bytes 18-31
        withUnsafePointer(to: reserved) { ptr in
            ptr.withMemoryRebound(to: UInt8.self, capacity: 14) { src in
                for i in 0..<14 {
                    bytes[18 + i] = src[i]
                }
            }
        }

        // Salt bytes 32-47
        withUnsafePointer(to: salt) { ptr in
            ptr.withMemoryRebound(to: UInt8.self, capacity: 16) { src in
                for i in 0..<16 {
                    bytes[32 + i] = src[i]
                }
            }
        }

        // Personal bytes 48-63
        withUnsafePointer(to: personal) { ptr in
            ptr.withMemoryRebound(to: UInt8.self, capacity: 16) { src in
                for i in 0..<16 {
                    bytes[48 + i] = src[i]
                }
            }
        }

        return bytes
    }
}

/// BLAKE2b hash state
public struct Blake2bState: Sendable {
    /// Hash state (8 x 64-bit words)
    var h: (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64)

    /// Counter (low and high parts)
    var t: (UInt64, UInt64)

    /// Finalization flags
    var f: (UInt64, UInt64)

    /// Input buffer
    var buf: [UInt8]

    /// Buffer length
    var buflen: Int

    /// Output length
    var outlen: Int

    /// Last node flag (for tree hashing)
    var lastNode: Bool

    public init() {
        h = (blake2bIV[0], blake2bIV[1], blake2bIV[2], blake2bIV[3],
             blake2bIV[4], blake2bIV[5], blake2bIV[6], blake2bIV[7])
        t = (0, 0)
        f = (0, 0)
        buf = [UInt8](repeating: 0, count: blake2bBlockBytes)
        buflen = 0
        outlen = 0
        lastNode = false
    }

    /// Get hash state word using pointer access (no switch)
    @inline(__always)
    func getH(_ index: Int) -> UInt64 {
        withUnsafePointer(to: h) { ptr in
            ptr.withMemoryRebound(to: UInt64.self, capacity: 8) { arr in
                arr[index]
            }
        }
    }

    /// Set hash state word using pointer access (no switch)
    @inline(__always)
    mutating func setH(_ index: Int, _ value: UInt64) {
        withUnsafeMutablePointer(to: &h) { ptr in
            ptr.withMemoryRebound(to: UInt64.self, capacity: 8) { arr in
                arr[index] = value
            }
        }
    }

    /// XOR hash state word using pointer access (no switch)
    @inline(__always)
    mutating func xorH(_ index: Int, _ value: UInt64) {
        withUnsafeMutablePointer(to: &h) { ptr in
            ptr.withMemoryRebound(to: UInt64.self, capacity: 8) { arr in
                arr[index] ^= value
            }
        }
    }

    @inline(__always)
    mutating func incrementCounter(_ inc: UInt64) {
        let (newT0, overflow) = t.0.addingReportingOverflow(inc)
        t.0 = newT0
        if overflow {
            t.1 &+= 1
        }
    }

    @inline(__always)
    mutating func setLastBlock() {
        if lastNode {
            f.1 = ~UInt64(0)
        }
        f.0 = ~UInt64(0)
    }

    var isFinalized: Bool {
        f.0 != 0
    }
}
