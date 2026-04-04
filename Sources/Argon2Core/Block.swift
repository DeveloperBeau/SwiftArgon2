@_exported import Blake2b

/// Block size in bytes
public let argon2BlockSize = 1024

/// Number of 64-bit words in a block
public let argon2QWordsInBlock = 128

/// Number of addresses generated per block in Argon2i
public let argon2AddressesInBlock = 128

/// A 1024-byte memory block for Argon2 (optimized class-based implementation)
/// Uses raw pointer storage to eliminate tuple access overhead and enable SIMD operations
public final class Block: @unchecked Sendable {
    /// Storage for 128 × UInt64 words
    internal let storage: UnsafeMutablePointer<UInt64>

    /// Whether this block owns its storage (vs being a view into a pool)
    private let ownsStorage: Bool

    public init() {
        // 64-byte aligned allocation for optimal SIMD performance
        let rawPtr = UnsafeMutableRawPointer.allocate(byteCount: 1024, alignment: 64)
        rawPtr.initializeMemory(as: UInt64.self, repeating: 0, count: 128)
        storage = rawPtr.assumingMemoryBound(to: UInt64.self)
        ownsStorage = true
    }

    public init(repeating value: UInt8) {
        // 64-byte aligned allocation for optimal SIMD performance
        let rawPtr = UnsafeMutableRawPointer.allocate(byteCount: 1024, alignment: 64)
        let word = UInt64(value) | (UInt64(value) << 8) | (UInt64(value) << 16) | (UInt64(value) << 24) |
                   (UInt64(value) << 32) | (UInt64(value) << 40) | (UInt64(value) << 48) | (UInt64(value) << 56)
        rawPtr.initializeMemory(as: UInt64.self, repeating: word, count: 128)
        storage = rawPtr.assumingMemoryBound(to: UInt64.self)
        ownsStorage = true
    }

    /// Internal initializer for pool views (storage not owned by this block)
    internal init(storage: UnsafeMutablePointer<UInt64>) {
        self.storage = storage
        self.ownsStorage = false
    }

    deinit {
        if ownsStorage {
            storage.deinitialize(count: 128)
            UnsafeMutableRawPointer(storage).deallocate()
        }
    }

    /// Direct pointer access for SIMD and bulk operations
    @inline(__always)
    public var wordPointer: UnsafeMutablePointer<UInt64> { storage }

    @inline(__always)
    public func getWord(_ index: Int) -> UInt64 {
        storage[index]
    }

    @inline(__always)
    public func setWord(_ index: Int, _ value: UInt64) {
        storage[index] = value
    }

    @inline(__always)
    public func xorWord(_ index: Int, _ value: UInt64) {
        storage[index] ^= value
    }

    /// Copy contents from another block using SIMD operations
    public func copy(from source: Block) {
        UnsafeMutableRawPointer(storage).withMemoryRebound(to: SIMD8<UInt64>.self, capacity: 16) { dst in
            UnsafeRawPointer(source.storage).withMemoryRebound(to: SIMD8<UInt64>.self, capacity: 16) { src in
                for i in 0..<16 {
                    dst[i] = src[i]
                }
            }
        }
    }

    /// XOR contents with another block using SIMD operations
    public func xor(with source: Block) {
        UnsafeMutableRawPointer(storage).withMemoryRebound(to: SIMD8<UInt64>.self, capacity: 16) { dst in
            UnsafeRawPointer(source.storage).withMemoryRebound(to: SIMD8<UInt64>.self, capacity: 16) { src in
                for i in 0..<16 {
                    dst[i] ^= src[i]
                }
            }
        }
    }

    /// Copy and XOR in one pass using SIMD operations
    @inline(__always)
    public func copyXor(from a: Block, xorWith b: Block) {
        UnsafeMutableRawPointer(storage).withMemoryRebound(to: SIMD8<UInt64>.self, capacity: 16) { dst in
            UnsafeRawPointer(a.storage).withMemoryRebound(to: SIMD8<UInt64>.self, capacity: 16) { srcA in
                UnsafeRawPointer(b.storage).withMemoryRebound(to: SIMD8<UInt64>.self, capacity: 16) { srcB in
                    for i in 0..<16 {
                        dst[i] = srcA[i] ^ srcB[i]
                    }
                }
            }
        }
    }

    /// Securely wipe the block contents
    public func wipe() {
        let ptr = UnsafeMutableRawPointer(storage).assumingMemoryBound(to: UInt8.self)
        secureWipe(ptr, count: argon2BlockSize)
    }

    /// Load block from raw bytes (little-endian)
    public func load(from bytes: UnsafeRawPointer) {
        #if _endian(little)
        // On little-endian systems (all Apple silicon), direct memcpy is valid
        UnsafeMutableRawPointer(storage).copyMemory(from: bytes, byteCount: 1024)
        #else
        // Big-endian systems need byte-swap
        for i in 0..<128 {
            storage[i] = (bytes + i * 8).loadUnaligned(as: UInt64.self).littleEndian
        }
        #endif
    }

    /// Store block to raw bytes (little-endian)
    public func store(to bytes: UnsafeMutableRawPointer) {
        #if _endian(little)
        // On little-endian systems (all Apple silicon), direct memcpy is valid
        bytes.copyMemory(from: UnsafeRawPointer(storage), byteCount: 1024)
        #else
        // Big-endian systems need byte-swap
        for i in 0..<128 {
            (bytes + i * 8).storeBytes(of: storage[i].littleEndian, as: UInt64.self)
        }
        #endif
    }

    /// Convert block to byte array
    public func toBytes() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: argon2BlockSize)
        bytes.withUnsafeMutableBytes { buffer in
            store(to: buffer.baseAddress!)
        }
        return bytes
    }

    /// Create block from byte array
    public static func from(bytes: [UInt8]) -> Block {
        let block = Block()
        bytes.withUnsafeBytes { buffer in
            block.load(from: buffer.baseAddress!)
        }
        return block
    }
}

/// Secure memory wipe that won't be optimized away
@inline(never)
public func secureWipe(_ ptr: UnsafeMutablePointer<UInt8>, count: Int) {
    for i in 0..<count {
        ptr[i] = 0
    }
    _fixLifetime(ptr)
}

@inline(never)
public func _fixLifetime<T>(_ value: T) {
    withExtendedLifetime(value) { _ in }
}
