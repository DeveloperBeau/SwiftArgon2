/// BLAKE2b block size in bytes
public let blake2bBlockBytes = 128

/// BLAKE2b maximum output size in bytes
public let blake2bOutBytes = 64

/// BLAKE2b maximum key size in bytes
public let blake2bKeyBytes = 64

/// BLAKE2b salt size in bytes
public let blake2bSaltBytes = 16

/// BLAKE2b personalization size in bytes
public let blake2bPersonalBytes = 16

/// BLAKE2b initialization vectors (first 64 bits of fractional parts of square roots of first 8 primes)
let blake2bIV: [UInt64] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
]

/// BLAKE2b sigma permutations for message scheduling
let blake2bSigma: [[Int]] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
]

@inline(__always)
public func rotr64(_ x: UInt64, _ n: Int) -> UInt64 {
    (x >> n) | (x << (64 - n))
}

@inline(__always)
public func load64(_ bytes: UnsafeRawPointer) -> UInt64 {
    bytes.loadUnaligned(as: UInt64.self).littleEndian
}

@inline(__always)
public func load64(_ bytes: [UInt8], at offset: Int) -> UInt64 {
    bytes.withUnsafeBytes { buffer in
        buffer.loadUnaligned(fromByteOffset: offset, as: UInt64.self).littleEndian
    }
}

@inline(__always)
public func store64(_ value: UInt64, to bytes: UnsafeMutableRawPointer) {
    bytes.storeBytes(of: value.littleEndian, as: UInt64.self)
}

@inline(__always)
public func store64(_ value: UInt64, to bytes: inout [UInt8], at offset: Int) {
    var le = value.littleEndian
    withUnsafeBytes(of: &le) { src in
        for i in 0..<8 {
            bytes[offset + i] = src[i]
        }
    }
}

@inline(__always)
public func load32(_ bytes: UnsafeRawPointer) -> UInt32 {
    bytes.loadUnaligned(as: UInt32.self).littleEndian
}

@inline(__always)
public func store32(_ value: UInt32, to bytes: UnsafeMutableRawPointer) {
    bytes.storeBytes(of: value.littleEndian, as: UInt32.self)
}

@inline(__always)
public func store32(_ value: UInt32, to bytes: inout [UInt8], at offset: Int) {
    var le = value.littleEndian
    withUnsafeBytes(of: &le) { src in
        for i in 0..<4 {
            bytes[offset + i] = src[i]
        }
    }
}
