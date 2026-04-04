import Blake2b

/// Compute the initial hash H0 from all inputs
/// H0 = BLAKE2b(parallelism || outputLen || memoryCost || timeCost || version || type ||
///              pwdLen || password || saltLen || salt || secretLen || secret || adLen || ad)
public func initialHash(
    lanes: UInt32,
    outputLength: UInt32,
    memoryCost: UInt32,
    timeCost: UInt32,
    version: Argon2Version,
    type: Argon2Variant,
    password: [UInt8],
    salt: [UInt8],
    secret: [UInt8],
    associatedData: [UInt8]
) throws -> [UInt8] {
    var state = Blake2bState()
    try blake2bInit(&state, outlen: argon2PrehashDigestLength)

    // Helper to update with little-endian UInt32
    func updateU32(_ value: UInt32) throws {
        var bytes = [UInt8](repeating: 0, count: 4)
        store32(value, to: &bytes, at: 0)
        try blake2bUpdate(&state, bytes)
    }

    // Hash all parameters in order
    try updateU32(lanes)
    try updateU32(outputLength)
    try updateU32(memoryCost)
    try updateU32(timeCost)
    try updateU32(version.rawValue)
    try updateU32(type.rawValue)

    try updateU32(UInt32(password.count))
    if !password.isEmpty {
        try blake2bUpdate(&state, password)
    }

    try updateU32(UInt32(salt.count))
    if !salt.isEmpty {
        try blake2bUpdate(&state, salt)
    }

    try updateU32(UInt32(secret.count))
    if !secret.isEmpty {
        try blake2bUpdate(&state, secret)
    }

    try updateU32(UInt32(associatedData.count))
    if !associatedData.isEmpty {
        try blake2bUpdate(&state, associatedData)
    }

    var h0 = [UInt8](repeating: 0, count: argon2PrehashDigestLength)
    try blake2bFinal(&state, &h0)

    return h0
}

/// Fill first two blocks: Block[lane][0] = H'(H0 || 0 || lane), Block[lane][1] = H'(H0 || 1 || lane)
public func fillFirstBlocks(instance: Instance, blockhash: inout [UInt8]) throws {
    guard let memory = instance.memory else {
        throw Argon2CoreError.memoryNotAllocated
    }

    if blockhash.count < argon2PrehashSeedLength {
        blockhash.append(contentsOf: [UInt8](repeating: 0, count: argon2PrehashSeedLength - blockhash.count))
    }

    var blockBytes = [UInt8](repeating: 0, count: argon2BlockSize)

    for lane in 0..<instance.lanes {
        store32(0, to: &blockhash, at: argon2PrehashDigestLength)
        store32(lane, to: &blockhash, at: argon2PrehashDigestLength + 4)

        blockBytes = try blake2bLong(blockhash, outputLength: argon2BlockSize)
        blockBytes.withUnsafeBytes { buffer in
            memory.loadBlock(at: Int(lane) * memory.laneLength + 0, from: buffer.baseAddress!)
        }

        store32(1, to: &blockhash, at: argon2PrehashDigestLength)

        blockBytes = try blake2bLong(blockhash, outputLength: argon2BlockSize)
        blockBytes.withUnsafeBytes { buffer in
            memory.loadBlock(at: Int(lane) * memory.laneLength + 1, from: buffer.baseAddress!)
        }
    }

    for i in 0..<blockBytes.count {
        blockBytes[i] = 0
    }
}

public func initialize(
    instance: Instance,
    password: [UInt8],
    salt: [UInt8],
    secret: [UInt8],
    associatedData: [UInt8],
    outputLength: UInt32
) throws {
    instance.allocateMemory()

    var blockhash = try initialHash(
        lanes: instance.lanes,
        outputLength: outputLength,
        memoryCost: instance.memoryBlocks,
        timeCost: instance.passes,
        version: instance.version,
        type: instance.type,
        password: password,
        salt: salt,
        secret: secret,
        associatedData: associatedData
    )

    try fillFirstBlocks(instance: instance, blockhash: &blockhash)

    for i in 0..<blockhash.count {
        blockhash[i] = 0
    }
}

public enum Argon2CoreError: Error, Sendable {
    case memoryNotAllocated
    case invalidParameter
    case blake2Error
}
