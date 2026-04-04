import Blake2b

/// Finalize Argon2 hash: XOR last blocks of all lanes, then apply H' for output
public func finalize(instance: Instance, outputLength: Int) throws -> [UInt8] {
    guard let memory = instance.memory else {
        throw Argon2CoreError.memoryNotAllocated
    }

    let blockHash = Block()
    blockHash.copy(from: memory[memory.laneLength - 1])

    for lane in 1..<Int(instance.lanes) {
        let lastBlockIndex = lane * memory.laneLength + (memory.laneLength - 1)
        blockHash.xor(with: memory[lastBlockIndex])
    }

    var blockHashBytes = [UInt8](repeating: 0, count: argon2BlockSize)
    blockHashBytes.withUnsafeMutableBytes { buffer in
        blockHash.store(to: buffer.baseAddress!)
    }

    let output = try blake2bLong(blockHashBytes, outputLength: outputLength)

    blockHash.wipe()
    for i in 0..<blockHashBytes.count {
        blockHashBytes[i] = 0
    }

    instance.freeMemory()

    return output
}
