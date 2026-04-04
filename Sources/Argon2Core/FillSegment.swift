import Blake2b

/// Fill a single memory block using the compression function
/// Combines previous block and reference block using the BlaMka mixing function
/// Uses pre-allocated workspace blocks to avoid temporary allocations
///
/// - Parameters:
///   - prevBlock: The previous block in the sequence (reference, not copied)
///   - refBlock: The reference block (reference, not copied)
///   - currBlock: The block to fill (output)
///   - blockR: Pre-allocated workspace block for R = refBlock XOR prevBlock
///   - blockTmp: Pre-allocated workspace block for saving intermediate state
///   - withXor: Whether to XOR the result with existing currBlock content (v1.3 on passes > 0)
@inline(__always)
public func fillBlockDirect(
    prevBlock: Block,
    refBlock: Block,
    currBlock: Block,
    blockR: Block,
    blockTmp: Block,
    withXor: Bool
) {
    // Create working block R = refBlock XOR prevBlock (using workspace)
    blockR.copyXor(from: refBlock, xorWith: prevBlock)

    // Save for final XOR
    blockTmp.copy(from: blockR)

    if withXor {
        // For v1.3 on passes > 0: also XOR with existing currBlock
        blockTmp.xor(with: currBlock)
    }

    // Apply compression function to blockR
    applyBlaMkaCompression(blockR)

    // currBlock = blockTmp XOR blockR
    currBlock.copyXor(from: blockTmp, xorWith: blockR)
}

/// Apply the BlaMka compression function (8 column rounds + 8 row rounds)
@inline(__always)
private func applyBlaMkaCompression(_ blockR: Block) {
    let ptr = blockR.wordPointer

    // 8 column rounds on 16-word columns: (0,1,...,15), (16,17,...31), ..., (112,113,...127)
    for i in 0..<8 {
        let base = 16 * i
        var v0 = ptr[base + 0]
        var v1 = ptr[base + 1]
        var v2 = ptr[base + 2]
        var v3 = ptr[base + 3]
        var v4 = ptr[base + 4]
        var v5 = ptr[base + 5]
        var v6 = ptr[base + 6]
        var v7 = ptr[base + 7]
        var v8 = ptr[base + 8]
        var v9 = ptr[base + 9]
        var v10 = ptr[base + 10]
        var v11 = ptr[base + 11]
        var v12 = ptr[base + 12]
        var v13 = ptr[base + 13]
        var v14 = ptr[base + 14]
        var v15 = ptr[base + 15]

        blake2RoundNoMsg(&v0, &v1, &v2, &v3, &v4, &v5, &v6, &v7,
                         &v8, &v9, &v10, &v11, &v12, &v13, &v14, &v15)

        ptr[base + 0] = v0
        ptr[base + 1] = v1
        ptr[base + 2] = v2
        ptr[base + 3] = v3
        ptr[base + 4] = v4
        ptr[base + 5] = v5
        ptr[base + 6] = v6
        ptr[base + 7] = v7
        ptr[base + 8] = v8
        ptr[base + 9] = v9
        ptr[base + 10] = v10
        ptr[base + 11] = v11
        ptr[base + 12] = v12
        ptr[base + 13] = v13
        ptr[base + 14] = v14
        ptr[base + 15] = v15
    }

    // 8 row rounds on interleaved rows:
    // (0,1,16,17,32,33,48,49,64,65,80,81,96,97,112,113), etc.
    for i in 0..<8 {
        var v0 = ptr[2 * i]
        var v1 = ptr[2 * i + 1]
        var v2 = ptr[2 * i + 16]
        var v3 = ptr[2 * i + 17]
        var v4 = ptr[2 * i + 32]
        var v5 = ptr[2 * i + 33]
        var v6 = ptr[2 * i + 48]
        var v7 = ptr[2 * i + 49]
        var v8 = ptr[2 * i + 64]
        var v9 = ptr[2 * i + 65]
        var v10 = ptr[2 * i + 80]
        var v11 = ptr[2 * i + 81]
        var v12 = ptr[2 * i + 96]
        var v13 = ptr[2 * i + 97]
        var v14 = ptr[2 * i + 112]
        var v15 = ptr[2 * i + 113]

        blake2RoundNoMsg(&v0, &v1, &v2, &v3, &v4, &v5, &v6, &v7,
                         &v8, &v9, &v10, &v11, &v12, &v13, &v14, &v15)

        ptr[2 * i] = v0
        ptr[2 * i + 1] = v1
        ptr[2 * i + 16] = v2
        ptr[2 * i + 17] = v3
        ptr[2 * i + 32] = v4
        ptr[2 * i + 33] = v5
        ptr[2 * i + 48] = v6
        ptr[2 * i + 49] = v7
        ptr[2 * i + 64] = v8
        ptr[2 * i + 65] = v9
        ptr[2 * i + 80] = v10
        ptr[2 * i + 81] = v11
        ptr[2 * i + 96] = v12
        ptr[2 * i + 97] = v13
        ptr[2 * i + 112] = v14
        ptr[2 * i + 113] = v15
    }
}

/// Legacy fill block function (for compatibility with address generation)
public func fillBlock(
    prevBlock: Block,
    refBlock: Block,
    nextBlock: Block,
    withXor: Bool
) {
    // Create local workspace blocks for address generation (not on hot path)
    let blockR = Block()
    let blockTmp = Block()

    fillBlockDirect(
        prevBlock: prevBlock,
        refBlock: refBlock,
        currBlock: nextBlock,
        blockR: blockR,
        blockTmp: blockTmp,
        withXor: withXor
    )
}

/// Generate next address block for data-independent addressing (Argon2i/id)
/// Uses pre-allocated workspace blocks to avoid temporary allocations
@inline(__always)
func nextAddresses(addressBlock: Block, inputBlock: Block, zeroBlock: Block, tempBlock: Block,
                   blockR: Block, blockTmp: Block) {
    // Increment counter in input block
    inputBlock.setWord(6, inputBlock.getWord(6) &+ 1)

    // Generate addresses: fill_block(zeroBlock, inputBlock, addressBlock, false)
    fillBlockDirect(prevBlock: zeroBlock, refBlock: inputBlock, currBlock: addressBlock,
                    blockR: blockR, blockTmp: blockTmp, withXor: false)

    // Double hash: fill_block(zeroBlock, addressBlock, addressBlock, false)
    tempBlock.copy(from: addressBlock)
    fillBlockDirect(prevBlock: zeroBlock, refBlock: tempBlock, currBlock: addressBlock,
                    blockR: blockR, blockTmp: blockTmp, withXor: false)
}

/// Fill a segment of memory blocks
/// A segment is one quarter of a lane (memory is divided into 4 slices)
public func fillSegment(instance: Instance, position: Position) {
    guard let memory = instance.memory else { return }

    let dataIndependentAddressing = instance.isDataIndependent(at: position)

    // Get all pre-allocated workspace blocks for this lane
    let (blockR, blockTmp, zeroBlock, inputBlock, addressBlock, tempBlock) =
        memory.getFullWorkspace(lane: Int(position.lane))

    if dataIndependentAddressing {
        // Zero out blocks that need to be clean for address generation
        zeroBlock.wipe()

        // Initialize input block for address generation (only first 7 words used)
        inputBlock.setWord(0, UInt64(position.pass))
        inputBlock.setWord(1, UInt64(position.lane))
        inputBlock.setWord(2, UInt64(position.slice))
        inputBlock.setWord(3, UInt64(instance.memoryBlocks))
        inputBlock.setWord(4, UInt64(instance.passes))
        inputBlock.setWord(5, UInt64(instance.type.rawValue))
        inputBlock.setWord(6, 0)  // Counter starts at 0
    }

    // Determine starting index
    var startingIndex: UInt32 = 0
    if position.pass == 0 && position.slice == 0 {
        // First two blocks are already filled
        startingIndex = 2

        // Generate first address block if needed
        if dataIndependentAddressing {
            nextAddresses(addressBlock: addressBlock, inputBlock: inputBlock, zeroBlock: zeroBlock,
                          tempBlock: tempBlock, blockR: blockR, blockTmp: blockTmp)
        }
    }

    // Calculate offsets
    var currOffset = Int(position.lane) * memory.laneLength +
                     Int(position.slice) * Int(instance.segmentLength) +
                     Int(startingIndex)

    var prevOffset: Int
    if currOffset % memory.laneLength == 0 {
        // Wrap around to last block in lane
        prevOffset = currOffset + memory.laneLength - 1
    } else {
        prevOffset = currOffset - 1
    }

    // Fill each block in the segment
    for i in startingIndex..<instance.segmentLength {
        // Rotate prevOffset if at start of lane
        if currOffset % memory.laneLength == 1 {
            prevOffset = currOffset - 1
        }

        // Get pseudo-random value for reference block selection
        let pseudoRand: UInt64
        if dataIndependentAddressing {
            // Generate new addresses if needed
            if i % UInt32(argon2AddressesInBlock) == 0 {
                nextAddresses(addressBlock: addressBlock, inputBlock: inputBlock, zeroBlock: zeroBlock,
                              tempBlock: tempBlock, blockR: blockR, blockTmp: blockTmp)
            }
            pseudoRand = addressBlock.getWord(Int(i % UInt32(argon2AddressesInBlock)))
        } else {
            // Data-dependent: use first word of previous block
            pseudoRand = memory.getWord(blockIndex: prevOffset, wordIndex: 0)
        }

        // Compute reference lane
        var refLane = UInt32((pseudoRand >> 32) % UInt64(instance.lanes))

        // On first pass, first slice: can only reference current lane
        if position.pass == 0 && position.slice == 0 {
            refLane = position.lane
        }

        // Compute position for index_alpha
        var pos = position
        pos.index = i

        // Compute reference index within lane
        let refIndex = indexAlpha(
            instance: instance,
            position: pos,
            pseudoRand: UInt32(truncatingIfNeeded: pseudoRand),
            sameLane: refLane == position.lane
        )

        // Get reference block absolute index
        let refBlockIndex = Int(refLane) * memory.laneLength + Int(refIndex)

        // Determine if I should XOR (v1.3 on passes > 0)
        let withXor = instance.version == .v13 && position.pass > 0

        // Get block references directly (no copies due to class semantics)
        let prevBlock = memory[prevOffset]
        let refBlock = memory[refBlockIndex]
        let currBlock = memory[currOffset]

        // Fill the block using pre-allocated workspace
        fillBlockDirect(
            prevBlock: prevBlock,
            refBlock: refBlock,
            currBlock: currBlock,
            blockR: blockR,
            blockTmp: blockTmp,
            withXor: withXor
        )

        currOffset += 1
        prevOffset += 1
    }
}
