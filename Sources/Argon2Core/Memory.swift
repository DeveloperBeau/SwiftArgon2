import Foundation

/// Memory manager for Argon2 blocks (lane-isolated for safe concurrent filling)
/// Optimized with contiguous memory pool and pre-allocated workspace blocks
public final class Memory: @unchecked Sendable {
    /// Contiguous memory pool for all blocks (page-aligned for better TLB coverage)
    private let poolStorage: UnsafeMutableRawPointer

    /// Block views into the contiguous pool
    private var blocks: [Block]

    /// Pre-allocated workspace blocks per lane to avoid temporary allocations in fillBlock
    /// Each lane gets 6 workspace blocks: blockR, blockTmp, zeroBlock, inputBlock, addressBlock, tempBlock
    private var workspaceBlocks: [[Block]]

    public let blockCount: Int

    public let lanes: Int

    public let laneLength: Int

    public init(blockCount: Int, lanes: Int) {
        self.blockCount = blockCount
        self.lanes = lanes
        self.laneLength = blockCount / lanes

        // Single contiguous allocation with page alignment (16KB) for better TLB coverage
        let totalBytes = blockCount * 1024
        let pool = UnsafeMutableRawPointer.allocate(byteCount: totalBytes, alignment: 16384)
        pool.initializeMemory(as: UInt8.self, repeating: 0, count: totalBytes)
        self.poolStorage = pool

        // Create Block views into contiguous storage
        var blockArray = [Block]()
        blockArray.reserveCapacity(blockCount)
        for i in 0..<blockCount {
            blockArray.append(Block(storage: (pool + i * 1024).assumingMemoryBound(to: UInt64.self)))
        }
        self.blocks = blockArray

        // Pre-allocate 6 workspace blocks per lane (these own their storage)
        // [0]: blockR, [1]: blockTmp, [2]: zeroBlock, [3]: inputBlock, [4]: addressBlock, [5]: tempBlock
        var workspaceArray = [[Block]]()
        workspaceArray.reserveCapacity(lanes)
        for _ in 0..<lanes {
            workspaceArray.append([Block(), Block(), Block(), Block(), Block(), Block()])
        }
        self.workspaceBlocks = workspaceArray
    }

    deinit {
        poolStorage.deallocate()
    }

    /// Returns a reference to the block (no copying due to class semantics)
    public subscript(index: Int) -> Block {
        get { blocks[index] }
        set { blocks[index] = newValue }
    }

    /// Returns a reference to the block at the given lane and offset
    public func block(lane: Int, offset: Int) -> Block {
        blocks[lane * laneLength + offset]
    }

    public func setBlock(lane: Int, offset: Int, _ block: Block) {
        blocks[lane * laneLength + offset] = block
    }

    @inline(__always)
    public func getWord(blockIndex: Int, wordIndex: Int) -> UInt64 {
        blocks[blockIndex].getWord(wordIndex)
    }

    @inline(__always)
    public func setWord(blockIndex: Int, wordIndex: Int, _ value: UInt64) {
        blocks[blockIndex].setWord(wordIndex, value)
    }

    @inline(__always)
    public func xorWord(blockIndex: Int, wordIndex: Int, _ value: UInt64) {
        blocks[blockIndex].xorWord(wordIndex, value)
    }

    /// Copy block contents using direct pointer access
    public func copyBlock(from srcIndex: Int, to dstIndex: Int) {
        blocks[dstIndex].copy(from: blocks[srcIndex])
    }

    /// XOR block contents using vectorized operation
    public func xorBlock(from srcIndex: Int, onto dstIndex: Int) {
        blocks[dstIndex].xor(with: blocks[srcIndex])
    }

    public func loadBlock(at index: Int, from bytes: UnsafeRawPointer) {
        blocks[index].load(from: bytes)
    }

    public func storeBlock(at index: Int, to bytes: UnsafeMutableRawPointer) {
        blocks[index].store(to: bytes)
    }

    /// Access block directly (no closure overhead for simple operations)
    @inline(__always)
    public func blockAt(_ index: Int) -> Block {
        blocks[index]
    }

    /// Get workspace blocks for a lane (pre-allocated to avoid temporary allocations)
    @inline(__always)
    public func getWorkspace(lane: Int) -> (Block, Block, Block) {
        let ws = workspaceBlocks[lane]
        return (ws[0], ws[1], ws[2])
    }

    /// Get full workspace blocks for a lane (includes address generation blocks)
    /// Returns: (blockR, blockTmp, zeroBlock, inputBlock, addressBlock, tempBlock)
    @inline(__always)
    public func getFullWorkspace(lane: Int) -> (Block, Block, Block, Block, Block, Block) {
        let ws = workspaceBlocks[lane]
        return (ws[0], ws[1], ws[2], ws[3], ws[4], ws[5])
    }

    public func wipe() {
        for i in 0..<blockCount {
            blocks[i].wipe()
        }
        for ws in workspaceBlocks {
            for block in ws {
                block.wipe()
            }
        }
    }

    @inline(__always)
    public func absoluteIndex(lane: Int, offset: Int) -> Int {
        lane * laneLength + offset
    }

    @inline(__always)
    public func laneFrom(absoluteIndex: Int) -> Int {
        absoluteIndex / laneLength
    }

    @inline(__always)
    public func offsetFrom(absoluteIndex: Int) -> Int {
        absoluteIndex % laneLength
    }
}

/// Lane-isolated view for safe concurrent access
public struct LaneView: @unchecked Sendable {
    private let memory: Memory
    public let lane: Int

    public init(memory: Memory, lane: Int) {
        self.memory = memory
        self.lane = lane
    }

    public func block(at offset: Int) -> Block {
        memory.block(lane: lane, offset: offset)
    }

    public func setBlock(at offset: Int, _ block: Block) {
        memory.setBlock(lane: lane, offset: offset, block)
    }

    public func getWord(blockOffset: Int, wordIndex: Int) -> UInt64 {
        memory.getWord(blockIndex: memory.absoluteIndex(lane: lane, offset: blockOffset), wordIndex: wordIndex)
    }

    @inline(__always)
    public func blockAt(_ offset: Int) -> Block {
        memory.blockAt(memory.absoluteIndex(lane: lane, offset: offset))
    }

    public func absoluteIndex(offset: Int) -> Int {
        memory.absoluteIndex(lane: lane, offset: offset)
    }

    public var laneLength: Int { memory.laneLength }
}

public struct SegmentView: @unchecked Sendable {
    private let memory: Memory
    public let lane: Int
    public let slice: Int
    public let segmentLength: Int
    public let startOffset: Int

    public init(memory: Memory, lane: Int, slice: Int, segmentLength: Int) {
        self.memory = memory
        self.lane = lane
        self.slice = slice
        self.segmentLength = segmentLength
        self.startOffset = slice * segmentLength
    }

    public func block(at index: Int) -> Block {
        memory.block(lane: lane, offset: startOffset + index)
    }

    public func setBlock(at index: Int, _ block: Block) {
        memory.setBlock(lane: lane, offset: startOffset + index, block)
    }

    @inline(__always)
    public func blockAt(_ index: Int) -> Block {
        memory.blockAt(memory.absoluteIndex(lane: lane, offset: startOffset + index))
    }

    public func absoluteIndex(index: Int) -> Int {
        memory.absoluteIndex(lane: lane, offset: startOffset + index)
    }
}
