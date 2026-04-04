import Dispatch

/// Minimum segment length to benefit from multi-threading
/// Below this threshold, the overhead of task spawning exceeds the benefits
private let threadingThreshold: UInt32 = 64

public func fillMemoryBlocksSingleThreaded(instance: Instance) {
    for pass in 0..<instance.passes {
        for slice: UInt8 in 0..<UInt8(argon2SyncPoints) {
            for lane in 0..<instance.lanes {
                let position = Position(pass: pass, lane: lane, slice: slice, index: 0)
                fillSegment(instance: instance, position: position)
            }
        }
    }
}

public func fillMemoryBlocksMultiThreaded(instance: Instance) async {
    for pass in 0..<instance.passes {
        for slice: UInt8 in 0..<UInt8(argon2SyncPoints) {
            await withTaskGroup(of: Void.self) { group in
                for lane in 0..<instance.lanes {
                    group.addTask {
                        let position = Position(pass: pass, lane: lane, slice: slice, index: 0)
                        fillSegment(instance: instance, position: position)
                    }
                }
            }
        }
    }
}

/// GCD-based multi-threaded fill using DispatchQueue.concurrentPerform
/// Uses a work-stealing thread pool optimized for CPU-bound tasks with minimal per-iteration overhead
public func fillMemoryBlocksGCD(instance: Instance) {
    let lanes = Int(instance.lanes)
    for pass in 0..<instance.passes {
        for slice: UInt8 in 0..<UInt8(argon2SyncPoints) {
            DispatchQueue.concurrentPerform(iterations: lanes) { lane in
                let position = Position(pass: pass, lane: UInt32(lane), slice: slice, index: 0)
                fillSegment(instance: instance, position: position)
            }
        }
    }
}

public func fillMemoryBlocks(instance: Instance) async {
    // Use single-threaded for small workloads where threading overhead exceeds benefits
    if instance.threads == 1 || instance.segmentLength < threadingThreshold {
        fillMemoryBlocksSingleThreaded(instance: instance)
    } else {
        // Use GCD for better performance with CPU-bound parallel workloads
        fillMemoryBlocksGCD(instance: instance)
    }
}

public func fillMemoryBlocksSync(instance: Instance) {
    // Use GCD for multi-lane, single-threaded for small workloads
    if instance.lanes >= 2 && instance.segmentLength >= threadingThreshold {
        fillMemoryBlocksGCD(instance: instance)
    } else {
        fillMemoryBlocksSingleThreaded(instance: instance)
    }
}

public func argon2Hash(
    instance: Instance,
    password: [UInt8],
    salt: [UInt8],
    secret: [UInt8] = [],
    associatedData: [UInt8] = [],
    outputLength: Int
) async throws -> [UInt8] {
    try initialize(
        instance: instance,
        password: password,
        salt: salt,
        secret: secret,
        associatedData: associatedData,
        outputLength: UInt32(outputLength)
    )

    await fillMemoryBlocks(instance: instance)

    return try finalize(instance: instance, outputLength: outputLength)
}

public func argon2HashSync(
    instance: Instance,
    password: [UInt8],
    salt: [UInt8],
    secret: [UInt8] = [],
    associatedData: [UInt8] = [],
    outputLength: Int
) throws -> [UInt8] {
    try initialize(
        instance: instance,
        password: password,
        salt: salt,
        secret: secret,
        associatedData: associatedData,
        outputLength: UInt32(outputLength)
    )

    fillMemoryBlocksSync(instance: instance)

    return try finalize(instance: instance, outputLength: outputLength)
}
