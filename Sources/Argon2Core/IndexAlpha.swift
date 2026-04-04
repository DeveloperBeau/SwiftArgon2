/// Compute the absolute position of the reference block
/// Uses a pseudo-random value to determine which previous block to reference
///
/// - Parameters:
///   - instance: The Argon2 instance
///   - position: Current position (pass, lane, slice, index)
///   - pseudoRand: 32-bit pseudo-random value from previous block or address block
///   - sameLane: Whether the reference block is in the same lane
/// - Returns: Absolute position within the lane
public func indexAlpha(
    instance: Instance,
    position: Position,
    pseudoRand: UInt32,
    sameLane: Bool
) -> UInt32 {
    /*
     * Pass 0:
     *   This lane: all already finished segments plus already constructed blocks in this segment
     *   Other lanes: all already finished segments
     * Pass 1+:
     *   This lane: (SYNC_POINTS - 1) last segments plus already constructed blocks in this segment
     *   Other lanes: (SYNC_POINTS - 1) last segments
     */

    let referenceAreaSize: UInt32

    if position.pass == 0 {
        // First pass
        if position.slice == 0 {
            // First slice: can only reference previous blocks in this segment
            // All but the previous block (and current)
            referenceAreaSize = position.index &- 1
        } else {
            if sameLane {
                // Same lane: can reference all previous slices plus current segment
                referenceAreaSize = UInt32(position.slice) &* instance.segmentLength &+ position.index &- 1
            } else {
                // Other lane: can only reference completed slices
                // Subtract 1 if at index 0 (previous block not yet complete)
                let adjustment: UInt32 = (position.index == 0) ? 1 : 0
                referenceAreaSize = UInt32(position.slice) &* instance.segmentLength &- adjustment
            }
        }
    } else {
        // Subsequent passes
        if sameLane {
            // Same lane: all blocks except current segment minus current position
            referenceAreaSize = instance.laneLength &- instance.segmentLength &+ position.index &- 1
        } else {
            // Other lane: all blocks except current segment
            let adjustment: UInt32 = (position.index == 0) ? 1 : 0
            referenceAreaSize = instance.laneLength &- instance.segmentLength &- adjustment
        }
    }

    // Handle edge case where reference area is 0
    guard referenceAreaSize > 0 else {
        return 0
    }

    // Map pseudo_rand to [0, referenceAreaSize) using a skewed distribution
    // relative_position = pseudoRand^2 / 2^32
    // relative_position = referenceAreaSize - 1 - (referenceAreaSize * relative_position / 2^32)
    var relativePosition = UInt64(pseudoRand)
    relativePosition = (relativePosition &* relativePosition) >> 32
    relativePosition = UInt64(referenceAreaSize) &- 1 &- ((UInt64(referenceAreaSize) &* relativePosition) >> 32)

    // Compute starting position
    let startPosition: UInt32
    if position.pass != 0 {
        // On subsequent passes, start after the current slice (wrapping around)
        startPosition = (position.slice == argon2SyncPoints - 1) ? 0 : (UInt32(position.slice) + 1) * instance.segmentLength
    } else {
        startPosition = 0
    }

    // Compute absolute position within the lane (wrapping around)
    // Use bitwise AND for power-of-2 lane lengths (faster than modulo)
    let absolutePosition: UInt32
    if let mask = instance.laneLengthMask {
        absolutePosition = (startPosition &+ UInt32(relativePosition)) & mask
    } else {
        absolutePosition = (startPosition &+ UInt32(relativePosition)) % instance.laneLength
    }

    return absolutePosition
}
