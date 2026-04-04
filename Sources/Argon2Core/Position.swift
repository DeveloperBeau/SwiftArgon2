/// Number of synchronization points per pass
public let argon2SyncPoints: UInt32 = 4

/// Position in the Argon2 memory matrix
public struct Position: Sendable {
    /// Current pass number (0-indexed)
    public var pass: UInt32

    /// Current lane number (0-indexed)
    public var lane: UInt32

    /// Current slice number (0-3, corresponding to sync points)
    public var slice: UInt8

    /// Current index within the segment
    public var index: UInt32

    public init(pass: UInt32 = 0, lane: UInt32 = 0, slice: UInt8 = 0, index: UInt32 = 0) {
        self.pass = pass
        self.lane = lane
        self.slice = slice
        self.index = index
    }
}

public struct ThreadData: Sendable {
    public var position: Position

    public init(position: Position) {
        self.position = position
    }
}
