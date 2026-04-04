/// A secure container for sensitive bytes (passwords, secrets)
public final class SecureBytes: @unchecked Sendable {
    private var storage: [UInt8]

    public var count: Int { storage.count }

    public var isEmpty: Bool { storage.isEmpty }

    public init(_ bytes: [UInt8]) {
        storage = bytes
    }

    public init(_ string: String) {
        storage = Array(string.utf8)
    }

    public init(count: Int, repeating value: UInt8 = 0) {
        storage = [UInt8](repeating: value, count: count)
    }

    public init() {
        storage = []
    }

    public convenience init(buffer: UnsafeRawBufferPointer) {
        self.init([UInt8](buffer))
    }

    public convenience init(pointer: UnsafeRawPointer, count: Int) {
        var bytes = [UInt8](repeating: 0, count: count)
        bytes.withUnsafeMutableBytes { dst in
            dst.copyMemory(from: UnsafeRawBufferPointer(start: pointer, count: count))
        }
        self.init(bytes)
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try storage.withUnsafeBytes(body)
    }

    public func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try storage.withUnsafeMutableBytes(body)
    }

    public subscript(index: Int) -> UInt8 {
        get { storage[index] }
        set { storage[index] = newValue }
    }

    public func append(_ bytes: [UInt8]) {
        storage.append(contentsOf: bytes)
    }

    public func append(_ byte: UInt8) {
        storage.append(byte)
    }

    public func wipe() {
        storage.withUnsafeMutableBytes { buffer in
            if let ptr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                secureWipe(ptr, count: buffer.count)
            }
        }
    }

    public func toArray() -> [UInt8] {
        return storage
    }

    deinit {
        // Wipe sensitive data before deallocation
        storage.withUnsafeMutableBytes { buffer in
            if let ptr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                secureWipe(ptr, count: buffer.count)
            }
        }
    }
}
