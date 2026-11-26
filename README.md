# SwiftArgon2

A pure Swift 6 implementation of the Argon2 password hashing algorithm.

## Motivation

I wanted to use Argon2 in a personal Swift project, but the existing Swift wrappers rely on C bindings that trigger compiler warnings about unsafe C function usage. Rather than suppress these warnings or accept the risks, I decided to create a pure Swift implementation from scratch.

This project is a loving recreation of the Argon2 algorithm, built entirely in Swift without any C dependencies in the core implementation. To ensure correctness, I've included the original C reference implementation as a test dependency and wrote tests with **1,000+ parameter combinations** that verify the Swift output matches the C output exactly.

## Features

- Pure Swift 6 implementation with strict concurrency (`Sendable` compliance)
- All three Argon2 variants: Argon2d, Argon2i, and Argon2id
- Both algorithm versions: v1.0 (0x10) and v1.3 (0x13)
- PHC string format encoding/decoding for password storage
- Async/await API for non-blocking password hashing
- Parallel lane processing using Swift's structured concurrency
- Secure memory handling with explicit wiping
- iOS, macOS, tvOS, watchOS, and visionOS support

## Installation

### Swift Package Manager

Add the following to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/developerbeau/SwiftArgon2.git", from: "1.0.0")
]
```

Then add the `SwiftArgon2` product to your target dependencies:

```swift
.target(
    name: "YourTarget",
    dependencies: [.product(name: "SwiftArgon2", package: "SwiftArgon2")]
)
```

## Usage

### Basic Password Hashing

```swift
import SwiftArgon2

// Hash a password with default settings (Argon2id, recommended for most uses)
let salt = Argon2.generateSalt(length: 16)
let encoded = try Argon2.hashEncoded(
    password: "my secure password",
    salt: salt,
    configuration: .default
)
// Result: "$argon2id$v=19$m=65536,t=3,p=4$..."
```

### Password Verification

```swift
import SwiftArgon2

let isValid = try Argon2.verify(
    password: "my secure password",
    encoded: storedHash
)
```

### Custom Configuration

```swift
import SwiftArgon2

let config = Argon2Configuration(
    variant: .argon2id,      // argon2d, argon2i, or argon2id
    version: .v13,           // v10 or v13
    timeCost: 3,             // Number of iterations
    memoryCost: 65536,       // Memory usage in KiB (64 MiB)
    parallelism: 4,          // Number of parallel lanes
    hashLength: 32           // Output hash length in bytes
)

let hash = try Argon2.hashRaw(
    password: "password",
    salt: salt,
    configuration: config
)
```

### Async API

```swift
import SwiftArgon2

// Non-blocking hash for use in async contexts
let hash = try await Argon2.hashRawAsync(
    password: "password",
    salt: salt,
    configuration: .default
)

let isValid = try await Argon2.verifyAsync(
    password: "password",
    encoded: storedHash
)
```

### Preset Configurations

```swift
// For interactive logins (fast, lower security)
let config = Argon2Configuration.interactive

// For sensitive data (slower, higher security)
let config = Argon2Configuration.moderate

// For highly sensitive data (slowest, highest security)
let config = Argon2Configuration.sensitive
```

## Testing & Verification

This implementation includes comprehensive tests to ensure correctness:

- **115 tests** across 7 test suites
- **1,000+ parameter combinations** compared against the C reference implementation
- Tests cover all variants (Argon2d, Argon2i, Argon2id), both versions (v1.0, v1.3), and various parameter ranges
- BLAKE2b hash function verified against RFC 7693 test vectors

Run all tests (recommended):

```bash
bash test.sh
```

### C Reference Tests

The `CReferenceTests` target compares Swift output against the C reference implementation from [phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2). It runs from `swift test`, `xcodebuild test`, and Xcode's Test Navigator.

The public module is named `SwiftArgon2` rather than `Argon2` so its build products do not collide with the C module `argon2` on case-insensitive file systems.

## Performance

This implementation achieves near-C performance while remaining pure Swift.

### Benchmark Results

Tested on Apple M4 with 10 cores (288 configurations across all variants):

| Memory (KiB) | Swift/C Ratio | Notes |
|-------------:|--------------:|-------|
| 64           | **0.86x**     | Swift faster than C |
| 256          | **0.99x**     | Near parity |
| 1024         | 1.23x         | 23% slower than C |
| 4096         | 1.27x         | 27% slower than C |
| 16384        | 1.34x         | 34% slower than C |
| 65536        | 1.39x         | 39% slower than C |

**Overall average: 1.18x** (Swift is only 18% slower than the optimized C reference implementation)

At small memory sizes with parallelism, Swift is actually **faster** than C due to GCD's pre-warmed thread pool having lower overhead than pthreads for short-lived tasks. Ratios as low as **0.32x** (Swift 3x faster) have been observed.

| Parallelism | Avg Ratio | Notes |
|------------:|----------:|-------|
| p=1         | 1.37x     | Single-threaded |
| p=2         | 1.05x     | Near parity |
| p=4         | 1.11x     | Near parity |
| p=8         | 1.19x     | Some overhead |

### Performance Considerations

While this pure Swift implementation achieves competitive performance with the C reference (averaging only 18% slower), **there is a measurable performance impact** compared to using C bindings directly.

For my personal projects with moderate hashing loads, this trade-off was acceptable—the benefits of avoiding C compiler warnings about unsafe function usage and having a pure Swift dependency outweighed the performance difference.

**You should evaluate your own requirements:**
- For high-throughput scenarios (thousands of hashes per second), the C implementation may be more appropriate
- For typical application use (user authentication, occasional password hashing), the performance difference is negligible
- If you value Swift 6 strict concurrency compliance, no C dependencies, and cleaner builds, this implementation offers those benefits

The choice between raw performance and safer compatibility depends on your specific use case.

### Optimization Techniques

This implementation uses several techniques to achieve high performance:

#### 1. GCD over async/await for Parallelism

Swift's `async/await` with `TaskGroup` has significant per-task overhead that hurts performance for CPU-bound workloads. This implementation uses `DispatchQueue.concurrentPerform` instead, which provides a work-stealing thread pool optimized for parallel computation with minimal overhead.

```swift
// Instead of TaskGroup (high overhead):
await withTaskGroup(of: Void.self) { group in
    for lane in 0..<lanes {
        group.addTask { fillSegment(lane) }
    }
}

// GCD (low overhead):
DispatchQueue.concurrentPerform(iterations: lanes) { lane in
    fillSegment(lane)
}
```

#### 2. SIMD Block Operations

Block operations (copy, XOR) use `SIMD8<UInt64>` for vectorized processing, operating on 64 bytes at a time instead of scalar operations.

```swift
// SIMD-accelerated XOR
UnsafeMutableRawPointer(storage).withMemoryRebound(to: SIMD8<UInt64>.self, capacity: 16) { dst in
    UnsafeRawPointer(source.storage).withMemoryRebound(to: SIMD8<UInt64>.self, capacity: 16) { src in
        for i in 0..<16 {
            dst[i] ^= src[i]
        }
    }
}
```

#### 3. Contiguous Memory Pool

Instead of allocating each 1 KiB block separately (which would mean 65,536 allocations for a 64 MiB workload), this implementation allocates a single contiguous memory region with page alignment (16 KB) for better TLB coverage and cache performance.

```swift
// Single allocation for all blocks
let pool = UnsafeMutableRawPointer.allocate(byteCount: blockCount * 1024, alignment: 16384)

// Blocks are views into the contiguous pool
for i in 0..<blockCount {
    blocks.append(Block(storage: (pool + i * 1024).assumingMemoryBound(to: UInt64.self)))
}
```

#### 4. 64-byte Aligned Allocations

Block storage is aligned to 64 bytes (cache line size) for optimal SIMD performance and to avoid false sharing in parallel workloads.

#### 5. Power-of-2 Modulo Optimization

For lane lengths that are powers of 2 (common case), expensive modulo operations are replaced with fast bitwise AND:

```swift
// Pre-computed at initialization
let laneLengthMask: UInt32? = (laneLength & (laneLength - 1)) == 0 ? (laneLength - 1) : nil

// Fast path in hot loop
if let mask = instance.laneLengthMask {
    absolutePosition = (startPosition &+ relativePosition) & mask  // Fast
} else {
    absolutePosition = (startPosition &+ relativePosition) % instance.laneLength  // Slow
}
```

#### 6. Pre-allocated Workspace Blocks

Each lane has 6 pre-allocated workspace blocks to avoid allocations in the hot path during segment filling. This includes blocks for the main fill operation (`blockR`, `blockTmp`) and blocks for data-independent address generation (`zeroBlock`, `inputBlock`, `addressBlock`, `tempBlock`).

```swift
// Pre-allocate all workspace blocks per lane
let (blockR, blockTmp, zeroBlock, inputBlock, addressBlock, tempBlock) =
    memory.getFullWorkspace(lane: Int(position.lane))
```

#### 7. Direct Memory Copy for Load/Store

On little-endian systems (all Apple silicon), block load and store operations use direct `copyMemory` instead of per-element loops with endian conversion, since `.littleEndian` is a no-op.

```swift
#if _endian(little)
public func load(from bytes: UnsafeRawPointer) {
    UnsafeMutableRawPointer(storage).copyMemory(from: bytes, byteCount: 1024)
}
#endif
```

### Running Benchmarks

To benchmark Swift against the C reference implementation:

```bash
./benchmark.sh
```

Results are written to `BENCHMARK.md` with detailed per-configuration timings.

## Architecture

```
Sources/
├── SwiftArgon2/      # Public API
├── Argon2Core/       # Core algorithm implementation
├── Blake2b/          # BLAKE2b hash function
└── Encoding/         # PHC string format encoding
```

## Platform Support

| Platform  | Minimum Version |
|-----------|-----------------|
| macOS     | 12.0            |
| iOS       | 15.0            |
| tvOS      | 15.0            |
| watchOS   | 9.0             |
| visionOS  | 1.0             |
| Android   | Swift SDK for Android (Swift 6.4) |

Requires Swift 6.4 / Xcode 27.2 or later. The Apple minimums match the lowest deployment targets Xcode 27.2 supports.

## Credits & Acknowledgments

This project recreates the Argon2 algorithm in Swift. It is not affiliated with, endorsed by, or connected to the original Argon2 project or its creators.

### Original Argon2 Authors

Immense gratitude to the creators of the Argon2 algorithm:

- **Daniel Dinu**
- **Dmitry Khovratovich**
- **Jean-Philippe Aumasson**
- **Samuel Neves**

The original C reference implementation is available at:
https://github.com/P-H-C/phc-winner-argon2

### Contributors to the Original Project

Special thanks to everyone who contributed bindings, improvements, and ports that helped make Argon2 accessible across many platforms:

- **Thomas Pornin** - String encoding routines
- **@lambdapioneer** - Android/Java/Kotlin bindings
- **@tmthecoder** - Dart and Swift bindings
- **@riverrun** - Elixir bindings
- **@ergenius** - Erlang bindings
- **@tvdburgt** - Go bindings
- **@hvr** - Haskell bindings
- **@ranisalt**, **@jdconley** - JavaScript native bindings
- **@cjlarose** - JavaScript FFI bindings
- **@antelle** - JavaScript browser implementation
- **@phXql** - JVM bindings
- **@kosprov** - JVM with keyed hashing
- **@thibaultCha** - Lua native and FFI bindings
- **@Khady** - OCaml bindings
- **@flamewow** - Python native bindings
- **@hynek**, **@thusoy**, **@ultrahorizon** - Python FFI bindings
- **@wrathematics** - R bindings
- **@technion** - Ruby bindings
- **@quininer** - Rust bindings
- **@bcmyers** - Rust Argonautica
- **@kmaragon** - C#/.NET CoreCLR bindings
- **@leont** - Perl bindings
- **@Asmod4n** - mruby bindings
- **@ImKcat** - Swift bindings

And thank you to all the researchers, cryptographers, and developers who participated in the Password Hashing Competition and continue to advance the field of password security.

## License

This Swift implementation is released under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.

The original Argon2 reference implementation is dual-licensed under CC0 1.0 and Apache 2.0.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

This project was a learning experience for me, so if you find any improvements—whether it's performance optimizations, bug fixes, documentation clarifications, or corrections to technical details—please open a PR and I'll review it as soon as I can. I'm always happy to learn from the community.

## Security Notice

If you discover a security vulnerability, please report it responsibly. This implementation has been tested extensively against the C reference implementation but has not undergone formal security audits.

For production use with sensitive data, please evaluate whether this implementation meets your security requirements.
