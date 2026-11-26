# SwiftArgon2 FAQ

Frequently asked questions about SwiftArgon2, a pure Swift implementation of the Argon2 password hashing algorithm.

## Table of Contents

- [Performance](#performance)
- [Design Decisions](#design-decisions)
- [Security](#security)
- [Usage](#usage)
- [Platform Support](#platform-support)
- [Glossary](#glossary)

---

## Performance

### Why is Swift faster than C at small memory sizes but slower at large sizes?

At small memory sizes (64 KiB) with parallelism enabled, Swift can be **up to 3x faster than C** (0.32x ratio). This counterintuitive result comes from several factors:

1. **Threading overhead dominates at small sizes**: The C reference implementation spawns threads via pthreads, which has relatively high per-thread overhead. Swift's GCD uses a pre-warmed thread pool that's optimized for short-lived tasks, making it more efficient when the actual computation per thread is small.

2. **Memory allocation patterns**: At small sizes, allocation overhead matters more relative to compute time. Swift's contiguous memory pool eliminates per-block allocation overhead.

3. **At large memory sizes**: The bottleneck shifts from threading to memory bandwidth and cache efficiency. The C implementation uses hand-optimized assembly (SSE/AVX on x86, NEON on ARM) that's been tuned for years, giving it an edge in memory-intensive operations.

See [BENCHMARK.md](BENCHMARK.md) for detailed performance data across all configurations.

### Why doesn't Swift show linear scaling like C?

Swift's scaling behavior differs from C due to:

1. **GCD thread pool behavior**: `DispatchQueue.concurrentPerform` uses a work-stealing thread pool that dynamically adjusts thread count based on system conditions. This provides excellent average performance but can introduce variance.

2. **Memory bandwidth saturation**: At high parallelism (8 lanes) with large memory (65 MiB), both Swift and C become memory-bound. The C implementation's hand-tuned memory access patterns (prefetching, cache-aware ordering) give it an advantage here.

3. **No hand-written assembly**: Swift relies on the compiler for SIMD optimization, while C uses hand-tuned assembly for critical paths like the G/P permutation rounds.

### What optimizations were implemented?

Several optimizations bring Swift within 18% of C performance on average:

#### 1. GCD over async/await
See [`Sources/Argon2Core/FillMemory.swift:35-45`](Sources/Argon2Core/FillMemory.swift#L35-L45)

```swift
DispatchQueue.concurrentPerform(iterations: lanes) { lane in
    let position = Position(pass: pass, lane: UInt32(lane), slice: slice, index: 0)
    fillSegment(instance: instance, position: position)
}
```

`concurrentPerform` uses a work-stealing thread pool optimized for CPU-bound tasks with minimal per-iteration overhead, unlike `TaskGroup` which has significant per-task overhead.

#### 2. SIMD Block Operations
See [`Sources/Argon2Core/Block.swift:72-105`](Sources/Argon2Core/Block.swift#L72-L105)

```swift
UnsafeMutableRawPointer(storage).withMemoryRebound(to: SIMD8<UInt64>.self, capacity: 16) { dst in
    UnsafeRawPointer(source.storage).withMemoryRebound(to: SIMD8<UInt64>.self, capacity: 16) { src in
        for i in 0..<16 {
            dst[i] ^= src[i]
        }
    }
}
```

Block operations (copy, XOR) use `SIMD8<UInt64>` for vectorized processing, operating on 64 bytes at a time.

#### 3. Contiguous Memory Pool
See [`Sources/Argon2Core/Memory.swift:22-49`](Sources/Argon2Core/Memory.swift#L22-L49)

Instead of 65,536 separate allocations for a 64 MiB workload, a single page-aligned (16 KB) contiguous buffer is allocated. This improves TLB coverage and cache performance.

#### 4. 64-byte Aligned Allocations
See [`Sources/Argon2Core/Block.swift:22-27`](Sources/Argon2Core/Block.swift#L22-L27)

Block storage is aligned to 64 bytes (cache line size) for optimal SIMD performance and to avoid false sharing.

#### 5. Power-of-2 Modulo Optimization
For lane lengths that are powers of 2, expensive modulo operations are replaced with fast bitwise AND.

#### 6. Pre-allocated Workspace Blocks
See [`Sources/Argon2Core/Memory.swift:41-48`](Sources/Argon2Core/Memory.swift#L41-L48)

Each lane has 6 pre-allocated workspace blocks to avoid allocations in the hot path during segment filling.

### What is a work-stealing thread pool?

GCD uses work-stealing: each thread has its own work queue, and idle threads "steal" tasks from busy threads. This avoids a central bottleneck and automatically balances load. It's well-suited for uniform CPU-bound tasks like filling Argon2 memory segments.

### How does GCD compare to async/await for this workload?

For CPU-bound parallel workloads like Argon2, **GCD significantly outperforms async/await**:

| Approach | Characteristics |
|----------|----------------|
| **GCD** (`concurrentPerform`) | Work-stealing thread pool, minimal per-iteration overhead, optimized for CPU-bound tasks |
| **async/await** (`TaskGroup`) | Cooperative scheduling, per-task allocation, better for I/O-bound or heterogeneous tasks |

The implementation includes both (see [`Sources/Argon2Core/FillMemory.swift:18-31`](Sources/Argon2Core/FillMemory.swift#L18-L31) for async/await, [`35-45`](Sources/Argon2Core/FillMemory.swift#L35-L45) for GCD), but defaults to GCD for performance reasons.

In benchmarks, GCD reduced threading overhead by 40-50% compared to `TaskGroup`.

---

## Design Decisions

### Why pure Swift instead of C bindings?

1. **Compiler warnings**: Existing Swift wrappers for Argon2 rely on C bindings that trigger warnings about unsafe C function usage. Rather than suppress warnings or accept risks, a pure Swift implementation avoids these issues entirely.

2. **Swift 6 strict concurrency**: Pure Swift allows full compliance with Swift 6's strict concurrency checking (`Sendable` types, actor isolation, etc.) without unsafe escape hatches.

3. **No build complexity**: No need to manage C library compilation across platforms, handle header search paths, or deal with module map issues.

4. **Maintainability**: Swift code is easier to audit, modify, and extend for Swift developers.

5. **Correctness verification**: The test suite includes **1,000+ parameter combinations** verified against the C reference implementation, ensuring the pure Swift version produces identical output.

### Why use GCD instead of Swift Concurrency?

Swift Concurrency (`async/await`, `TaskGroup`) is designed for cooperative multitasking with excellent ergonomics for async I/O. However, for **CPU-bound parallel computation**, GCD is superior:

1. **Lower overhead**: `concurrentPerform` has minimal per-iteration overhead, while `TaskGroup.addTask` allocates a continuation and involves executor scheduling.

2. **Work stealing**: GCD's work-stealing scheduler is optimized for uniform CPU-bound tasks, automatically balancing load across cores.

3. **Predictable thread count**: GCD spawns threads equal to the iteration count (up to CPU cores), while Swift Concurrency may throttle based on its cooperative executor's heuristics.

4. **No executor overhead**: Swift Concurrency uses cooperative executors that periodically yield, which introduces latency for compute-heavy tasks that don't have suspension points.

The async API still exists for callers who need async/await compatibility; it simply wraps the GCD implementation.

### Why a contiguous memory pool?

Argon2 with 64 MiB of memory requires 65,536 individual 1 KiB blocks. Allocating these separately would mean:

1. **65,536 `malloc` calls**: Each with overhead for allocation metadata
2. **Fragmented virtual memory**: Poor TLB (Translation Lookaside Buffer) efficiency
3. **Poor spatial locality**: Blocks scattered across memory hurt prefetching
The contiguous pool solution (see [`Sources/Argon2Core/Memory.swift:27-31`](Sources/Argon2Core/Memory.swift#L27-L31)):

```swift
let totalBytes = blockCount * 1024
let pool = UnsafeMutableRawPointer.allocate(byteCount: totalBytes, alignment: 16384)
```

- **Single allocation**: One `allocate` call regardless of block count
- **Page alignment (16 KB)**: Optimal TLB coverage on Apple silicon
- **Perfect spatial locality**: Sequential blocks are physically sequential
- **Improved prefetching**: Hardware prefetchers can predict access patterns

### Why use a custom base64 implementation instead of Swift's built-in?

I couldn't use Swift's `Data.base64EncodedString()` directly for two reasons:

**1. No Padding Characters**

The PHC string format expects base64 **without** the usual `=` padding:

| Implementation | `"somesalt"` encoded |
|----------------|---------------------|
| Swift built-in | `c29tZXNhbHQ=` |
| This implementation | `c29tZXNhbHQ` |

Standard base64 pads output to multiples of 4 characters, but the PHC format skips this.

**2. Constant-Time Operations**

I needed timing-safe operations when handling password hashes and salts. The implementation uses constant-time comparison functions to avoid leaking information through timing:

```swift
@inline(__always)
private func eq(_ x: UInt, _ y: UInt) -> UInt {
    let diff = x ^ y
    return ((0 &- diff) >> 8 & 0xFF) ^ 0xFF
}
```

Swift's built-in base64 doesn't make any timing guarantees, which matters when you're dealing with security-sensitive data.

**Origin**: I ported this from Thomas Pornin's C reference implementation (CC0 Public Domain) to ensure compatibility with the official Argon2 PHC string format:

```
$argon2id$v=19$m=65536,t=3,p=4$<salt_b64>$<hash_b64>
```

---

## Security

### Is this implementation secure for production use?

**Use with appropriate caution.** This implementation:

**Has been verified for correctness:**
- 1,000+ parameter combinations tested against the C reference implementation
- All test vectors pass for Argon2d, Argon2i, and Argon2id
- Both algorithm versions (v1.0 and v1.3) are supported and tested

**Has NOT undergone:**
- Formal security audit by cryptography professionals
- Side-channel analysis or timing attack review
- Fuzzing for memory corruption vulnerabilities

**Recommendations:**
- For personal projects and non-critical applications: suitable for use
- For production systems with sensitive data: consider whether this meets your security requirements, or use a formally audited implementation
- For compliance-sensitive environments (HIPAA, PCI-DSS, etc.): consult your security team

### How is memory wiped securely?

Memory containing sensitive data (passwords, keys) is wiped using a technique that prevents compiler optimization from removing the operation:

See [`Sources/Argon2Core/Block.swift:158-170`](Sources/Argon2Core/Block.swift#L158-L170):

```swift
@inline(never)
public func secureWipe(_ ptr: UnsafeMutablePointer<UInt8>, count: Int) {
    for i in 0..<count {
        ptr[i] = 0
    }
    _fixLifetime(ptr)
}

@inline(never)
public func _fixLifetime<T>(_ value: T) {
    withExtendedLifetime(value) { _ in }
}
```

Key techniques:
1. **`@inline(never)`**: Prevents the compiler from inlining and potentially eliminating the wipe
2. **`_fixLifetime`**: Uses `withExtendedLifetime` to create an observable side effect that forces the compiler to actually perform the writes
3. **Explicit byte-by-byte zeroing**: Ensures every byte is overwritten

All blocks are wiped via the `wipe()` method on `Memory` (see [`Sources/Argon2Core/Memory.swift:124-133`](Sources/Argon2Core/Memory.swift#L124-L133)), which is called after finalization.

**Note**: This provides software-level protection. It does not protect against hardware-level attacks (cold boot, DMA) or compromised operating systems.

---

## Usage

### Which Argon2 variant should I use?

| Variant | Use Case | Notes |
|---------|----------|-------|
| **Argon2id** | General password hashing | **Recommended for most applications.** Hybrid of Argon2i and Argon2d, resistant to both side-channel and GPU attacks |
| **Argon2i** | When side-channel resistance is critical | Uses data-independent memory access. Slightly slower. Best for environments where timing attacks are a concern |
| **Argon2d** | Maximum GPU resistance | Data-dependent memory access makes it harder to parallelize on GPUs. Vulnerable to side-channel attacks |

**TL;DR**: Use **Argon2id** unless you have a specific reason not to.

### What are recommended parameters?

The implementation provides preset configurations:

```swift
// For interactive logins (fast, ~100ms target)
let config = Argon2Configuration.interactive
// m=65536 (64 MiB), t=1, p=4

// For sensitive data (moderate, ~500ms target)
let config = Argon2Configuration.moderate
// m=262144 (256 MiB), t=2, p=4

// For highly sensitive data (slow, ~1s+ target)
let config = Argon2Configuration.sensitive
// m=1048576 (1 GiB), t=3, p=4
```

**Guidelines:**

- **Memory (m)**: Use as much as your system can handle—more memory = harder to crack with GPUs/ASICs.
- **Time (t)**: Bump this up if you want slower hashing without using more RAM.
- **Parallelism (p)**: Match your core count. More lanes = more memory bandwidth required.

Start with `.moderate` and adjust based on measured performance on your target hardware.

### Async vs sync API - which to use?

| API | When to Use |
|-----|-------------|
| **Async** (`hashRawAsync`, `verifyAsync`) | In async contexts (SwiftUI, server handlers). Doesn't block the calling thread. |
| **Sync** (`hashRaw`, `verify`) | In synchronous contexts, background threads, or when you need deterministic timing. |

Both use the same underlying GCD-based implementation; the async versions simply wrap the sync versions in a way that's compatible with Swift Concurrency.

Example:
```swift
// Async context (e.g., SwiftUI button action)
Task {
    let hash = try await Argon2.hashRawAsync(password: pwd, salt: salt, configuration: .default)
}

// Sync context (e.g., background thread)
DispatchQueue.global().async {
    let hash = try Argon2.hashRaw(password: pwd, salt: salt, configuration: .default)
}
```

---

## Platform Support

### Why minimum iOS 15 / macOS 12?

The minimum deployment targets are:
- macOS 12.0 (Monterey)
- iOS 15.0
- tvOS 15.0
- watchOS 9.0
- visionOS 1.0

These are the lowest deployment targets Xcode 27.2 supports. The code itself would run on older OS versions because:

1. **Swift Concurrency back-deployment**: While Swift 6 is used for compilation, the concurrency runtime is back-deployed to these OS versions.

2. **GCD availability**: `DispatchQueue.concurrentPerform` has been available since these OS versions.

3. **Foundation APIs**: The Foundation APIs used (like `UnsafeMutableRawPointer.allocate`) are available on these older versions.

The implementation uses Swift 6 strict concurrency checking at compile time, but the runtime requirements are modest, allowing deployment to older devices.

### Does this work on Linux?

**Not currently.** The implementation depends on:

1. **`Dispatch` (GCD)**: While libdispatch exists on Linux, the `concurrentPerform` API behavior differs and performance characteristics vary.

2. **`mach_absolute_time`**: Used for high-resolution timing in benchmarks (could be replaced with `clock_gettime`).

3. **Apple-specific optimizations**: Some optimizations (like 16 KB page alignment) are tuned for Apple silicon.

**Potential Linux support** would require:

- Replacing GCD with a cross-platform thread pool (e.g., custom implementation or pthreads)
- Using portable timing APIs
- Testing and tuning for Linux memory allocators and page sizes
- Testing across different architectures (x86_64, ARM64)

Contributions for Linux support are welcome.

---

## Additional Questions?

If you have questions not covered here:

1. Check the [README](README.md) for usage examples
2. Review [BENCHMARK.md](BENCHMARK.md) for detailed performance data
3. Open an issue on the repository

### Feedback Welcome

This project was a learning experience for me, and I'd genuinely appreciate feedback if I've gotten anything wrong or described technical details inaccurately. If you spot errors in this FAQ, the implementation, or the documentation, please open an issue or submit a PR. I'm always looking to learn and improve.

---

## Glossary

| Term | Definition |
|------|------------|
| **ASIC** | Custom hardware for a single purpose (mining, cracking). Memory-hardness makes these attacks expensive. |
| **Cache line** | 64-byte unit of CPU cache. Alignment prevents false sharing. |
| **False sharing** | Threads invalidating each other's cache by accessing different data on the same cache line. |
| **GCD** | Grand Central Dispatch — Apple's thread pool / work scheduling library. |
| **Memory-hard** | Requires lots of memory, making GPU/ASIC parallelization expensive. |
| **Page alignment** | Aligning to OS page boundaries (4-16 KB). Improves TLB efficiency. |
| **Prefetching** | CPU loading data into cache before it's needed. Sequential access helps. |
| **SIMD** | Single Instruction, Multiple Data — operate on multiple values at once. |
| **Side-channel attack** | Exploits timing, power, or other physical leaks rather than crypto weaknesses. |
| **TLB** | Translation Lookaside Buffer — CPU cache for address translations. Misses are expensive. |
| **Work-stealing** | Idle threads "steal" work from busy threads' queues. |

