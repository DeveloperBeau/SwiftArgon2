# Implementation Assumptions & Deviations

This is a pure Swift port of the Argon2 reference implementation. The hash outputs match the C reference exactly—you can verify this against the official test vectors. This document exists to help anyone auditing the code or contributing to understand why I made certain choices that differ from the C implementation.

## Threading

The C code uses pthreads (or Windows threads) with explicit thread create/join per lane. I went with GCD's `concurrentPerform` instead—it's a work-stealing pool that handles the scheduling, and the overhead is substantially lower for CPU-bound work like this.

There's also a threshold check: if `segmentLength < 64`, threading is skipped entirely and it runs single-threaded. The C code doesn't do this—it'll spawn threads even when the overhead exceeds the benefit. For small memory configs, single-threaded is actually faster.

There's also an async/await API that uses `TaskGroup`, but GCD is the default because TaskGroup has ~20-30μs per-task overhead that adds up across thousands of iterations. The async API is there for when you need structured concurrency integration.

See `FillMemory.swift:5` for the threshold constant and `FillMemory.swift:35-45` for the GCD implementation.

## Memory Layout

C does a straightforward malloc for the block array (with optional custom allocator callbacks). This implementation does a single 16KB page-aligned allocation for the entire memory pool, then creates `Block` views into it. This gives better TLB coverage and avoids thousands of individual allocations.

```swift
// From Memory.swift:29
let pool = UnsafeMutableRawPointer.allocate(byteCount: totalBytes, alignment: 16384)
```

I also pre-allocate 6 workspace blocks per lane (`blockR`, `blockTmp`, `zeroBlock`, `inputBlock`, `addressBlock`, `tempBlock`). The C code stack-allocates these in `fill_block` on every call. Pre-allocating means zero allocations in the hot path—every allocation during hashing comes from the upfront pool.

Custom allocator callbacks aren't supported. Haven't seen a real need for them in Swift land, and they'd complicate the memory pooling.

## Blocks

C uses `struct block { uint64_t v[128]; }`—value semantics, so passing a block around copies 1KB. This implementation uses a `final class Block` with reference semantics. No copying, just pointer passing.

The storage is `UnsafeMutablePointer<UInt64>` rather than a fixed array, which allows pool views without extra indirection. The `Block` class tracks whether it owns its storage (for workspace blocks) or is a view into the pool.

```swift
// From Block.swift:14-19
public final class Block: @unchecked Sendable {
    internal let storage: UnsafeMutablePointer<UInt64>
    private let ownsStorage: Bool
    // ...
}
```

## SIMD

The C reference has `opt.c` with hand-tuned AVX-512, AVX2, and SSE variants. Swift doesn't expose those intrinsics directly.

I use `SIMD8<UInt64>` (64-byte vectors) for block operations like copy and XOR—that's what's available in Swift's SIMD types. The BlaMka compression function stays scalar with direct pointer access; trying to vectorize it in Swift wasn't worth the complexity and didn't show meaningful gains in benchmarks.

```swift
// From Block.swift:72-79
public func copy(from source: Block) {
    UnsafeMutableRawPointer(storage).withMemoryRebound(to: SIMD8<UInt64>.self, capacity: 16) { dst in
        UnsafeRawPointer(source.storage).withMemoryRebound(to: SIMD8<UInt64>.self, capacity: 16) { src in
            for i in 0..<16 {
                dst[i] = src[i]
            }
        }
    }
}
```

## Secure Memory Wiping

C uses platform-specific approaches: `SecureZeroMemory` on Windows, `explicit_bzero` on glibc 2.25+, or a volatile pointer trick as fallback. There's also a `NOT_OPTIMIZED` attribute to prevent the compiler from optimizing away the zeroing.

Swift doesn't have `explicit_bzero`. I do byte-by-byte zeroing with `@inline(never)` on the wipe function and `_fixLifetime` (wrapping `withExtendedLifetime`) to create an observable side effect. This prevents the compiler from seeing "this memory is never read after zeroing" and optimizing it away.

```swift
// From Block.swift:159-170
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

The combination of `@inline(never)` plus the lifetime extension should prevent dead-store elimination in current Swift compilers. That said, this could break—compiler optimizations evolve, and Swift doesn't provide the same guarantees that C's `volatile` or `explicit_bzero` do.

## Defaults

The C CLI defaults to 4 MiB memory, t=3, p=1. That's pretty conservative—reasonable for 2015-era hardware.

The presets here are higher because I'm targeting iOS 13+ / macOS 10.15+ where devices have plenty of RAM:

| Preset | Memory | Time Cost | Parallelism | Use Case |
|--------|--------|-----------|-------------|----------|
| `interactive` | 64 MiB | 2 | 1 | Login forms, low latency |
| `moderate` | 64 MiB | 3 | 4 | General purpose |
| `sensitive` | 128 MiB | 4 | 4 | High-value data |

These align with [OWASP password storage recommendations](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html). You can always create a custom `Argon2Configuration` if you need different parameters.

## Index Alpha Optimization

When lane length is a power of 2, I pre-compute a bitmask and use bitwise AND instead of modulo in `indexAlpha`. C always does modulo. This is a small win but it's free.

```swift
// From Instance.swift:109-110
let ll = self.laneLength
self.laneLengthMask = (ll & (ll - 1)) == 0 ? (ll - 1) : nil

// From IndexAlpha.swift:79-84
if let mask = instance.laneLengthMask {
    absolutePosition = (startPosition &+ UInt32(relativePosition)) & mask
} else {
    absolutePosition = (startPosition &+ UInt32(relativePosition)) % instance.laneLength
}
```

Most common memory configurations (64 MiB, 128 MiB, etc.) result in power-of-2 lane lengths, so this applies in practice.

## Error Handling

C returns integer error codes; you call `argon2_error_message()` to get the string. This implementation uses a Swift `Argon2Error` enum with `throw`/`try`/`catch`. Same granularity of errors, just idiomatic Swift.

The raw values match the C error codes for anyone doing interop or comparing behavior:

```swift
// From Argon2Error.swift
public enum Argon2Error: Int, Error, Sendable, CaseIterable {
    case ok = 0
    case outputPointerNull = -1
    case outputTooShort = -2
    // ... etc
}
```

## Quick Reference: What's Different

**C has, this doesn't:**
- Custom allocator callbacks
- `ARGON2_NO_THREADS` compile flag (runtime threshold instead)
- GENKAT debug output mode

**This has, C doesn't:**
- async/await API alongside synchronous
- Named configuration presets (`interactive`, `moderate`, `sensitive`)
- Threading threshold (skip threads for small workloads)
- Power-of-2 lane length optimization
- Memory pooling with pre-allocated workspace blocks
