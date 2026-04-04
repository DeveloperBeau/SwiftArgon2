/// BLAKE2b G mixing function with direct array indexing (optimized)
/// a = a + b + m[blake2b_sigma[r][2*i+0]]
/// d = rotr64(d ^ a, 32)
/// c = c + d
/// b = rotr64(b ^ c, 24)
/// a = a + b + m[blake2b_sigma[r][2*i+1]]
/// d = rotr64(d ^ a, 16)
/// c = c + d
/// b = rotr64(b ^ c, 63)
@inline(__always)
func blake2bG(
    _ v: UnsafeMutablePointer<UInt64>,
    _ a: Int, _ b: Int, _ c: Int, _ d: Int,
    _ x: UInt64, _ y: UInt64
) {
    v[a] = v[a] &+ v[b] &+ x
    v[d] = rotr64(v[d] ^ v[a], 32)
    v[c] = v[c] &+ v[d]
    v[b] = rotr64(v[b] ^ v[c], 24)
    v[a] = v[a] &+ v[b] &+ y
    v[d] = rotr64(v[d] ^ v[a], 16)
    v[c] = v[c] &+ v[d]
    v[b] = rotr64(v[b] ^ v[c], 63)
}

func blake2bCompress(_ state: inout Blake2bState, _ block: UnsafeRawPointer) {
    // Use stack-allocated arrays for direct indexing (no switch statements)
    var m = (
        load64(block),
        load64(block + 8),
        load64(block + 16),
        load64(block + 24),
        load64(block + 32),
        load64(block + 40),
        load64(block + 48),
        load64(block + 56),
        load64(block + 64),
        load64(block + 72),
        load64(block + 80),
        load64(block + 88),
        load64(block + 96),
        load64(block + 104),
        load64(block + 112),
        load64(block + 120)
    )

    var v = (
        state.h.0,
        state.h.1,
        state.h.2,
        state.h.3,
        state.h.4,
        state.h.5,
        state.h.6,
        state.h.7,
        blake2bIV[0],
        blake2bIV[1],
        blake2bIV[2],
        blake2bIV[3],
        blake2bIV[4] ^ state.t.0,
        blake2bIV[5] ^ state.t.1,
        blake2bIV[6] ^ state.f.0,
        blake2bIV[7] ^ state.f.1
    )

    // Use pointer access to avoid switch statements
    withUnsafeMutablePointer(to: &v) { vPtr in
        vPtr.withMemoryRebound(to: UInt64.self, capacity: 16) { vArr in
            withUnsafePointer(to: &m) { mPtr in
                mPtr.withMemoryRebound(to: UInt64.self, capacity: 16) { mArr in
                    for r in 0..<12 {
                        let s = blake2bSigma[r]

                        blake2bG(vArr, 0, 4,  8, 12, mArr[s[0]],  mArr[s[1]])
                        blake2bG(vArr, 1, 5,  9, 13, mArr[s[2]],  mArr[s[3]])
                        blake2bG(vArr, 2, 6, 10, 14, mArr[s[4]],  mArr[s[5]])
                        blake2bG(vArr, 3, 7, 11, 15, mArr[s[6]],  mArr[s[7]])

                        blake2bG(vArr, 0, 5, 10, 15, mArr[s[8]],  mArr[s[9]])
                        blake2bG(vArr, 1, 6, 11, 12, mArr[s[10]], mArr[s[11]])
                        blake2bG(vArr, 2, 7,  8, 13, mArr[s[12]], mArr[s[13]])
                        blake2bG(vArr, 3, 4,  9, 14, mArr[s[14]], mArr[s[15]])
                    }
                }
            }
        }
    }

    state.h.0 ^= v.0 ^ v.8
    state.h.1 ^= v.1 ^ v.9
    state.h.2 ^= v.2 ^ v.10
    state.h.3 ^= v.3 ^ v.11
    state.h.4 ^= v.4 ^ v.12
    state.h.5 ^= v.5 ^ v.13
    state.h.6 ^= v.6 ^ v.14
    state.h.7 ^= v.7 ^ v.15
}

func blake2bCompress(_ state: inout Blake2bState, _ block: [UInt8], at offset: Int = 0) {
    block.withUnsafeBytes { buffer in
        blake2bCompress(&state, buffer.baseAddress! + offset)
    }
}
