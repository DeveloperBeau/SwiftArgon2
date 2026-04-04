/// fBlaMka mixing function
/// Returns x + y + 2 * trunc32(x) * trunc32(y)
/// This provides multiplication-hardening compared to regular BLAKE2b
@inline(__always)
public func fBlaMka(_ x: UInt64, _ y: UInt64) -> UInt64 {
    let m: UInt64 = 0xFFFFFFFF
    let xy = (x & m) &* (y & m)
    return x &+ y &+ (xy &<< 1)  // Shift instead of multiply by 2
}

/// G function for Argon2 (using fBlaMka instead of addition)
/// a = fBlaMka(a, b)
/// d = rotr64(d ^ a, 32)
/// c = fBlaMka(c, d)
/// b = rotr64(b ^ c, 24)
/// a = fBlaMka(a, b)
/// d = rotr64(d ^ a, 16)
/// c = fBlaMka(c, d)
/// b = rotr64(b ^ c, 63)
@inline(__always)
public func blamkaG(_ a: inout UInt64, _ b: inout UInt64, _ c: inout UInt64, _ d: inout UInt64) {
    a = fBlaMka(a, b)
    d = rotr64(d ^ a, 32)
    c = fBlaMka(c, d)
    b = rotr64(b ^ c, 24)
    a = fBlaMka(a, b)
    d = rotr64(d ^ a, 16)
    c = fBlaMka(c, d)
    b = rotr64(b ^ c, 63)
}

/// BLAKE2 round without message addition (for Argon2)
/// Applies 8 G functions: 4 columns then 4 diagonals
@inline(__always)
public func blake2RoundNoMsg(
    _ v0: inout UInt64, _ v1: inout UInt64, _ v2: inout UInt64, _ v3: inout UInt64,
    _ v4: inout UInt64, _ v5: inout UInt64, _ v6: inout UInt64, _ v7: inout UInt64,
    _ v8: inout UInt64, _ v9: inout UInt64, _ v10: inout UInt64, _ v11: inout UInt64,
    _ v12: inout UInt64, _ v13: inout UInt64, _ v14: inout UInt64, _ v15: inout UInt64
) {
    // Column step
    blamkaG(&v0, &v4, &v8, &v12)
    blamkaG(&v1, &v5, &v9, &v13)
    blamkaG(&v2, &v6, &v10, &v14)
    blamkaG(&v3, &v7, &v11, &v15)

    // Diagonal step
    blamkaG(&v0, &v5, &v10, &v15)
    blamkaG(&v1, &v6, &v11, &v12)
    blamkaG(&v2, &v7, &v8, &v13)
    blamkaG(&v3, &v4, &v9, &v14)
}
