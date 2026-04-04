// Constant-time comparison primitives (return 0xFF on true, 0x00 on false)
@inline(__always)
private func eq(_ x: UInt, _ y: UInt) -> UInt {
    let diff = x ^ y
    return ((0 &- diff) >> 8 & 0xFF) ^ 0xFF
}

@inline(__always)
private func gt(_ x: UInt, _ y: UInt) -> UInt {
    return ((y &- x) >> 8) & 0xFF
}

@inline(__always)
private func ge(_ x: UInt, _ y: UInt) -> UInt {
    return gt(y, x) ^ 0xFF
}

@inline(__always)
private func lt(_ x: UInt, _ y: UInt) -> UInt {
    return gt(y, x)
}

@inline(__always)
private func le(_ x: UInt, _ y: UInt) -> UInt {
    return ge(y, x)
}

@inline(__always)
private func base64ByteToChar(_ x: UInt) -> UInt8 {
    let a = UInt(UInt8(ascii: "A"))
    let z = UInt(UInt8(ascii: "a"))
    let zero = UInt(UInt8(ascii: "0"))
    let plus = UInt(UInt8(ascii: "+"))
    let slash = UInt(UInt8(ascii: "/"))

    let result =
        (lt(x, 26) & (x &+ a)) |
        (ge(x, 26) & lt(x, 52) & (x &+ (z &- 26))) |
        (ge(x, 52) & lt(x, 62) & (x &+ (zero &- 52))) |
        (eq(x, 62) & plus) |
        (eq(x, 63) & slash)

    return UInt8(result & 0xFF)
}

@inline(__always)
private func base64CharToByte(_ c: UInt8) -> UInt {
    let cu = UInt(c)
    let a = UInt(UInt8(ascii: "A"))
    let az = UInt(UInt8(ascii: "Z"))
    let la = UInt(UInt8(ascii: "a"))
    let lz = UInt(UInt8(ascii: "z"))
    let zero = UInt(UInt8(ascii: "0"))
    let nine = UInt(UInt8(ascii: "9"))
    let plus = UInt(UInt8(ascii: "+"))
    let slash = UInt(UInt8(ascii: "/"))

    var x: UInt = 0
    x |= (ge(cu, a) & le(cu, az) & (cu &- a))
    x |= (ge(cu, la) & le(cu, lz) & (cu &- la &+ 26))
    x |= (ge(cu, zero) & le(cu, nine) & (cu &- zero &+ 52))
    x |= (eq(cu, plus) & 62)
    x |= (eq(cu, slash) & 63)
    x |= (eq(x, 0) & (eq(cu, a) ^ 0xFF))

    return x
}

public func base64Encode(_ data: [UInt8]) -> String {
    if data.isEmpty {
        return ""
    }

    var outputLen = (data.count / 3) * 4
    switch data.count % 3 {
    case 2: outputLen += 3
    case 1: outputLen += 2
    default: break
    }

    var output = [UInt8](repeating: 0, count: outputLen)
    var acc: UInt = 0
    var accLen: Int = 0
    var outputIndex = 0

    for byte in data {
        acc = (acc << 8) | UInt(byte)
        accLen += 8

        while accLen >= 6 {
            accLen -= 6
            output[outputIndex] = base64ByteToChar((acc >> accLen) & 0x3F)
            outputIndex += 1
        }
    }

    if accLen > 0 {
        output[outputIndex] = base64ByteToChar((acc << (6 - accLen)) & 0x3F)
    }

    return String(decoding: output, as: UTF8.self)
}

public func base64Decode(_ string: String) -> [UInt8]? {
    if string.isEmpty {
        return []
    }

    let chars = Array(string.utf8)

    var outputLen = (chars.count / 4) * 3
    switch chars.count % 4 {
    case 3: outputLen += 2
    case 2: outputLen += 1
    case 1: return nil // Invalid length
    default: break
    }

    var output = [UInt8](repeating: 0, count: outputLen)
    var acc: UInt = 0
    var accLen: Int = 0
    var outputIndex = 0

    for char in chars {
        let d = base64CharToByte(char)
        if d == 0xFF {
            if outputIndex == 0 {
                return nil
            }
            break
        }

        acc = (acc << 6) | d
        accLen += 6

        if accLen >= 8 {
            accLen -= 8
            if outputIndex < output.count {
                output[outputIndex] = UInt8((acc >> accLen) & 0xFF)
                outputIndex += 1
            }
        }
    }

    if outputIndex < output.count {
        output = Array(output.prefix(outputIndex))
    }

    return output
}

public func base64EncodedLength(_ byteCount: Int) -> Int {
    var len = (byteCount / 3) * 4
    switch byteCount % 3 {
    case 2: len += 3
    case 1: len += 2
    default: break
    }
    return len
}
