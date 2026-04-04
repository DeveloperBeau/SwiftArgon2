import Argon2Core

public func encodeHash(
    type: Argon2Variant,
    version: Argon2Version,
    memoryCost: UInt32,
    timeCost: UInt32,
    parallelism: UInt32,
    salt: [UInt8],
    hash: [UInt8]
) -> String {
    var result = "$\(type.name)"

    result += "$v=\(version.rawValue)"
    result += "$m=\(memoryCost),t=\(timeCost),p=\(parallelism)"
    result += "$\(base64Encode(salt))"
    result += "$\(base64Encode(hash))"

    return result
}

public func encodedLength(
    type: Argon2Variant,
    memoryCost: UInt32,
    timeCost: UInt32,
    parallelism: UInt32,
    saltLength: Int,
    hashLength: Int
) -> Int {
    var len = 1 + type.name.count
    len += 4 + 2
    len += 3 + numLength(memoryCost)
    len += 3 + numLength(timeCost)
    len += 3 + numLength(parallelism)
    len += 1 + base64EncodedLength(saltLength)
    len += 1 + base64EncodedLength(hashLength)
    return len
}

private func numLength(_ num: UInt32) -> Int {
    var n = num
    var len = 1
    while n >= 10 {
        len += 1
        n /= 10
    }
    return len
}
