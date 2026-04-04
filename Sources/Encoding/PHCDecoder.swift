import Argon2Core

public struct DecodedHash: Sendable {
    public let type: Argon2Variant
    public let version: Argon2Version
    public let memoryCost: UInt32
    public let timeCost: UInt32
    public let parallelism: UInt32
    public let salt: [UInt8]
    public let hash: [UInt8]

    public init(
        type: Argon2Variant,
        version: Argon2Version,
        memoryCost: UInt32,
        timeCost: UInt32,
        parallelism: UInt32,
        salt: [UInt8],
        hash: [UInt8]
    ) {
        self.type = type
        self.version = version
        self.memoryCost = memoryCost
        self.timeCost = timeCost
        self.parallelism = parallelism
        self.salt = salt
        self.hash = hash
    }
}

public enum DecodingError: Error, Sendable {
    case invalidFormat
    case invalidType
    case invalidVersion
    case invalidParameter
    case invalidSalt
    case invalidHash
    case saltTooShort
    case hashTooShort
}

public func decodeHash(_ encoded: String) throws -> DecodedHash {
    var remaining = encoded[...]

    guard remaining.hasPrefix("$argon2") else {
        throw DecodingError.invalidFormat
    }
    remaining = remaining.dropFirst(7)

    let type: Argon2Variant
    if remaining.hasPrefix("id") {
        type = .argon2id
        remaining = remaining.dropFirst(2)
    } else if remaining.hasPrefix("i") {
        type = .argon2i
        remaining = remaining.dropFirst(1)
    } else if remaining.hasPrefix("d") {
        type = .argon2d
        remaining = remaining.dropFirst(1)
    } else {
        throw DecodingError.invalidType
    }

    var version = Argon2Version.v10
    if remaining.hasPrefix("$v=") {
        remaining = remaining.dropFirst(3)
        let (versionValue, rest) = try parseDecimal(remaining)
        remaining = rest

        guard let v = Argon2Version(rawValue: UInt32(versionValue)) else {
            throw DecodingError.invalidVersion
        }
        version = v
    }

    guard remaining.hasPrefix("$m=") else {
        throw DecodingError.invalidFormat
    }
    remaining = remaining.dropFirst(3)

    let (memoryCost, afterMemory) = try parseDecimal(remaining)
    remaining = afterMemory

    guard remaining.hasPrefix(",t=") else {
        throw DecodingError.invalidFormat
    }
    remaining = remaining.dropFirst(3)

    let (timeCost, afterTime) = try parseDecimal(remaining)
    remaining = afterTime

    guard remaining.hasPrefix(",p=") else {
        throw DecodingError.invalidFormat
    }
    remaining = remaining.dropFirst(3)

    let (parallelism, afterParallelism) = try parseDecimal(remaining)
    remaining = afterParallelism

    guard remaining.hasPrefix("$") else {
        throw DecodingError.invalidFormat
    }
    remaining = remaining.dropFirst(1)

    let (saltB64, afterSalt) = parseBase64(remaining)
    remaining = afterSalt

    guard let salt = base64Decode(String(saltB64)) else {
        throw DecodingError.invalidSalt
    }

    if salt.count < 8 {
        throw DecodingError.saltTooShort
    }

    guard remaining.hasPrefix("$") else {
        throw DecodingError.invalidFormat
    }
    remaining = remaining.dropFirst(1)

    let (hashB64, afterHash) = parseBase64(remaining)
    remaining = afterHash

    guard let hash = base64Decode(String(hashB64)) else {
        throw DecodingError.invalidHash
    }

    if hash.count < 4 {
        throw DecodingError.hashTooShort
    }

    guard remaining.isEmpty else {
        throw DecodingError.invalidFormat
    }

    return DecodedHash(
        type: type,
        version: version,
        memoryCost: UInt32(memoryCost),
        timeCost: UInt32(timeCost),
        parallelism: UInt32(parallelism),
        salt: salt,
        hash: hash
    )
}

private func parseDecimal(_ str: Substring) throws -> (UInt64, Substring) {
    var value: UInt64 = 0
    var index = str.startIndex
    var hasDigits = false

    while index < str.endIndex {
        let c = str[index]
        guard let digit = c.asciiValue, digit >= 0x30 && digit <= 0x39 else {
            break
        }

        let d = UInt64(digit - 0x30)

        // Check for overflow
        if value > (UInt64.max / 10) {
            throw DecodingError.invalidParameter
        }
        value *= 10

        if d > (UInt64.max - value) {
            throw DecodingError.invalidParameter
        }
        value += d

        hasDigits = true
        index = str.index(after: index)
    }

    // Check for no digits or invalid leading zero
    if !hasDigits {
        throw DecodingError.invalidParameter
    }

    if str.first == "0" && str.startIndex != str.index(before: index) {
        throw DecodingError.invalidParameter
    }

    return (value, str[index...])
}

private func parseBase64(_ str: Substring) -> (Substring, Substring) {
    var index = str.startIndex

    while index < str.endIndex {
        let c = str[index]
        guard let ascii = c.asciiValue else { break }

        // Base64 alphabet: A-Z, a-z, 0-9, +, /
        let isBase64 =
            (ascii >= 0x41 && ascii <= 0x5A) ||
            (ascii >= 0x61 && ascii <= 0x7A) ||
            (ascii >= 0x30 && ascii <= 0x39) ||
            ascii == 0x2B ||
            ascii == 0x2F

        if !isBase64 { break }
        index = str.index(after: index)
    }

    return (str[..<index], str[index...])
}

public func decodeHash(_ encoded: String, expectedType: Argon2Variant) throws -> DecodedHash {
    let decoded = try decodeHash(encoded)

    guard decoded.type == expectedType else {
        throw DecodingError.invalidType
    }

    return decoded
}
