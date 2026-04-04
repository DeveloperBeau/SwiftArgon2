@_exported import Argon2Core
import Encoding

#if canImport(Security)
import Security
#endif


/// Main Argon2 API
public enum Argon2 {

    // MARK: - Raw Hash Functions

    /// Hash a password and return the raw hash bytes
    ///
    /// - Parameters:
    ///   - password: The password to hash
    ///   - salt: Random salt (minimum 8 bytes, recommended 16+ bytes)
    ///   - configuration: Hashing parameters
    ///   - secret: Optional secret key for keyed hashing
    ///   - associatedData: Optional associated data
    /// - Returns: Raw hash bytes
    public static func hashRaw(
        password: [UInt8],
        salt: [UInt8],
        configuration: Argon2Configuration = .moderate,
        secret: [UInt8] = [],
        associatedData: [UInt8] = []
    ) throws -> [UInt8] {
        try configuration.validate(saltLength: salt.count)

        let instance = Instance(
            type: configuration.variant,
            version: configuration.version,
            passes: configuration.timeCost,
            memoryCost: configuration.memoryCost,
            lanes: configuration.parallelism,
            threads: configuration.parallelism
        )

        return try argon2HashSync(
            instance: instance,
            password: password,
            salt: salt,
            secret: secret,
            associatedData: associatedData,
            outputLength: Int(configuration.hashLength)
        )
    }

    /// Hash a password string and return the raw hash bytes
    public static func hashRaw(
        password: String,
        salt: [UInt8],
        configuration: Argon2Configuration = .moderate,
        secret: [UInt8] = [],
        associatedData: [UInt8] = []
    ) throws -> [UInt8] {
        try hashRaw(
            password: Array(password.utf8),
            salt: salt,
            configuration: configuration,
            secret: secret,
            associatedData: associatedData
        )
    }

    // MARK: - Encoded Hash Functions

    /// Hash a password and return PHC-encoded string
    ///
    /// - Parameters:
    ///   - password: The password to hash
    ///   - salt: Random salt (minimum 8 bytes, recommended 16+ bytes)
    ///   - configuration: Hashing parameters
    ///   - secret: Optional secret key for keyed hashing
    ///   - associatedData: Optional associated data
    /// - Returns: PHC-formatted hash string (e.g., $argon2id$v=19$m=65536,t=3,p=4$...)
    public static func hashEncoded(
        password: [UInt8],
        salt: [UInt8],
        configuration: Argon2Configuration = .moderate,
        secret: [UInt8] = [],
        associatedData: [UInt8] = []
    ) throws -> String {
        let hash = try hashRaw(
            password: password,
            salt: salt,
            configuration: configuration,
            secret: secret,
            associatedData: associatedData
        )

        return encodeHash(
            type: configuration.variant,
            version: configuration.version,
            memoryCost: configuration.memoryCost,
            timeCost: configuration.timeCost,
            parallelism: configuration.parallelism,
            salt: salt,
            hash: hash
        )
    }

    /// Hash a password string and return PHC-encoded string
    public static func hashEncoded(
        password: String,
        salt: [UInt8],
        configuration: Argon2Configuration = .moderate,
        secret: [UInt8] = [],
        associatedData: [UInt8] = []
    ) throws -> String {
        try hashEncoded(
            password: Array(password.utf8),
            salt: salt,
            configuration: configuration,
            secret: secret,
            associatedData: associatedData
        )
    }

    // MARK: - Async Hash Functions

    /// Hash a password asynchronously and return raw hash bytes
    public static func hashRawAsync(
        password: [UInt8],
        salt: [UInt8],
        configuration: Argon2Configuration = .moderate,
        secret: [UInt8] = [],
        associatedData: [UInt8] = []
    ) async throws -> [UInt8] {
        try configuration.validate(saltLength: salt.count)

        let instance = Instance(
            type: configuration.variant,
            version: configuration.version,
            passes: configuration.timeCost,
            memoryCost: configuration.memoryCost,
            lanes: configuration.parallelism,
            threads: configuration.parallelism
        )

        return try await argon2Hash(
            instance: instance,
            password: password,
            salt: salt,
            secret: secret,
            associatedData: associatedData,
            outputLength: Int(configuration.hashLength)
        )
    }

    /// Hash a password string asynchronously and return raw hash bytes
    public static func hashRawAsync(
        password: String,
        salt: [UInt8],
        configuration: Argon2Configuration = .moderate,
        secret: [UInt8] = [],
        associatedData: [UInt8] = []
    ) async throws -> [UInt8] {
        try await hashRawAsync(
            password: Array(password.utf8),
            salt: salt,
            configuration: configuration,
            secret: secret,
            associatedData: associatedData
        )
    }

    /// Hash a password asynchronously and return PHC-encoded string
    public static func hashEncodedAsync(
        password: [UInt8],
        salt: [UInt8],
        configuration: Argon2Configuration = .moderate,
        secret: [UInt8] = [],
        associatedData: [UInt8] = []
    ) async throws -> String {
        let hash = try await hashRawAsync(
            password: password,
            salt: salt,
            configuration: configuration,
            secret: secret,
            associatedData: associatedData
        )

        return encodeHash(
            type: configuration.variant,
            version: configuration.version,
            memoryCost: configuration.memoryCost,
            timeCost: configuration.timeCost,
            parallelism: configuration.parallelism,
            salt: salt,
            hash: hash
        )
    }

    // MARK: - Verification Functions

    /// Verify a password against a PHC-encoded hash
    ///
    /// - Parameters:
    ///   - password: The password to verify
    ///   - encoded: The PHC-encoded hash string
    ///   - secret: Optional secret key (must match original)
    ///   - associatedData: Optional associated data (must match original)
    /// - Returns: true if password matches, false otherwise
    /// - Throws: Argon2Error if the encoded string is invalid
    public static func verify(
        password: [UInt8],
        encoded: String,
        secret: [UInt8] = [],
        associatedData: [UInt8] = []
    ) throws -> Bool {
        let decoded: DecodedHash
        do {
            decoded = try decodeHash(encoded)
        } catch {
            throw Argon2Error.decodingFailed
        }

        let configuration = Argon2Configuration(
            variant: decoded.type,
            version: decoded.version,
            timeCost: decoded.timeCost,
            memoryCost: decoded.memoryCost,
            parallelism: decoded.parallelism,
            hashLength: UInt32(decoded.hash.count)
        )

        let computedHash = try hashRaw(
            password: password,
            salt: decoded.salt,
            configuration: configuration,
            secret: secret,
            associatedData: associatedData
        )

        return constantTimeEqual(computedHash, decoded.hash)
    }

    /// Verify a password string against a PHC-encoded hash
    public static func verify(
        password: String,
        encoded: String,
        secret: [UInt8] = [],
        associatedData: [UInt8] = []
    ) throws -> Bool {
        try verify(
            password: Array(password.utf8),
            encoded: encoded,
            secret: secret,
            associatedData: associatedData
        )
    }

    /// Verify a password asynchronously against a PHC-encoded hash
    public static func verifyAsync(
        password: [UInt8],
        encoded: String,
        secret: [UInt8] = [],
        associatedData: [UInt8] = []
    ) async throws -> Bool {
        let decoded: DecodedHash
        do {
            decoded = try decodeHash(encoded)
        } catch {
            throw Argon2Error.decodingFailed
        }

        let configuration = Argon2Configuration(
            variant: decoded.type,
            version: decoded.version,
            timeCost: decoded.timeCost,
            memoryCost: decoded.memoryCost,
            parallelism: decoded.parallelism,
            hashLength: UInt32(decoded.hash.count)
        )

        let computedHash = try await hashRawAsync(
            password: password,
            salt: decoded.salt,
            configuration: configuration,
            secret: secret,
            associatedData: associatedData
        )

        return constantTimeEqual(computedHash, decoded.hash)
    }

    // MARK: - Variant-Specific Functions

    /// Hash using Argon2d (data-dependent, faster but vulnerable to side-channel attacks)
    public static func hashArgon2d(
        password: [UInt8],
        salt: [UInt8],
        timeCost: UInt32 = 3,
        memoryCost: UInt32 = 65536,
        parallelism: UInt32 = 4,
        hashLength: UInt32 = 32
    ) throws -> [UInt8] {
        try hashRaw(
            password: password,
            salt: salt,
            configuration: Argon2Configuration(
                variant: .argon2d,
                timeCost: timeCost,
                memoryCost: memoryCost,
                parallelism: parallelism,
                hashLength: hashLength
            )
        )
    }

    /// Hash using Argon2i (data-independent, resistant to side-channel attacks)
    public static func hashArgon2i(
        password: [UInt8],
        salt: [UInt8],
        timeCost: UInt32 = 3,
        memoryCost: UInt32 = 65536,
        parallelism: UInt32 = 4,
        hashLength: UInt32 = 32
    ) throws -> [UInt8] {
        try hashRaw(
            password: password,
            salt: salt,
            configuration: Argon2Configuration(
                variant: .argon2i,
                timeCost: timeCost,
                memoryCost: memoryCost,
                parallelism: parallelism,
                hashLength: hashLength
            )
        )
    }

    /// Hash using Argon2id (hybrid, recommended for password hashing)
    public static func hashArgon2id(
        password: [UInt8],
        salt: [UInt8],
        timeCost: UInt32 = 3,
        memoryCost: UInt32 = 65536,
        parallelism: UInt32 = 4,
        hashLength: UInt32 = 32
    ) throws -> [UInt8] {
        try hashRaw(
            password: password,
            salt: salt,
            configuration: Argon2Configuration(
                variant: .argon2id,
                timeCost: timeCost,
                memoryCost: memoryCost,
                parallelism: parallelism,
                hashLength: hashLength
            )
        )
    }

    // MARK: - Utility Functions

    /// Generate cryptographically secure random salt
    public static func generateSalt(length: Int = 16) -> [UInt8] {
        var salt = [UInt8](repeating: 0, count: length)
        #if canImport(Security)
        _ = SecRandomCopyBytes(kSecRandomDefault, length, &salt)
        #else
        // Fallback for non-Apple platforms
        for i in 0..<length {
            salt[i] = UInt8.random(in: 0...255)
        }
        #endif
        return salt
    }

    /// Convert hash bytes to hexadecimal string
    public static func hexEncode(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Convert hexadecimal string to bytes
    public static func hexDecode(_ hex: String) -> [UInt8]? {
        var bytes = [UInt8]()
        var index = hex.startIndex

        while index < hex.endIndex {
            guard let nextIndex = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) else {
                return nil
            }

            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else {
                return nil
            }

            bytes.append(byte)
            index = nextIndex
        }

        return bytes
    }
}

// MARK: - Private Helpers

/// Constant-time byte array comparison to prevent timing attacks
private func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }

    var result: UInt8 = 0
    for i in 0..<a.count {
        result |= a[i] ^ b[i]
    }
    return result == 0
}
