import Testing
import Argon2
import argon2

/// Comprehensive tests comparing Swift Argon2 output against the C reference implementation
/// Tests cover all variants, versions, and a wide range of parameter combinations
@Suite("C Reference Comparison Tests")
struct CReferenceTests {

    // MARK: - Helper Functions

    /// Convert bytes to hex string for debugging
    private func hexString(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Hash using C library with raw output
    private func hashWithC(
        password: [UInt8],
        salt: [UInt8],
        timeCost: UInt32,
        memoryCost: UInt32,
        parallelism: UInt32,
        hashLength: Int,
        type: Argon2_type,
        version: UInt32
    ) -> [UInt8]? {
        var hash = [UInt8](repeating: 0, count: hashLength)

        let result = password.withUnsafeBytes { pwdPtr in
            salt.withUnsafeBytes { saltPtr in
                hash.withUnsafeMutableBytes { hashPtr in
                    argon2_hash(
                        timeCost,
                        memoryCost,
                        parallelism,
                        pwdPtr.baseAddress,
                        password.count,
                        saltPtr.baseAddress,
                        salt.count,
                        hashPtr.baseAddress,
                        hashLength,
                        nil,
                        0,
                        type,
                        version
                    )
                }
            }
        }

        guard result == ARGON2_OK.rawValue else {
            return nil
        }
        return hash
    }

    /// Hash using Swift library
    private func hashWithSwift(
        password: [UInt8],
        salt: [UInt8],
        timeCost: UInt32,
        memoryCost: UInt32,
        parallelism: UInt32,
        hashLength: UInt32,
        variant: Argon2Variant,
        version: Argon2Version
    ) throws -> [UInt8] {
        let config = Argon2Configuration(
            variant: variant,
            version: version,
            timeCost: timeCost,
            memoryCost: memoryCost,
            parallelism: parallelism,
            hashLength: hashLength
        )
        return try Argon2.hashRaw(
            password: password,
            salt: salt,
            configuration: config
        )
    }

    /// Compare C and Swift outputs with detailed error messages
    private func compareOutputs(
        password: [UInt8],
        salt: [UInt8],
        timeCost: UInt32,
        memoryCost: UInt32,
        parallelism: UInt32,
        hashLength: Int,
        cType: Argon2_type,
        swiftVariant: Argon2Variant,
        cVersion: UInt32,
        swiftVersion: Argon2Version,
        sourceLocation: SourceLocation = #_sourceLocation
    ) throws {
        let cHash = hashWithC(
            password: password,
            salt: salt,
            timeCost: timeCost,
            memoryCost: memoryCost,
            parallelism: parallelism,
            hashLength: hashLength,
            type: cType,
            version: cVersion
        )

        let swiftHash = try hashWithSwift(
            password: password,
            salt: salt,
            timeCost: timeCost,
            memoryCost: memoryCost,
            parallelism: parallelism,
            hashLength: UInt32(hashLength),
            variant: swiftVariant,
            version: swiftVersion
        )

        #expect(cHash != nil, "C library failed", sourceLocation: sourceLocation)
        #expect(
            swiftHash == cHash!,
            """
            Hash mismatch for:
            - variant: \(swiftVariant), version: \(swiftVersion)
            - t=\(timeCost), m=\(memoryCost), p=\(parallelism), hashLen=\(hashLength)
            - password length: \(password.count), salt length: \(salt.count)
            Swift:  \(hexString(swiftHash))
            C:      \(hexString(cHash!))
            """,
            sourceLocation: sourceLocation
        )
    }

    // MARK: - Test Data Generators

    /// Generate test password of specified length
    private func password(length: Int) -> [UInt8] {
        if length == 0 { return [] }
        return (0..<length).map { UInt8($0 & 0xFF) }
    }

    /// Generate test salt of specified length
    private func salt(length: Int) -> [UInt8] {
        return (0..<length).map { UInt8((0xFF - $0) & 0xFF) }
    }

    // MARK: - Comprehensive Variant/Version Tests

    @Test("All variants and versions")
    func allVariantsAndVersions() throws {
        let testPassword = Array("password".utf8)
        let testSalt = Array("somesalt".utf8)

        let variants: [(Argon2_type, Argon2Variant)] = [
            (Argon2_d, .argon2d),
            (Argon2_i, .argon2i),
            (Argon2_id, .argon2id)
        ]

        let versions: [(UInt32, Argon2Version)] = [
            (0x10, .v10),
            (0x13, .v13)
        ]

        for (cType, swiftVariant) in variants {
            for (cVersion, swiftVersion) in versions {
                try compareOutputs(
                    password: testPassword,
                    salt: testSalt,
                    timeCost: 2,
                    memoryCost: 64,
                    parallelism: 2,
                    hashLength: 32,
                    cType: cType,
                    swiftVariant: swiftVariant,
                    cVersion: cVersion,
                    swiftVersion: swiftVersion
                )
            }
        }
    }

    // MARK: - Password Length Tests

    @Test("Empty password")
    func emptyPassword() throws {
        try compareOutputs(
            password: [],
            salt: salt(length: 16),
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            cType: Argon2_id,
            swiftVariant: .argon2id,
            cVersion: 0x13,
            swiftVersion: .v13
        )
    }

    @Test("Single byte password")
    func singleBytePassword() throws {
        try compareOutputs(
            password: [0x42],
            salt: salt(length: 16),
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            cType: Argon2_id,
            swiftVariant: .argon2id,
            cVersion: 0x13,
            swiftVersion: .v13
        )
    }

    @Test("Various password lengths")
    func passwordLengths() throws {
        let lengths = [1, 8, 16, 32, 64, 100, 128, 255]
        let testSalt = salt(length: 16)

        for length in lengths {
            try compareOutputs(
                password: password(length: length),
                salt: testSalt,
                timeCost: 2,
                memoryCost: 64,
                parallelism: 1,
                hashLength: 32,
                cType: Argon2_id,
                swiftVariant: .argon2id,
                cVersion: 0x13,
                swiftVersion: .v13
            )
        }
    }

    @Test("Long password (1000 bytes)")
    func longPassword() throws {
        try compareOutputs(
            password: password(length: 1000),
            salt: salt(length: 16),
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            cType: Argon2_id,
            swiftVariant: .argon2id,
            cVersion: 0x13,
            swiftVersion: .v13
        )
    }

    // MARK: - Salt Length Tests

    @Test("Minimum salt length (8 bytes)")
    func minimumSaltLength() throws {
        try compareOutputs(
            password: password(length: 32),
            salt: salt(length: 8),
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            cType: Argon2_id,
            swiftVariant: .argon2id,
            cVersion: 0x13,
            swiftVersion: .v13
        )
    }

    @Test("Various salt lengths")
    func saltLengths() throws {
        let lengths = [8, 16, 32, 64, 128]
        let testPassword = password(length: 32)

        for length in lengths {
            try compareOutputs(
                password: testPassword,
                salt: salt(length: length),
                timeCost: 2,
                memoryCost: 64,
                parallelism: 1,
                hashLength: 32,
                cType: Argon2_id,
                swiftVariant: .argon2id,
                cVersion: 0x13,
                swiftVersion: .v13
            )
        }
    }

    // MARK: - Time Cost Tests

    @Test("Various time costs")
    func timeCosts() throws {
        let timeCosts: [UInt32] = [1, 2, 3, 4, 5]
        let testPassword = password(length: 32)
        let testSalt = salt(length: 16)

        for t in timeCosts {
            try compareOutputs(
                password: testPassword,
                salt: testSalt,
                timeCost: t,
                memoryCost: 64,
                parallelism: 1,
                hashLength: 32,
                cType: Argon2_id,
                swiftVariant: .argon2id,
                cVersion: 0x13,
                swiftVersion: .v13
            )
        }
    }

    @Test("Time costs all variants")
    func timeCostsAllVariants() throws {
        let testPassword = password(length: 32)
        let testSalt = salt(length: 16)

        let variants: [(Argon2_type, Argon2Variant)] = [
            (Argon2_d, .argon2d),
            (Argon2_i, .argon2i),
            (Argon2_id, .argon2id)
        ]

        for (cType, swiftVariant) in variants {
            for t: UInt32 in [1, 2, 3] {
                try compareOutputs(
                    password: testPassword,
                    salt: testSalt,
                    timeCost: t,
                    memoryCost: 64,
                    parallelism: 2,
                    hashLength: 32,
                    cType: cType,
                    swiftVariant: swiftVariant,
                    cVersion: 0x13,
                    swiftVersion: .v13
                )
            }
        }
    }

    // MARK: - Memory Cost Tests

    @Test("Various memory costs")
    func memoryCosts() throws {
        let memoryCosts: [UInt32] = [8, 16, 32, 64, 128, 256, 512]
        let testPassword = password(length: 32)
        let testSalt = salt(length: 16)

        for m in memoryCosts {
            try compareOutputs(
                password: testPassword,
                salt: testSalt,
                timeCost: 1,
                memoryCost: m,
                parallelism: 1,
                hashLength: 32,
                cType: Argon2_id,
                swiftVariant: .argon2id,
                cVersion: 0x13,
                swiftVersion: .v13
            )
        }
    }

    @Test("Memory costs all variants")
    func memoryCostsAllVariants() throws {
        let testPassword = password(length: 32)
        let testSalt = salt(length: 16)

        let variants: [(Argon2_type, Argon2Variant)] = [
            (Argon2_d, .argon2d),
            (Argon2_i, .argon2i),
            (Argon2_id, .argon2id)
        ]

        for (cType, swiftVariant) in variants {
            for m: UInt32 in [32, 64, 128] {
                try compareOutputs(
                    password: testPassword,
                    salt: testSalt,
                    timeCost: 2,
                    memoryCost: m,
                    parallelism: 2,
                    hashLength: 32,
                    cType: cType,
                    swiftVariant: swiftVariant,
                    cVersion: 0x13,
                    swiftVersion: .v13
                )
            }
        }
    }

    // MARK: - Parallelism Tests

    @Test("Various parallelism values")
    func parallelism() throws {
        let parallelisms: [UInt32] = [1, 2, 4, 8]
        let testPassword = password(length: 32)
        let testSalt = salt(length: 16)

        for p in parallelisms {
            // Memory must be at least 8 * parallelism
            let memoryCost = max(64, 8 * p)
            try compareOutputs(
                password: testPassword,
                salt: testSalt,
                timeCost: 2,
                memoryCost: memoryCost,
                parallelism: p,
                hashLength: 32,
                cType: Argon2_id,
                swiftVariant: .argon2id,
                cVersion: 0x13,
                swiftVersion: .v13
            )
        }
    }

    @Test("Parallelism all variants and versions")
    func parallelismAllVariantsVersions() throws {
        let testPassword = password(length: 32)
        let testSalt = salt(length: 16)

        let variants: [(Argon2_type, Argon2Variant)] = [
            (Argon2_d, .argon2d),
            (Argon2_i, .argon2i),
            (Argon2_id, .argon2id)
        ]

        let versions: [(UInt32, Argon2Version)] = [
            (0x10, .v10),
            (0x13, .v13)
        ]

        for (cType, swiftVariant) in variants {
            for (cVersion, swiftVersion) in versions {
                for p: UInt32 in [1, 2, 4] {
                    try compareOutputs(
                        password: testPassword,
                        salt: testSalt,
                        timeCost: 2,
                        memoryCost: 64,
                        parallelism: p,
                        hashLength: 32,
                        cType: cType,
                        swiftVariant: swiftVariant,
                        cVersion: cVersion,
                        swiftVersion: swiftVersion
                    )
                }
            }
        }
    }

    // MARK: - Hash Length Tests

    @Test("Minimum hash length (4 bytes)")
    func minimumHashLength() throws {
        try compareOutputs(
            password: password(length: 32),
            salt: salt(length: 16),
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 4,
            cType: Argon2_id,
            swiftVariant: .argon2id,
            cVersion: 0x13,
            swiftVersion: .v13
        )
    }

    @Test("Various hash lengths")
    func hashLengths() throws {
        let hashLengths = [4, 8, 16, 32, 64, 128, 256]
        let testPassword = password(length: 32)
        let testSalt = salt(length: 16)

        for hashLen in hashLengths {
            try compareOutputs(
                password: testPassword,
                salt: testSalt,
                timeCost: 2,
                memoryCost: 64,
                parallelism: 1,
                hashLength: hashLen,
                cType: Argon2_id,
                swiftVariant: .argon2id,
                cVersion: 0x13,
                swiftVersion: .v13
            )
        }
    }

    @Test("Hash lengths all variants")
    func hashLengthsAllVariants() throws {
        let testPassword = password(length: 32)
        let testSalt = salt(length: 16)

        let variants: [(Argon2_type, Argon2Variant)] = [
            (Argon2_d, .argon2d),
            (Argon2_i, .argon2i),
            (Argon2_id, .argon2id)
        ]

        for (cType, swiftVariant) in variants {
            for hashLen in [16, 32, 64] {
                try compareOutputs(
                    password: testPassword,
                    salt: testSalt,
                    timeCost: 2,
                    memoryCost: 64,
                    parallelism: 2,
                    hashLength: hashLen,
                    cType: cType,
                    swiftVariant: swiftVariant,
                    cVersion: 0x13,
                    swiftVersion: .v13
                )
            }
        }
    }

    // MARK: - Reference Test Vectors from C test.c

    @Test("Reference vectors from C test.c")
    func referenceVectors() throws {
        let password: [UInt8] = [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]
        let testSalt: [UInt8] = [0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                                  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02]

        // Argon2i v1.3
        try compareOutputs(
            password: password,
            salt: testSalt,
            timeCost: 3,
            memoryCost: 32,
            parallelism: 4,
            hashLength: 32,
            cType: Argon2_i,
            swiftVariant: .argon2i,
            cVersion: 0x13,
            swiftVersion: .v13
        )

        // Argon2d v1.3
        try compareOutputs(
            password: password,
            salt: testSalt,
            timeCost: 3,
            memoryCost: 32,
            parallelism: 4,
            hashLength: 32,
            cType: Argon2_d,
            swiftVariant: .argon2d,
            cVersion: 0x13,
            swiftVersion: .v13
        )

        // Argon2id v1.3
        try compareOutputs(
            password: password,
            salt: testSalt,
            timeCost: 3,
            memoryCost: 32,
            parallelism: 4,
            hashLength: 32,
            cType: Argon2_id,
            swiftVariant: .argon2id,
            cVersion: 0x13,
            swiftVersion: .v13
        )

        // Argon2i v1.0
        try compareOutputs(
            password: password,
            salt: testSalt,
            timeCost: 3,
            memoryCost: 32,
            parallelism: 4,
            hashLength: 32,
            cType: Argon2_i,
            swiftVariant: .argon2i,
            cVersion: 0x10,
            swiftVersion: .v10
        )

        // Argon2d v1.0
        try compareOutputs(
            password: password,
            salt: testSalt,
            timeCost: 3,
            memoryCost: 32,
            parallelism: 4,
            hashLength: 32,
            cType: Argon2_d,
            swiftVariant: .argon2d,
            cVersion: 0x10,
            swiftVersion: .v10
        )

        // Argon2id v1.0
        try compareOutputs(
            password: password,
            salt: testSalt,
            timeCost: 3,
            memoryCost: 32,
            parallelism: 4,
            hashLength: 32,
            cType: Argon2_id,
            swiftVariant: .argon2id,
            cVersion: 0x10,
            swiftVersion: .v10
        )
    }

    // MARK: - Comprehensive Parameter Matrix Tests

    @Test("Parameter matrix (~486 combinations)")
    func parameterMatrix() throws {
        let variants: [(Argon2_type, Argon2Variant)] = [
            (Argon2_d, .argon2d),
            (Argon2_i, .argon2i),
            (Argon2_id, .argon2id)
        ]

        let versions: [(UInt32, Argon2Version)] = [
            (0x10, .v10),
            (0x13, .v13)
        ]

        let timeCosts: [UInt32] = [1, 2, 3]
        let memoryCosts: [UInt32] = [32, 64, 128]
        let parallelisms: [UInt32] = [1, 2, 4]
        let hashLengths = [16, 32, 64]

        let testPassword = password(length: 32)
        let testSalt = salt(length: 16)

        for (cType, swiftVariant) in variants {
            for (cVersion, swiftVersion) in versions {
                for t in timeCosts {
                    for m in memoryCosts {
                        for p in parallelisms {
                            // Skip if memory is too small for parallelism
                            guard m >= 8 * p else { continue }

                            for hashLen in hashLengths {
                                try compareOutputs(
                                    password: testPassword,
                                    salt: testSalt,
                                    timeCost: t,
                                    memoryCost: m,
                                    parallelism: p,
                                    hashLength: hashLen,
                                    cType: cType,
                                    swiftVariant: swiftVariant,
                                    cVersion: cVersion,
                                    swiftVersion: swiftVersion
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: - Edge Cases

    @Test("All zeros password")
    func zerosPassword() throws {
        let zeros = [UInt8](repeating: 0, count: 32)
        try compareOutputs(
            password: zeros,
            salt: salt(length: 16),
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            cType: Argon2_id,
            swiftVariant: .argon2id,
            cVersion: 0x13,
            swiftVersion: .v13
        )
    }

    @Test("All 0xFF password")
    func maxBytesPassword() throws {
        let maxBytes = [UInt8](repeating: 0xFF, count: 32)
        try compareOutputs(
            password: maxBytes,
            salt: salt(length: 16),
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            cType: Argon2_id,
            swiftVariant: .argon2id,
            cVersion: 0x13,
            swiftVersion: .v13
        )
    }

    @Test("All zeros salt")
    func zerosSalt() throws {
        let zeros = [UInt8](repeating: 0, count: 16)
        try compareOutputs(
            password: password(length: 32),
            salt: zeros,
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            cType: Argon2_id,
            swiftVariant: .argon2id,
            cVersion: 0x13,
            swiftVersion: .v13
        )
    }

    @Test("All 0xFF salt")
    func maxBytesSalt() throws {
        let maxBytes = [UInt8](repeating: 0xFF, count: 16)
        try compareOutputs(
            password: password(length: 32),
            salt: maxBytes,
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            cType: Argon2_id,
            swiftVariant: .argon2id,
            cVersion: 0x13,
            swiftVersion: .v13
        )
    }

    @Test("ASCII printable password")
    func asciiPassword() throws {
        let ascii = Array("The quick brown fox jumps over the lazy dog!".utf8)
        try compareOutputs(
            password: ascii,
            salt: salt(length: 16),
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            cType: Argon2_id,
            swiftVariant: .argon2id,
            cVersion: 0x13,
            swiftVersion: .v13
        )
    }

    @Test("Unicode password (UTF-8)")
    func unicodePassword() throws {
        let unicode = Array("密码🔐пароль".utf8)
        try compareOutputs(
            password: unicode,
            salt: salt(length: 16),
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            cType: Argon2_id,
            swiftVariant: .argon2id,
            cVersion: 0x13,
            swiftVersion: .v13
        )
    }

    // MARK: - Version-Specific Behavior Tests

    @Test("Version difference")
    func versionDifference() throws {
        let testPassword = password(length: 32)
        let testSalt = salt(length: 16)

        let v10Hash = try hashWithSwift(
            password: testPassword,
            salt: testSalt,
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            variant: .argon2id,
            version: .v10
        )

        let v13Hash = try hashWithSwift(
            password: testPassword,
            salt: testSalt,
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            variant: .argon2id,
            version: .v13
        )

        // Verify versions produce different output
        #expect(v10Hash != v13Hash, "v1.0 and v1.3 should produce different results")

        // Verify both match C library
        let cV10Hash = hashWithC(
            password: testPassword,
            salt: testSalt,
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            type: Argon2_id,
            version: 0x10
        )
        let cV13Hash = hashWithC(
            password: testPassword,
            salt: testSalt,
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            type: Argon2_id,
            version: 0x13
        )

        #expect(v10Hash == cV10Hash!)
        #expect(v13Hash == cV13Hash!)
    }

    @Test("Variant difference")
    func variantDifference() throws {
        let testPassword = password(length: 32)
        let testSalt = salt(length: 16)

        let argon2dHash = try hashWithSwift(
            password: testPassword,
            salt: testSalt,
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            variant: .argon2d,
            version: .v13
        )

        let argon2iHash = try hashWithSwift(
            password: testPassword,
            salt: testSalt,
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            variant: .argon2i,
            version: .v13
        )

        let argon2idHash = try hashWithSwift(
            password: testPassword,
            salt: testSalt,
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            variant: .argon2id,
            version: .v13
        )

        // Verify variants produce different output
        #expect(argon2dHash != argon2iHash, "argon2d and argon2i should differ")
        #expect(argon2iHash != argon2idHash, "argon2i and argon2id should differ")
        #expect(argon2dHash != argon2idHash, "argon2d and argon2id should differ")
    }

    // MARK: - Determinism Tests

    @Test("Determinism")
    func determinism() throws {
        let testPassword = password(length: 32)
        let testSalt = salt(length: 16)

        let hash1 = try hashWithSwift(
            password: testPassword,
            salt: testSalt,
            timeCost: 2,
            memoryCost: 64,
            parallelism: 2,
            hashLength: 32,
            variant: .argon2id,
            version: .v13
        )

        let hash2 = try hashWithSwift(
            password: testPassword,
            salt: testSalt,
            timeCost: 2,
            memoryCost: 64,
            parallelism: 2,
            hashLength: 32,
            variant: .argon2id,
            version: .v13
        )

        #expect(hash1 == hash2, "Same inputs should produce same output")
    }

    @Test("Password sensitivity")
    func passwordSensitivity() throws {
        let testSalt = salt(length: 16)

        let hash1 = try hashWithSwift(
            password: Array("password1".utf8),
            salt: testSalt,
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            variant: .argon2id,
            version: .v13
        )

        let hash2 = try hashWithSwift(
            password: Array("password2".utf8),
            salt: testSalt,
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            variant: .argon2id,
            version: .v13
        )

        #expect(hash1 != hash2, "Different passwords should produce different hashes")
    }

    @Test("Salt sensitivity")
    func saltSensitivity() throws {
        let testPassword = password(length: 32)

        let hash1 = try hashWithSwift(
            password: testPassword,
            salt: Array("saltsalt".utf8),
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            variant: .argon2id,
            version: .v13
        )

        let hash2 = try hashWithSwift(
            password: testPassword,
            salt: Array("saltsal2".utf8),
            timeCost: 2,
            memoryCost: 64,
            parallelism: 1,
            hashLength: 32,
            variant: .argon2id,
            version: .v13
        )

        #expect(hash1 != hash2, "Different salts should produce different hashes")
    }
}
