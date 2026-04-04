/// Argon2 error handling test suite
import Testing
@testable import Argon2
@testable import Argon2Core

@Suite("Argon2 Error Tests")
struct ErrorTests {

    // MARK: - Output Length Errors

    @Test("Output too short")
    func outputTooShort() {
        #expect(throws: Argon2Error.outputTooShort) {
            _ = try Argon2.hashRaw(
                password: "password",
                salt: Array("somesalt".utf8),
                configuration: Argon2Configuration(
                    timeCost: 2,
                    memoryCost: 256,
                    parallelism: 1,
                    hashLength: 3  // Minimum is 4
                )
            )
        }
    }

    // MARK: - Salt Errors

    @Test("Salt too short")
    func saltTooShort() {
        #expect(throws: Argon2Error.saltTooShort) {
            _ = try Argon2.hashRaw(
                password: "password",
                salt: Array("short".utf8),  // Less than 8 bytes
                configuration: .interactive
            )
        }
    }

    @Test("Salt empty")
    func saltEmpty() {
        #expect(throws: Argon2Error.saltTooShort) {
            _ = try Argon2.hashRaw(
                password: "password",
                salt: [],
                configuration: .interactive
            )
        }
    }

    // MARK: - Memory Cost Errors

    @Test("Memory too small")
    func memoryTooSmall() {
        #expect(throws: Argon2Error.memoryCostTooSmall) {
            _ = try Argon2.hashRaw(
                password: "password",
                salt: Array("somesalt".utf8),
                configuration: Argon2Configuration(
                    timeCost: 2,
                    memoryCost: 4,  // Less than 8 * parallelism
                    parallelism: 1,
                    hashLength: 32
                )
            )
        }
    }

    @Test("Memory too small for parallelism")
    func memoryTooSmallForParallelism() {
        // Memory must be at least 8 * parallelism
        #expect(throws: Argon2Error.memoryCostTooSmall) {
            _ = try Argon2.hashRaw(
                password: "password",
                salt: Array("somesalt".utf8),
                configuration: Argon2Configuration(
                    timeCost: 2,
                    memoryCost: 16,  // Too small for p=4
                    parallelism: 4,
                    hashLength: 32
                )
            )
        }
    }

    // MARK: - Time Cost Errors

    @Test("Time cost zero")
    func timeCostZero() {
        #expect(throws: Argon2Error.timeCostTooSmall) {
            _ = try Argon2.hashRaw(
                password: "password",
                salt: Array("somesalt".utf8),
                configuration: Argon2Configuration(
                    timeCost: 0,  // Minimum is 1
                    memoryCost: 256,
                    parallelism: 1,
                    hashLength: 32
                )
            )
        }
    }

    // MARK: - Parallelism Errors

    @Test("Lanes too few")
    func lanesTooFew() {
        #expect(throws: Argon2Error.lanesTooFew) {
            _ = try Argon2.hashRaw(
                password: "password",
                salt: Array("somesalt".utf8),
                configuration: Argon2Configuration(
                    timeCost: 2,
                    memoryCost: 256,
                    parallelism: 0,  // Minimum is 1
                    hashLength: 32
                )
            )
        }
    }

    // MARK: - Decoding Errors

    @Test("Decoding failed")
    func decodingFailed() throws {
        #expect(throws: Argon2Error.decodingFailed) {
            _ = try Argon2.verify(
                password: "password",
                encoded: "invalid hash string"
            )
        }
    }

    // MARK: - Valid Edge Cases

    @Test("Minimum valid parameters")
    func minimumValidParameters() throws {
        // Minimum valid configuration
        let hash = try Argon2.hashRaw(
            password: "p",  // Minimum password (0 bytes is also valid)
            salt: Array("12345678".utf8),  // Exactly 8 bytes
            configuration: Argon2Configuration(
                timeCost: 1,
                memoryCost: 8,  // Minimum for p=1
                parallelism: 1,
                hashLength: 4  // Minimum output
            )
        )

        #expect(hash.count == 4)
    }

    @Test("Empty password")
    func emptyPassword() throws {
        // Empty password should work (password length can be 0)
        let hash = try Argon2.hashRaw(
            password: [],
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                timeCost: 2,
                memoryCost: 256,
                parallelism: 1,
                hashLength: 32
            )
        )

        #expect(hash.count == 32)
    }
}
