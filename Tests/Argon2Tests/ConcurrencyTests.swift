/// Argon2 concurrency test suite
import Testing
@testable import Argon2
@testable import Argon2Core

@Suite("Argon2 Concurrency Tests")
struct ConcurrencyTests {

    // MARK: - Basic Parallel Tests

    @Test("Parallelism variations")
    func parallelismVariations() throws {
        let password = Array("password".utf8)
        let salt = Array("somesalt".utf8)

        // Test different parallelism levels produce different hashes
        var hashes: [[UInt8]] = []

        for p: UInt32 in 1...4 {
            let hash = try Argon2.hashRaw(
                password: password,
                salt: salt,
                configuration: Argon2Configuration(
                    variant: .argon2id,
                    timeCost: 2,
                    memoryCost: 64 * p,  // Ensure enough memory for lanes
                    parallelism: p,
                    hashLength: 32
                )
            )
            hashes.append(hash)
        }

        // Each parallelism level should produce a different hash
        for i in 0..<hashes.count {
            for j in (i+1)..<hashes.count {
                #expect(hashes[i] != hashes[j],
                    "Parallelism \(i+1) and \(j+1) should produce different hashes")
            }
        }
    }

    // MARK: - Async API Tests

    @Test("Async hash")
    func asyncHash() async throws {
        let hash = try await Argon2.hashRawAsync(
            password: "password",
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2id,
                timeCost: 2,
                memoryCost: 256,
                parallelism: 2,
                hashLength: 32
            )
        )

        // Verify same result as sync version
        let syncHash = try Argon2.hashRaw(
            password: "password",
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2id,
                timeCost: 2,
                memoryCost: 256,
                parallelism: 2,
                hashLength: 32
            )
        )

        #expect(hash == syncHash)
    }

    @Test("Async verify")
    func asyncVerify() async throws {
        let encoded = "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4"

        let result = try await Argon2.verifyAsync(
            password: Array("password".utf8),
            encoded: encoded
        )

        #expect(result)
    }

    @Test("Concurrent hashing")
    func concurrentHashing() async throws {
        // Run multiple hashing operations concurrently
        let passwords = ["pass1", "pass2", "pass3", "pass4"]
        let salt = Array("somesalt".utf8)

        let hashes = try await withThrowingTaskGroup(of: (Int, [UInt8]).self) { group in
            for (index, password) in passwords.enumerated() {
                group.addTask {
                    let hash = try await Argon2.hashRawAsync(
                        password: password,
                        salt: salt,
                        configuration: Argon2Configuration(
                            timeCost: 1,
                            memoryCost: 256,
                            parallelism: 1,
                            hashLength: 32
                        )
                    )
                    return (index, hash)
                }
            }

            var results = [(Int, [UInt8])]()
            for try await result in group {
                results.append(result)
            }
            return results.sorted { $0.0 < $1.0 }.map { $0.1 }
        }

        // All hashes should be different
        for i in 0..<hashes.count {
            for j in (i+1)..<hashes.count {
                #expect(hashes[i] != hashes[j])
            }
        }
    }

    // MARK: - Thread Safety Tests

    @Test("Concurrent sync hashing")
    func concurrentSyncHashing() async throws {
        let passwords = ["pass1", "pass2", "pass3", "pass4"]
        let salt = Array("somesalt".utf8)

        // Use async/await with task group instead of XCTestExpectation
        let hashes = try await withThrowingTaskGroup(of: (Int, [UInt8]).self) { group in
            for (index, password) in passwords.enumerated() {
                group.addTask {
                    let hash = try Argon2.hashRaw(
                        password: password,
                        salt: salt,
                        configuration: Argon2Configuration(
                            timeCost: 1,
                            memoryCost: 256,
                            parallelism: 1,
                            hashLength: 32
                        )
                    )
                    return (index, hash)
                }
            }

            var results = [(Int, [UInt8])]()
            for try await result in group {
                results.append(result)
            }
            return results.sorted { $0.0 < $1.0 }.map { $0.1 }
        }

        // Verify all hashes were computed and are different
        #expect(hashes.count == 4)
        for i in 0..<hashes.count {
            for j in (i+1)..<hashes.count {
                #expect(hashes[i] != hashes[j])
            }
        }
    }

    // MARK: - Determinism Tests

    @Test("Deterministic output")
    func deterministicOutput() throws {
        let password = Array("test password".utf8)
        let salt = Array("test salt12".utf8)

        let config = Argon2Configuration(
            variant: .argon2id,
            timeCost: 2,
            memoryCost: 256,
            parallelism: 2,
            hashLength: 32
        )

        // Hash multiple times
        let hash1 = try Argon2.hashRaw(password: password, salt: salt, configuration: config)
        let hash2 = try Argon2.hashRaw(password: password, salt: salt, configuration: config)
        let hash3 = try Argon2.hashRaw(password: password, salt: salt, configuration: config)

        // All should be identical
        #expect(hash1 == hash2)
        #expect(hash2 == hash3)
    }
}
