/// Argon2 verification test suite
import Testing
@testable import SwiftArgon2
@testable import Encoding

@Suite("Argon2 Verification Tests")
struct VerifyTests {

    // MARK: - Basic Verification

    @Test("Verify correct password v10")
    func verifyCorrectPassword_v10() throws {
        let encoded = "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ"
        let result = try Argon2.verify(password: "password", encoded: encoded)
        #expect(result)
    }

    @Test("Verify correct password v13")
    func verifyCorrectPassword_v13() throws {
        let encoded = "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA"
        let result = try Argon2.verify(password: "password", encoded: encoded)
        #expect(result)
    }

    @Test("Verify correct password id v13")
    func verifyCorrectPassword_id_v13() throws {
        let encoded = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
        let result = try Argon2.verify(password: "password", encoded: encoded)
        #expect(result)
    }

    // MARK: - Wrong Password

    @Test("Verify wrong password v10")
    func verifyWrongPassword_v10() throws {
        let encoded = "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ"
        let result = try Argon2.verify(password: "wrongpassword", encoded: encoded)
        #expect(!result)
    }

    @Test("Verify wrong password v13")
    func verifyWrongPassword_v13() throws {
        let encoded = "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA"
        let result = try Argon2.verify(password: "wrongpassword", encoded: encoded)
        #expect(!result)
    }

    // MARK: - Round-Trip Verification

    @Test("Round-trip verification")
    func roundTripVerification() throws {
        let password = "my secure password"
        let salt = Argon2.generateSalt(length: 16)

        let encoded = try Argon2.hashEncoded(
            password: password,
            salt: salt,
            configuration: .interactive
        )

        // Correct password should verify
        #expect(try Argon2.verify(password: password, encoded: encoded))

        // Wrong password should not verify
        #expect(try !Argon2.verify(password: "wrong password", encoded: encoded))
    }

    @Test("Round-trip all variants")
    func roundTripAllVariants() throws {
        let password = "test password"
        let salt = Argon2.generateSalt(length: 16)

        for variant in [Argon2Variant.argon2d, .argon2i, .argon2id] {
            let config = Argon2Configuration(
                variant: variant,
                timeCost: 2,
                memoryCost: 256,
                parallelism: 1,
                hashLength: 32
            )

            let encoded = try Argon2.hashEncoded(
                password: password,
                salt: salt,
                configuration: config
            )

            #expect(try Argon2.verify(password: password, encoded: encoded), "Failed for \(variant.name)")
        }
    }

    // MARK: - Invalid Encoded Strings

    @Test("Verify invalid encoding - missing salt delimiter")
    func verifyInvalidEncoding_missingSaltDelimiter() {
        // Missing $ before salt
        let encoded = "$argon2i$m=65536,t=2,p=1c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ"

        #expect(throws: Argon2Error.decodingFailed) {
            _ = try Argon2.verify(password: "password", encoded: encoded)
        }
    }

    @Test("Verify invalid encoding - missing hash delimiter")
    func verifyInvalidEncoding_missingHashDelimiter() {
        // Missing $ before hash
        let encoded = "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ"

        #expect(throws: Argon2Error.decodingFailed) {
            _ = try Argon2.verify(password: "password", encoded: encoded)
        }
    }

    @Test("Verify invalid encoding - empty salt")
    func verifyInvalidEncoding_emptySalt() {
        // Empty salt (salt too short)
        let encoded = "$argon2i$m=65536,t=2,p=1$$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ"

        #expect(throws: (any Error).self) {
            _ = try Argon2.verify(password: "password", encoded: encoded)
        }
    }

    // MARK: - Bytes API

    @Test("Verify bytes password")
    func verifyBytesPassword() throws {
        let encoded = "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4"
        let result = try Argon2.verify(password: Array("password".utf8), encoded: encoded)
        #expect(result)
    }
}
