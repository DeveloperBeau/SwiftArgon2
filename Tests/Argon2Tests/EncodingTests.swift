/// Encoding/Decoding test suite
import Testing
@testable import Encoding
@testable import Argon2Core

@Suite("PHC Encoding Tests")
struct EncodingTests {

    // MARK: - Base64 Tests

    @Test("Base64 encode empty")
    func base64EncodeEmpty() {
        #expect(base64Encode([]) == "")
    }

    @Test("Base64 encode simple")
    func base64EncodeSimple() {
        #expect(base64Encode(Array("somesalt".utf8)) == "c29tZXNhbHQ")
    }

    @Test("Base64 encode padding 1")
    func base64EncodePadding1() {
        // "AB" -> 2 bytes, should produce 3 chars (no padding in this implementation)
        #expect(base64Encode([65, 66]) == "QUI")
    }

    @Test("Base64 encode padding 2")
    func base64EncodePadding2() {
        // "A" -> 1 byte, should produce 2 chars
        #expect(base64Encode([65]) == "QQ")
    }

    @Test("Base64 decode simple")
    func base64DecodeSimple() {
        let decoded = base64Decode("c29tZXNhbHQ")
        #expect(decoded == Array("somesalt".utf8))
    }

    @Test("Base64 decode empty")
    func base64DecodeEmpty() {
        #expect(base64Decode("") == [])
    }

    @Test("Base64 round trip")
    func base64RoundTrip() {
        let original: [UInt8] = [0, 1, 2, 255, 254, 128, 64, 32, 16, 8, 4, 2, 1]
        let encoded = base64Encode(original)
        let decoded = base64Decode(encoded)
        #expect(decoded == original)
    }

    @Test("Base64 decode invalid char")
    func base64DecodeInvalidChar() {
        // @ is not a valid base64 character
        let decoded = base64Decode("abc@def")
        // Should return partial decode up to invalid char
        #expect(decoded != nil)
    }

    // MARK: - PHC Encoding Tests

    @Test("PHC encode argon2i v10")
    func phcEncode_argon2i_v10() {
        let salt = Array("somesalt".utf8)
        let hash = hexDecode("f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694")!

        let encoded = encodeHash(
            type: .argon2i,
            version: .v10,
            memoryCost: 65536,
            timeCost: 2,
            parallelism: 1,
            salt: salt,
            hash: hash
        )

        // v1.0 still includes version in our implementation
        #expect(encoded.contains("$argon2i$"))
        #expect(encoded.contains("m=65536"))
        #expect(encoded.contains("t=2"))
        #expect(encoded.contains("p=1"))
        #expect(encoded.contains("c29tZXNhbHQ")) // Base64 of "somesalt"
    }

    @Test("PHC encode argon2i v13")
    func phcEncode_argon2i_v13() {
        let salt = Array("somesalt".utf8)
        let hash = hexDecode("c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0")!

        let encoded = encodeHash(
            type: .argon2i,
            version: .v13,
            memoryCost: 65536,
            timeCost: 2,
            parallelism: 1,
            salt: salt,
            hash: hash
        )

        #expect(encoded.hasPrefix("$argon2i$v=19$"))
        #expect(encoded.contains("m=65536,t=2,p=1"))
    }

    @Test("PHC encode argon2id v13")
    func phcEncode_argon2id_v13() {
        let salt = Array("somesalt".utf8)
        let hash = hexDecode("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")!

        let encoded = encodeHash(
            type: .argon2id,
            version: .v13,
            memoryCost: 65536,
            timeCost: 2,
            parallelism: 1,
            salt: salt,
            hash: hash
        )

        #expect(encoded.hasPrefix("$argon2id$v=19$"))
    }

    // MARK: - PHC Decoding Tests

    @Test("PHC decode argon2i v10")
    func phcDecode_argon2i_v10() throws {
        let encoded = "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ"

        let decoded = try decodeHash(encoded)

        #expect(decoded.type == .argon2i)
        #expect(decoded.version == .v10)
        #expect(decoded.memoryCost == 65536)
        #expect(decoded.timeCost == 2)
        #expect(decoded.parallelism == 1)
        #expect(decoded.salt == Array("somesalt".utf8))
    }

    @Test("PHC decode argon2i v13")
    func phcDecode_argon2i_v13() throws {
        let encoded = "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA"

        let decoded = try decodeHash(encoded)

        #expect(decoded.type == .argon2i)
        #expect(decoded.version == .v13)
        #expect(decoded.memoryCost == 65536)
        #expect(decoded.timeCost == 2)
        #expect(decoded.parallelism == 1)
        #expect(decoded.salt == Array("somesalt".utf8))
    }

    @Test("PHC decode argon2id")
    func phcDecode_argon2id() throws {
        let encoded = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"

        let decoded = try decodeHash(encoded)

        #expect(decoded.type == .argon2id)
        #expect(decoded.version == .v13)
    }

    @Test("PHC decode argon2d")
    func phcDecode_argon2d() throws {
        let encoded = "$argon2d$v=19$m=256,t=2,p=1$c29tZXNhbHQ$WdME7F4J1CUpDUEILuxcAOqB5S6Mm7/eGAe5FuiE0oQ"

        let decoded = try decodeHash(encoded)

        #expect(decoded.type == .argon2d)
    }

    // MARK: - Decoding Errors

    @Test("PHC decode invalid format")
    func phcDecode_invalidFormat() {
        #expect(throws: DecodingError.self) {
            _ = try decodeHash("not a valid hash")
        }
    }

    @Test("PHC decode missing type")
    func phcDecode_missingType() {
        #expect(throws: (any Error).self) {
            _ = try decodeHash("$argon2$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$hash")
        }
    }

    @Test("PHC decode invalid type")
    func phcDecode_invalidType() {
        #expect(throws: (any Error).self) {
            _ = try decodeHash("$argon2x$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$hash")
        }
    }

    @Test("PHC decode missing salt delimiter")
    func phcDecode_missingSaltDelimiter() {
        #expect(throws: (any Error).self) {
            _ = try decodeHash("$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ$hash")
        }
    }

    @Test("PHC decode missing hash delimiter")
    func phcDecode_missingHashDelimiter() {
        #expect(throws: (any Error).self) {
            _ = try decodeHash("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQhash")
        }
    }

    @Test("PHC decode salt too short")
    func phcDecode_saltTooShort() {
        // Empty salt (less than 8 bytes)
        #expect(throws: (any Error).self) {
            _ = try decodeHash("$argon2i$v=19$m=65536,t=2,p=1$$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ")
        }
    }

    // MARK: - Round Trip

    @Test("PHC round trip")
    func phcRoundTrip() throws {
        let salt = Array("testsalt12345678".utf8)
        let hash: [UInt8] = (0..<32).map { UInt8($0) }

        let encoded = encodeHash(
            type: .argon2id,
            version: .v13,
            memoryCost: 131072,
            timeCost: 3,
            parallelism: 4,
            salt: salt,
            hash: hash
        )

        let decoded = try decodeHash(encoded)

        #expect(decoded.type == .argon2id)
        #expect(decoded.version == .v13)
        #expect(decoded.memoryCost == 131072)
        #expect(decoded.timeCost == 3)
        #expect(decoded.parallelism == 4)
        #expect(decoded.salt == salt)
        #expect(decoded.hash == hash)
    }

    // MARK: - Helpers

    private func hexDecode(_ hex: String) -> [UInt8]? {
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
