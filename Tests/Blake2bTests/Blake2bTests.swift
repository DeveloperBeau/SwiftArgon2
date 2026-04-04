/// BLAKE2b test suite
import Testing
@testable import Blake2b

@Suite("BLAKE2b Hash Function")
struct Blake2bTests {

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

    // MARK: - Basic Tests

    @Test("Empty input hash")
    func emptyInput() throws {
        let result = try blake2b([], outputLength: 64)
        let expected = hexDecode("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")!

        #expect(result == expected)
    }

    @Test("Simple 'abc' input hash")
    func simpleInput() throws {
        let result = try blake2b(Array("abc".utf8), outputLength: 64)
        let expected = hexDecode("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")!

        #expect(result == expected)
    }

    // MARK: - Variable Output Length

    @Test("32-byte output length")
    func outputLength32() throws {
        let result = try blake2b(Array("test".utf8), outputLength: 32)
        #expect(result.count == 32)
    }

    @Test("16-byte output length")
    func outputLength16() throws {
        let result = try blake2b(Array("test".utf8), outputLength: 16)
        #expect(result.count == 16)
    }

    @Test("1-byte output length")
    func outputLength1() throws {
        let result = try blake2b(Array("test".utf8), outputLength: 1)
        #expect(result.count == 1)
    }

    // MARK: - Keyed Hashing

    @Test("Keyed hash differs from unkeyed")
    func keyedHash() throws {
        let key = Array("secret key".utf8)
        let message = Array("hello world".utf8)
        let result = try blake2b(message, key: key, outputLength: 32)

        #expect(result.count == 32)
        let unkeyed = try blake2b(message, outputLength: 32)
        #expect(result != unkeyed)
    }

    // MARK: - Blake2b Long Tests

    @Test("Blake2bLong short output (≤64 bytes)")
    func blake2bLongShortOutput() throws {
        let result = try blake2bLong(Array("input".utf8), outputLength: 32)
        #expect(result.count == 32)
    }

    @Test("Blake2bLong 128-byte output")
    func blake2bLong128Bytes() throws {
        let result = try blake2bLong(Array("input".utf8), outputLength: 128)
        #expect(result.count == 128)
    }

    @Test("Blake2bLong 1024-byte output (Argon2 block size)")
    func blake2bLong1024Bytes() throws {
        let result = try blake2bLong(Array("input".utf8), outputLength: 1024)
        #expect(result.count == 1024)
    }

    // MARK: - Error Cases

    @Test("Invalid output length throws error")
    func invalidOutputLength() {
        #expect(throws: (any Error).self) {
            _ = try blake2b([], outputLength: 0)
        }
        #expect(throws: (any Error).self) {
            _ = try blake2b([], outputLength: 65)
        }
    }

    @Test("Invalid key length throws error")
    func invalidKeyLength() {
        let longKey = [UInt8](repeating: 0, count: 65)
        #expect(throws: (any Error).self) {
            _ = try blake2b([], key: longKey, outputLength: 32)
        }
    }

    // MARK: - Incremental Hashing

    @Test("Incremental hashing matches one-shot")
    func incrementalHashing() throws {
        let oneShot = try blake2b(Array("hello world".utf8), outputLength: 32)

        var state = Blake2bState()
        try blake2bInit(&state, outlen: 32)
        try blake2bUpdate(&state, Array("hello ".utf8))
        try blake2bUpdate(&state, Array("world".utf8))
        var incremental = [UInt8](repeating: 0, count: 32)
        try blake2bFinal(&state, &incremental)

        #expect(oneShot == incremental)
    }

    // MARK: - RFC 7693 Test Vectors

    @Test("RFC 7693 test vector")
    func rfc7693Vector1() throws {
        let result = try blake2b(Array("abc".utf8), outputLength: 64)
        let expected = hexDecode("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")!

        #expect(result == expected)
    }
}
