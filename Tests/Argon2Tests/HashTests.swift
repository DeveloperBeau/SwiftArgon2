/// Argon2 hash test suite
/// Test vectors from the C reference implementation
import Testing
@testable import Argon2
@testable import Argon2Core
@testable import Encoding

@Suite("Argon2 Hash Tests")
struct HashTests {

    // MARK: - Argon2i Version 0x10 Tests

    @Test("Argon2i v10 t=2 m=16 p=1")
    func argon2i_v10_t2_m16_p1() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2i,
                version: .v10,
                timeCost: 2,
                memoryCost: 65536,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694")!
        #expect(hash == expected)
    }

    @Test("Argon2i v10 t=2 m=8 p=1")
    func argon2i_v10_t2_m8_p1() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2i,
                version: .v10,
                timeCost: 2,
                memoryCost: 256,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06")!
        #expect(hash == expected)
    }

    @Test("Argon2i v10 t=2 m=8 p=2")
    func argon2i_v10_t2_m8_p2() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2i,
                version: .v10,
                timeCost: 2,
                memoryCost: 256,
                parallelism: 2,
                hashLength: 32
            )
        )

        let expected = hexDecode("b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb")!
        #expect(hash == expected)
    }

    @Test("Argon2i v10 t=1 m=16 p=1")
    func argon2i_v10_t1_m16_p1() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2i,
                version: .v10,
                timeCost: 1,
                memoryCost: 65536,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2")!
        #expect(hash == expected)
    }

    @Test("Argon2i v10 t=4 m=16 p=1")
    func argon2i_v10_t4_m16_p1() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2i,
                version: .v10,
                timeCost: 4,
                memoryCost: 65536,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b")!
        #expect(hash == expected)
    }

    // MARK: - Argon2i Version 0x13 Tests

    @Test("Argon2i v13 t=2 m=16 p=1")
    func argon2i_v13_t2_m16_p1() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2i,
                version: .v13,
                timeCost: 2,
                memoryCost: 65536,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0")!
        #expect(hash == expected)
    }

    @Test("Argon2i v13 t=2 m=8 p=1")
    func argon2i_v13_t2_m8_p1() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2i,
                version: .v13,
                timeCost: 2,
                memoryCost: 256,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f")!
        #expect(hash == expected)
    }

    @Test("Argon2i v13 t=2 m=8 p=2")
    func argon2i_v13_t2_m8_p2() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2i,
                version: .v13,
                timeCost: 2,
                memoryCost: 256,
                parallelism: 2,
                hashLength: 32
            )
        )

        let expected = hexDecode("4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61")!
        #expect(hash == expected)
    }

    @Test("Argon2i v13 t=1 m=16 p=1")
    func argon2i_v13_t1_m16_p1() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2i,
                version: .v13,
                timeCost: 1,
                memoryCost: 65536,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf")!
        #expect(hash == expected)
    }

    @Test("Argon2i v13 t=4 m=16 p=1")
    func argon2i_v13_t4_m16_p1() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2i,
                version: .v13,
                timeCost: 4,
                memoryCost: 65536,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b")!
        #expect(hash == expected)
    }

    // MARK: - Argon2id Version 0x13 Tests

    @Test("Argon2id v13 t=2 m=16 p=1")
    func argon2id_v13_t2_m16_p1() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2id,
                version: .v13,
                timeCost: 2,
                memoryCost: 65536,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")!
        #expect(hash == expected)
    }

    @Test("Argon2id v13 t=2 m=8 p=1")
    func argon2id_v13_t2_m8_p1() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2id,
                version: .v13,
                timeCost: 2,
                memoryCost: 256,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe")!
        #expect(hash == expected)
    }

    @Test("Argon2id v13 t=2 m=8 p=2")
    func argon2id_v13_t2_m8_p2() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2id,
                version: .v13,
                timeCost: 2,
                memoryCost: 256,
                parallelism: 2,
                hashLength: 32
            )
        )

        let expected = hexDecode("6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037")!
        #expect(hash == expected)
    }

    @Test("Argon2id v13 t=1 m=16 p=1")
    func argon2id_v13_t1_m16_p1() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2id,
                version: .v13,
                timeCost: 1,
                memoryCost: 65536,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98")!
        #expect(hash == expected)
    }

    @Test("Argon2id v13 t=4 m=16 p=1")
    func argon2id_v13_t4_m16_p1() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2id,
                version: .v13,
                timeCost: 4,
                memoryCost: 65536,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c")!
        #expect(hash == expected)
    }

    // MARK: - Different Password/Salt Tests

    @Test("Different password v10")
    func differentPassword_v10() throws {
        let hash = try Argon2.hashRaw(
            password: Array("differentpassword".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2i,
                version: .v10,
                timeCost: 2,
                memoryCost: 65536,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3")!
        #expect(hash == expected)
    }

    @Test("Different salt v10")
    func differentSalt_v10() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("diffsalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2i,
                version: .v10,
                timeCost: 2,
                memoryCost: 65536,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497")!
        #expect(hash == expected)
    }

    @Test("Different password v13")
    func differentPassword_v13() throws {
        let hash = try Argon2.hashRaw(
            password: Array("differentpassword".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2i,
                version: .v13,
                timeCost: 2,
                memoryCost: 65536,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee")!
        #expect(hash == expected)
    }

    @Test("Different salt v13")
    func differentSalt_v13() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("diffsalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2i,
                version: .v13,
                timeCost: 2,
                memoryCost: 65536,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271")!
        #expect(hash == expected)
    }

    @Test("Different password id v13")
    func differentPassword_id_v13() throws {
        let hash = try Argon2.hashRaw(
            password: Array("differentpassword".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2id,
                version: .v13,
                timeCost: 2,
                memoryCost: 65536,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde")!
        #expect(hash == expected)
    }

    @Test("Different salt id v13")
    func differentSalt_id_v13() throws {
        let hash = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("diffsalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2id,
                version: .v13,
                timeCost: 2,
                memoryCost: 65536,
                parallelism: 1,
                hashLength: 32
            )
        )

        let expected = hexDecode("bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c")!
        #expect(hash == expected)
    }

    // MARK: - String API Tests

    @Test("String password API")
    func stringPassword() throws {
        let hash1 = try Argon2.hashRaw(
            password: "password",
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2id,
                version: .v13,
                timeCost: 2,
                memoryCost: 256,
                parallelism: 1,
                hashLength: 32
            )
        )

        let hash2 = try Argon2.hashRaw(
            password: Array("password".utf8),
            salt: Array("somesalt".utf8),
            configuration: Argon2Configuration(
                variant: .argon2id,
                version: .v13,
                timeCost: 2,
                memoryCost: 256,
                parallelism: 1,
                hashLength: 32
            )
        )

        #expect(hash1 == hash2)
    }

    // MARK: - Helpers

    private func hexDecode(_ hex: String) -> [UInt8]? {
        Argon2.hexDecode(hex)
    }
}
