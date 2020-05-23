import EOSIO
@testable import EOSIOKeyEncryption
import XCTest

final class EOSIOKeyEncryptionTests: XCTestCase {
    func testEncryption() {
        let password = "foobar".data(using: .utf8)!

        let key = PrivateKey("5JZAVLoiZWc5u4JsmFXfZa7MfBsf7axQy2nu5ztrQitukEhmLzE")
        let encrypted = try! key.encrypted(using: password)

        XCTAssertEqual(encrypted, "SEC_K1_8vWLjFLTcvWNKY8wwfMKJJ3Sf278qb5xQgqXFzrRF44ECxACwoC3RPTj")
        XCTAssertEqual(encrypted.securityLevel, .default)

        let decrypted = try! encrypted.decrypt(using: password)

        XCTAssertEqual(key, decrypted)

        XCTAssertThrowsError(try encrypted.decrypt(using: "hunter1".data(using: .utf8)!))
    }

    func testSecurityLevel() {
        var params = EncryptedPrivateKey.SecurityLevel.default.params
        XCTAssertEqual(params.N, 32768)
        XCTAssertEqual(params.r, 16)
        XCTAssertEqual(params.p, 1)
        params = EncryptedPrivateKey.SecurityLevel.high.params
        XCTAssertEqual(params.N, 65536)
        XCTAssertEqual(params.r, 16)
        XCTAssertEqual(params.p, 1)
        params = EncryptedPrivateKey.SecurityLevel.paranoid.params
        XCTAssertEqual(params.N, 131_072)
        XCTAssertEqual(params.r, 16)
        XCTAssertEqual(params.p, 1)
        params = EncryptedPrivateKey.SecurityLevel.custom(0).params
        XCTAssertEqual(params.N, 16384)
        XCTAssertEqual(params.r, 8)
        XCTAssertEqual(params.p, 1)
        params = EncryptedPrivateKey.SecurityLevel.custom(0xFF).params
        XCTAssertEqual(params.N, 2_097_152)
        XCTAssertEqual(params.r, 1024)
        XCTAssertEqual(params.p, 8)

        XCTAssertEqual(EncryptedPrivateKey.SecurityLevel.default, EncryptedPrivateKey.SecurityLevel.custom(36))
        XCTAssertNotEqual(EncryptedPrivateKey.SecurityLevel.default, EncryptedPrivateKey.SecurityLevel.custom(0))
        XCTAssertNotEqual(EncryptedPrivateKey.SecurityLevel.default, EncryptedPrivateKey.SecurityLevel.high)
    }

    func testCoding() {
        let encryptedKey = EncryptedPrivateKey("SEC_K1_8vWLjFLTcvWNKY8wwfMKJJ3Sf278qb5xQgqXFzrRF44ECxACwoC3RPTj")

        let abiEncoder = ABIEncoder()
        let abiData: Data = try! abiEncoder.encode(encryptedKey)

        XCTAssertEqual(
            abiData.hexEncodedString(),
            "00241feb8491b4fd5745396bb401bac0be2c7a85855b3b2b79eaafced1396765e315b7a93fec"
        )

        let jsonEncoder = JSONEncoder()
        let jsonData = try! jsonEncoder.encode(encryptedKey)

        XCTAssertEqual(
            String(bytes: jsonData, encoding: .utf8)!,
            "\"SEC_K1_8vWLjFLTcvWNKY8wwfMKJJ3Sf278qb5xQgqXFzrRF44ECxACwoC3RPTj\""
        )

        let abiDecoder = ABIDecoder()
        let abiDecoded = try! abiDecoder.decode(EncryptedPrivateKey.self, from: abiData)

        XCTAssertEqual(encryptedKey, abiDecoded)

        let jsonDecoder = JSONDecoder()
        let jsonDecoded = try! jsonDecoder.decode(EncryptedPrivateKey.self, from: jsonData)

        XCTAssertEqual(encryptedKey, jsonDecoded)
    }
}
