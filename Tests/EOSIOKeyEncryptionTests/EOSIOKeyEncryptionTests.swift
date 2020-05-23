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
}
