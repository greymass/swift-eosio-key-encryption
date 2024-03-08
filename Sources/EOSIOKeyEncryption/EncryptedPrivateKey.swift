import EOSIO
import Foundation
import Scrypt

enum TestError: Error {
    case failed(String)
}

extension TestError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .failed(let message):
            return message
        }
    }
}

/// Type encapsulating an encrypted EOSIO private key.
public struct EncryptedPrivateKey: Equatable, Hashable {
    public enum SecurityLevel {
        case `default`
        case high
        case paranoid
        case custom(UInt8)

        internal static let allNamed: [Self] = [.default, .high, .paranoid]

        internal init(_ header: UInt8) {
            for value in Self.allNamed {
                if value.flags == header {
                    self = value
                    return
                }
            }
            self = .custom(header)
        }

        /// Resolved scrypt params (N, r, p).
        public var params: (N: UInt64, r: UInt32, p: UInt32) {
            let flags = self.flags

            let nExp = ((flags & 0b1110_0000) >> 5) + 14 // First 3 bits is N starting at 14
            let rExp = ((flags & 0b0001_1100) >> 2) + 3 // Next 3 bits is r starting at 3
            let pExp = flags & 0b0000_0011 // Last two bits is p

            // raise to power of 2
            let N: UInt64 = 1 << nExp
            let r: UInt32 = 1 << rExp
            let p: UInt32 = 1 << pExp

            return (N, r, p)
        }

        /// Scrypt param flags.
        ///
        /// Byte used to specify what scrypt params should be used.
        /// - 3 bits N as power of two starting at 14
        /// - 3 bits r as power of two 8 starting at 3
        /// - 2 bits p as a power of two starting at 0
        ///
        /// Easiest difficulty represented is: N=16384 r=8 p=1 (2009 scrypt paper recommendation).
        /// Hardest: N=2097152, r=1024, p=16 (don't use this).
        internal var flags: UInt8 {
            switch self {
            case .default:
                return 0b0010_0100 // N=32768 p=16 r=1
            case .high:
                return 0b0100_0100 // N=65536 p=16 r=1
            case .paranoid:
                return 0b0110_0100 // N=131072 p=16 r=1
            case let .custom(flags):
                return flags
            }
        }
    }

    public enum Error: Swift.Error {
        case invalidK1Data
        case parsingFailed(_ message: String)
        case unsupportedKeyType(_ type: String)
        case invalidPassword
    }

    private enum Storage: Equatable, Hashable {
        /// 32-bytes encrypted k1 key.
        case k1(data: Data)
        /// Unknown type.
        case unknown(name: String, data: Data)
    }

    /// Internal key data.
    private let storage: Storage
    /// Header with scrypt params.
    private let header: UInt8

    /// Checksum of the corresponding public key.
    /// First 4 bytes of `double_sha256(PUB_<type>_<base58checkKeyData>)`.
    public let checksum: Data

    /// Create new instance from K1 key data
    public init(fromK1Data data: Data) throws {
        guard data.count == 37 else {
            throw Error.invalidK1Data
        }
        header = data[0]
        checksum = data[1 ..< 5]
        storage = .k1(data: data.suffix(from: 5))
    }

    internal init?(fromUnknownData data: Data, ofType name: String) {
        guard data.count > 6 else {
            return nil
        }
        header = data[0]
        checksum = data[1 ..< 5]
        storage = .unknown(name: name, data: data.suffix(from: 5))
    }

    /// Create new instance from string format, e.g. `SEC_K1_<base58data>`.
    public init(stringValue: String) throws {
        guard stringValue.starts(with: "SEC_") else {
            throw Error.parsingFailed("Not a encrypted private key string")
        }
        let parts = stringValue.split(separator: "_")
        guard parts.count == 3 else {
            throw Error.parsingFailed("Malformed key string")
        }
        let checksumData = parts[1].data(using: .utf8) ?? Data(repeating: 0, count: 4)
        guard let data = Data(base58CheckEncoded: String(parts[2]), .ripemd160Extra(checksumData)) else {
            throw Error.parsingFailed("Unable to decode base58")
        }
        switch parts[1] {
        case "K1":
            try self.init(fromK1Data: data)
        default:
            guard parts[1].count == 2, parts[1].uppercased() == parts[1] else {
                throw Error.parsingFailed("Invalid key type")
            }
            guard let instance = Self(fromUnknownData: data, ofType: String(parts[1])) else {
                throw Error.parsingFailed("Invalid data payload")
            }
            self = instance
        }
    }

    /// Encrypted key curve type, e.g. `K1`.
    public var keyType: String {
        switch storage {
        case .k1:
            return "K1"
        case let .unknown(type, _):
            return type
        }
    }

    /// The encrypted key.
    public var ciphertext: Data {
        switch storage {
        case let .k1(data):
            return data
        case let .unknown(_, data):
            return data
        }
    }

    /// Security level this key was encrypted with.
    public var securityLevel: SecurityLevel {
        .init(header)
    }

    /// Header + checksum + ciphertext.
    public var data: Data {
        var rv = Data([header])
        rv.append(contentsOf: checksum)
        rv.append(contentsOf: ciphertext)
        return rv
    }

    /// The string representation of the encrypted key in the  format, `SEC_<type>_<base58data>`.
    public var stringValue: String {
        let type = keyType
        let encoded = data.base58CheckEncodedString(.ripemd160Extra(Data(type.utf8)))!
        return "SEC_\(type)_\(encoded)"
    }

    /// Decrypt private key, throws on wrong password.
    /// - Attention: This is very compute intensive, call this on a background thread. It's also good to verify that the
    ///              securityLevel is not set to something insane before attempting decryption.
    public func decrypt(using password: Data) throws -> PrivateKey {
        guard keyType == "K1" else {
            throw EncryptedPrivateKey.Error.unsupportedKeyType(keyType)
        }

        var decrypted = try Self.crypt(ciphertext, password: password, salt: checksum, security: securityLevel, operation: .decrypt)
        decrypted.insert(0x80, at: 0)

        let privateKey = try PrivateKey(fromK1Data: decrypted)
        let publicKey = try privateKey.getPublic()

       throw TestError.failed("checksum: \(checksum.hexEncodedString()) decrypted privateKey.stringValue: \(privateKey.stringValue) ||| decrypted publicKey.checksum: \(publicKey.checksum.hexEncodedString())")

        guard publicKey.checksum == checksum else {
            throw Error.invalidPassword
        }

        return privateKey
    }

    /// Encrypt or decrypt given input using password, salt and security level (scrypt params).
    fileprivate static func crypt(_ input: Data, password: Data, salt: Data, security: SecurityLevel, operation: AES.Operation) throws -> Data {
        let params = security.params
        let hash = try scrypt(password: Array(password), salt: Array(salt), length: 32 + 16, N: params.N, r: params.r, p: params.p)

        let iv = Data(hash[0 ..< 16])
        
        let key = Data(hash[16 ..< 48])

        let aes = try AES(key: key, iv: iv).crypt(input: input, operation: operation)
        
        // throw TestError.failed("scrypt params: \(params) ||| hash \(hash.hashValue) ||| iv: \(iv.hexEncodedString()) ||| key: \(key.hexEncodedString()) ||| aes: \(aes.hexEncodedString())")
        
        return aes
    }
}

public extension PrivateKey {
    /// Encrypt this private key using given password.
    /// - Attention: This is very compute intensive, call this on a background thread.
    func encrypted(using password: Data, securityLevel: EncryptedPrivateKey.SecurityLevel = .default) throws -> EncryptedPrivateKey {
        guard keyType == "K1" else {
            throw EncryptedPrivateKey.Error.unsupportedKeyType(keyType)
        }

        // key checksum, also used as scrypt salt
        let checksum = (try getPublic()).checksum

        // encrypt the key
        let encrypted = try EncryptedPrivateKey.crypt(keyData, password: password, salt: checksum, security: securityLevel, operation: .encrypt)

        // pack result with header and checksum
        var data = Data([securityLevel.flags])
        data.append(contentsOf: checksum)
        data.append(contentsOf: encrypted)

        return try EncryptedPrivateKey(fromK1Data: data)
    }
}

public extension PublicKey {
    /// First 4 bytes of double sha256 over key string (`PUB_K1_<base58check>`)
    var checksum: Data {
        stringValue.data(using: .ascii)!.sha256Digest.sha256Digest[0 ..< 4]
    }
}

// MARK: - ABI Coding conformance

extension EncryptedPrivateKey: ABICodable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(stringValue: try container.decode(String.self))
    }

    public init(fromAbi decoder: ABIDecoder) throws {
        let type = try decoder.decode(UInt8.self)
        let data = try decoder.decode(Data.self, byteCount: 1 + 4 + 32)
        if type == 0 {
            try self.init(fromK1Data: data)
        } else {
            let typeName: String
            switch type {
            case 1:
                typeName = "R1"
            case 2:
                typeName = "WA"
            default:
                typeName = "XX"
            }
            guard let instance = Self(fromUnknownData: data, ofType: typeName) else {
                throw DecodingError.dataCorrupted(DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Unable to create EncryptedPrivateKey instance for unknown type: \(typeName)"
                ))
            }
            self = instance
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(stringValue)
    }

    public func abiEncode(to encoder: ABIEncoder) throws {
        let type: UInt8
        switch keyType {
        case "K1":
            type = 0
        case "R1":
            type = 1
        case "WA":
            type = 2
        default:
            type = 255
        }
        try encoder.encode(type)
        try encoder.encode(contentsOf: data)
    }
}

// MARK: - Standard protocol conformances

extension EncryptedPrivateKey: LosslessStringConvertible {
    public init?(_ description: String) {
        guard let instance = try? EncryptedPrivateKey(stringValue: description) else {
            return nil
        }
        self = instance
    }

    public var description: String {
        stringValue
    }
}

extension EncryptedPrivateKey: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        guard let instance = try? EncryptedPrivateKey(stringValue: value) else {
            fatalError("Invalid EncryptedPrivateKey literal")
        }
        self = instance
    }
}

extension EncryptedPrivateKey.SecurityLevel: CustomStringConvertible {
    public var description: String {
        let params = self.params
        return "N=\(params.N) r=\(params.r) p=\(params.p)"
    }
}

extension EncryptedPrivateKey.SecurityLevel: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.flags == rhs.flags
    }
}
