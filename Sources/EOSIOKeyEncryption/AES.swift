import CommonCrypto
import Foundation

internal struct AES {
    enum Error: Swift.Error {
        case cryptoFailed(status: CCCryptorStatus)
        case badKeyLength
        case badInputVectorLength
    }

    enum Operation {
        case encrypt
        case decrypt

        fileprivate var op: CCOperation {
            switch self {
            case .decrypt:
                return CCOptions(kCCDecrypt)
            case .encrypt:
                return CCOptions(kCCEncrypt)
            }
        }
    }

    private let key: Data
    private let iv: Data

    init(key: Data, iv: Data) throws {
        guard key.count == kCCKeySizeAES256 else {
            throw Error.badKeyLength
        }
        guard iv.count == kCCBlockSizeAES128 else {
            throw Error.badInputVectorLength
        }
        self.key = key
        self.iv = iv
    }

    func crypt(input: Data, operation: Operation) throws -> Data {
        var outLength = Int(0)
        var outBytes = [UInt8](repeating: 0, count: input.count + kCCBlockSizeAES128)
        var status: CCCryptorStatus = -1
        input.withUnsafeBytes { (inputPtr: UnsafeRawBufferPointer) -> Void in
            iv.withUnsafeBytes { (ivPtr: UnsafeRawBufferPointer) -> Void in
                key.withUnsafeBytes { (keyPtr: UnsafeRawBufferPointer) -> Void in
                    status = CCCrypt(operation.op,
                                     CCAlgorithm(kCCAlgorithmAES), // algorithm
                                     0, // options
                                     keyPtr.bufPtr, // key
                                     keyPtr.count, // keylength
                                     ivPtr.bufPtr, // iv
                                     inputPtr.bufPtr, // dataIn
                                     inputPtr.count, // dataInLength
                                     &outBytes, // dataOut
                                     outBytes.count, // dataOutAvailable
                                     &outLength) // dataOutMoved
                }
            }
            return
        }
        guard status == kCCSuccess else {
            throw Error.cryptoFailed(status: status)
        }
        return outBytes.withUnsafeBytes { ptr in
            Data(bytes: ptr.bufPtr, count: outLength)
        }
    }
}
