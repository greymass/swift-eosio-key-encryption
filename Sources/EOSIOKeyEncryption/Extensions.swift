import Foundation

internal extension UnsafeRawBufferPointer {
    var bufPtr: UnsafePointer<UInt8> {
        baseAddress!.assumingMemoryBound(to: UInt8.self)
    }
}
