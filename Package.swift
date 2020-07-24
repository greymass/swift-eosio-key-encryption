// swift-tools-version:5.2

import PackageDescription

let package = Package(
    name: "swift-eosio-key-encryption",
    products: [
        .library(name: "EOSIOKeyEncryption", targets: ["EOSIOKeyEncryption"]),
    ],
    dependencies: [
        .package(url: "https://github.com/greymass/swift-eosio.git", .branch("master")),
        .package(url: "https://github.com/greymass/swift-scrypt.git", .branch("master")),
    ],
    targets: [
        .target(
            name: "EOSIOKeyEncryption",
            dependencies: ["EOSIO", "Scrypt"]
        ),
        .testTarget(
            name: "EOSIOKeyEncryptionTests",
            dependencies: ["EOSIOKeyEncryption"]
        ),
    ]
)
