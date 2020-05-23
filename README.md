# swift-eosio-key-encryption

EOSIO Private Key encryption

  - Supports multiple curve types
  - Scrypt key derivation with configurable params
  - Encodes to human readable-ish strings (`SEC_K1_8vWLjFLTcvWNKY8wwfMKJJ3Sf278qb5xQgqXFzrRF44ECxACwoC3RPTj`)

## Data format

 - 1 byte key type (secp256k1 = 0)
 - 1 byte scrypt params
 - 4 byte checksum of public key
 - 32 byte ciphertext
