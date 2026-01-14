# <img src="https://github.com/FeatherTools/.github/blob/main/profile/feather-logo-200.png" alt="FeatherTools Logo" width="100" height="100"> Cryptography

[![NuGet](https://img.shields.io/nuget/v/Feather.Cryptography.svg)](https://www.nuget.org/packages/Feather.Cryptography)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Feather.Cryptography.svg)](https://www.nuget.org/packages/Feather.Cryptography)
[![Checks](https://github.com/FeatherTools/cryptography/actions/workflows/tests.yaml/badge.svg)](https://github.com/FeatherTools/cryptography/actions/workflows/tests.yaml)

> Library with a predefined use-cases for encryption, decryption and hashing.

## Install

```sh
paket add Feather.Cryptography
```

## Usage

### Encoding

```fsharp
open Feather.Cryptography.Encode

// String to bytes and back
let text = "Hello, World!"
let bytes = stringToBytes text
let decoded = bytesToString bytes

// Base64 encoding
let encoded = Base64.encodeString "Hello, World!"
let decoded = Base64.decodeString encoded

// Base64 URL-safe encoding (for JWTs, URLs)
let base64Url =
    "Hello, World!"
    |> Base64.encodeString
    |> Base64.toBase64Url

let original =
    base64Url
    |> Base64.fromBase64Url
    |> Base64.decodeString
```

### Hashing

```fsharp
open Feather.Cryptography.Hash

// SHA256 hex hash
let hash = SHA256.sha256Hex "hello world"
// Result: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

// CRC32 checksum
let checksum = Crc32.crc32OfString "hello world"
// Result: "d4a1185"

// SHA256 of bytes
let dataBytes = "hello world"B
let hashBytes = SHA256.sha256 dataBytes
```

### RSA Encryption

```fsharp
open Feather.Cryptography.Cryptography

// Generate RSA key pair
let privateKey, publicKey = RSA256.createKeyPair()

// Encrypt data with public key
let plaintext = "Secret message"B
let encrypted = RSA256.encrypt publicKey plaintext

// Decrypt with private key
let decrypted = RSA256.decrypt privateKey encrypted
```

### AES-GCM Encryption

```fsharp
open Feather.Cryptography.Cryptography

// Generate a data encryption key (DEK)
let dek = AES256GCM.generateKey()

// Encrypt without additional authenticated data (AAD)
let plaintext = "Sensitive data"B
let iv, ciphertext, tag = AES256GCM.encrypt dek None plaintext

// Decrypt
let decrypted = AES256GCM.decrypt dek iv ciphertext tag None

// Encrypt with AAD (authenticated but not encrypted metadata)
let metadata = AAD "document-id-123"B
let iv2, ciphertext2, tag2 = AES256GCM.encrypt dek (Some metadata) plaintext

// Decrypt with AAD
let decrypted2 = AES256GCM.decrypt dek iv2 ciphertext2 tag2 (Some metadata)
```

### Envelope Encryption

Envelope encryption combines symmetric and asymmetric encryption: data is encrypted with a DEK (fast AES-GCM), then the DEK is encrypted with a master key (KEK) (RSA or vault service).

```fsharp
open Feather.Cryptography.Cryptography
open Feather.ErrorHandling

// Setup: Generate RSA keys or use a vault service
let privateKey, publicKey = RSA256.createKeyPair()

// Define how to encrypt the DEK (e.g., with RSA or vault)
let encryptDEK (DEK dek) = asyncResult {
    return RSA256.encrypt publicKey dek
}

// Define how to decrypt the DEK
let decryptDEK encryptedDek = asyncResult {
    let dekBytes = RSA256.decrypt privateKey encryptedDek
    return DEK dekBytes
}

// Encrypt data
let plaintext = "Top secret data"B
let envelope =
    EncryptedEnvelope.encrypt encryptDEK None plaintext
    |> AsyncResult.runSynchronously
    |> Result.orFail

// The envelope contains:
// - Version and Algorithm metadata
// - IV (initialization vector)
// - Ciphertext (encrypted data)
// - Tag (authentication tag)
// - DEK (encrypted data encryption key)
// - Optional AAD (additional authenticated data)

// Decrypt data
let decrypted =
    EncryptedEnvelope.decrypt decryptDEK envelope
    |> AsyncResult.runSynchronously
    |> Result.orFail

// With AAD (e.g., document ID, user ID, etc.)
let aad = AAD "user-123/document-456"B
let envelopeWithAAD =
    EncryptedEnvelope.encrypt encryptDEK (Some aad) plaintext
    |> AsyncResult.runSynchronously
    |> Result.orFail
```

#### Using Azure Key Vault for DEK Encryption

```fsharp
open Azure.Security.KeyVault.Keys.Cryptography

let encryptDEKWithVault (vaultClient: CryptographyClient) (DEK dek) = asyncResult {
    try
        let! result =
            vaultClient.EncryptAsync(EncryptionAlgorithm.RsaOaep256, dek)
            |> Async.AwaitTask
        return EncryptedData result.Ciphertext
    with ex ->
        return! Error $"Vault encryption failed: {ex.Message}"
}

let decryptDEKWithVault (vaultClient: CryptographyClient) (EncryptedData encryptedDek) = asyncResult {
    try
        let! result =
            vaultClient.DecryptAsync(EncryptionAlgorithm.RsaOaep256, encryptedDek)
            |> Async.AwaitTask
        return DEK result.Plaintext
    with ex ->
        return! Error $"Vault decryption failed: {ex.Message}"
}
```

## Release
1. Increment version in `Cryptography.fsproj`
2. Update `CHANGELOG.md`
3. Commit new version and tag it

## Development
### Requirements
- [dotnet core](https://dotnet.microsoft.com/learn/dotnet/hello-world-tutorial)

### Build
```bash
./build.sh build
```

### Tests
```bash
./build.sh -t tests
```
