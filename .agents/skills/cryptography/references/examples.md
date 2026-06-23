# Examples

This is the single source of all example code for the skill. Examples are ordered from basic to full workflow and are self-contained.

## Encoding

```fsharp
open Feather.Cryptography.Encode

// String <-> bytes (UTF-8)
let bytes = stringToBytes "Hello, World!"
let text = bytesToString bytes

// Standard Base64 round-trip
let encoded = Base64.encodeString "Hello, World!"
let decoded = Base64.decodeString encoded

// URL-safe base64url (for JWTs, query parameters)
let urlSafe =
    "Hello, World!"
    |> Base64.encodeString
    |> Base64.toBase64Url

let original =
    urlSafe
    |> Base64.fromBase64Url
    |> Base64.decodeString
```

## Hashing

```fsharp
open Feather.Cryptography.Hash

// SHA-256 as lowercase hex
let digest = SHA256.sha256Hex "hello world"
// "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

// SHA-256 of raw bytes
let rawDigest = SHA256.sha256 "hello world"B

// CRC-32 checksum (hex)
let checksum = Crc32.crc32OfString "hello world"
// "d4a1185"
```

## RSA

```fsharp
open Feather.Cryptography.Cryptography

let privateKey, publicKey = RSA256.createKeyPair ()

let encrypted = RSA256.encrypt publicKey "Secret message"B
let decrypted = RSA256.decrypt privateKey encrypted
```

## AES-GCM

```fsharp
open Feather.Cryptography.Cryptography

let dek = AES256GCM.generateKey ()

// Without additional authenticated data
let iv, ciphertext, tag = AES256GCM.encrypt dek None "Sensitive data"B
let plaintext = AES256GCM.decrypt dek iv ciphertext tag None

// With AAD (authenticated, not encrypted) — must match on decrypt
let aad = AAD "record-metadata"B
let iv2, ciphertext2, tag2 = AES256GCM.encrypt dek (Some aad) "Sensitive data"B
let plaintext2 = AES256GCM.decrypt dek iv2 ciphertext2 tag2 (Some aad)
```

## Symmetric

```fsharp
open Feather.Cryptography.Cryptography

// Generate a strong secret, or supply any string from an external secret store
let secret = Symmetric.generateSecret ()

let ciphertext = Symmetric.encrypt secret "Hello, symmetric world!"

match Symmetric.decrypt secret ciphertext with
| Ok plaintext -> printfn "Decrypted: %s" plaintext
| Error msg    -> printfn "Failed: %s" msg
```

## Bcrypt

```fsharp
open Feather.Cryptography.Cryptography

let hashed = Bcrypt.hashPassword "StrongPassword123!"

let isValid = Bcrypt.verifyPassword "StrongPassword123!" hashed   // true
let isWrong = Bcrypt.verifyPassword "WrongPassword" hashed        // false
```

## Envelope Encryption (Integration)

The payload is encrypted with a per-message `DEK`; the `DEK` is wrapped by a caller-supplied function so the master key can live in an external key service. Here RSA stands in for that service.

```fsharp
open Feather.Cryptography.Cryptography
open Feather.ErrorHandling

let privateKey, publicKey = RSA256.createKeyPair ()

let encryptDEK (DEK dek) = asyncResult {
    return RSA256.encrypt publicKey dek
}

let decryptDEK encryptedDek = asyncResult {
    let dekBytes = RSA256.decrypt privateKey encryptedDek
    return DEK dekBytes
}

let aad = AAD "resource-123"B |> Some

let envelope =
    "Top secret data"B
    |> EncryptedEnvelope.encrypt encryptDEK aad
    |> AsyncResult.runSynchronously
    |> Result.orFail

let decrypted =
    envelope
    |> EncryptedEnvelope.decrypt decryptDEK aad
    |> AsyncResult.runSynchronously
    |> Result.orFail
```

## Envelope Encryption with an External Key Service (Integration)

Plug any vault/HSM client into the same `encryptDEK`/`decryptDEK` shape. `KeyService` is a neutral placeholder for such a client.

```fsharp
open Feather.Cryptography.Cryptography
open Feather.ErrorHandling

let encryptDEKWithService (keyService: KeyService) (DEK dek) = asyncResult {
    try
        let! ciphertext = keyService.WrapAsync dek |> Async.AwaitTask
        return EncryptedData ciphertext
    with ex ->
        return! Error $"Key service wrap failed: {ex.Message}"
}

let decryptDEKWithService (keyService: KeyService) (EncryptedData wrappedDek) = asyncResult {
    try
        let! dek = keyService.UnwrapAsync wrappedDek |> Async.AwaitTask
        return DEK dek
    with ex ->
        return! Error $"Key service unwrap failed: {ex.Message}"
}
```

## Batch Envelope Encryption (Integration)

Wrap many `DEK`s in a single round-trip to the key service; list order is preserved.

```fsharp
open Feather.Cryptography.Cryptography
open Feather.ErrorHandling

let encryptDEKs (deks: DEK list) = asyncResult {
    return deks |> List.map (fun (DEK dek) -> RSA256.encrypt publicKey dek)
}

let decryptDEKs (wrapped: EncryptedData list) = asyncResult {
    return wrapped |> List.map (fun ed -> DEK (RSA256.decrypt privateKey ed))
}

let payloads = [ "Item 1"B; "Item 2"B; "Item 3"B ]

let envelopes =
    payloads
    |> EncryptedEnvelope.encryptBatch encryptDEKs None
    |> AsyncResult.runSynchronously
    |> Result.orFail

let restored =
    envelopes
    |> EncryptedEnvelope.decryptBatch decryptDEKs None
    |> AsyncResult.runSynchronously
    |> Result.orFail
```

## Test

A round-trip and a negative case with Expecto.

```fsharp
open Expecto
open Feather.Cryptography.Cryptography

[<Tests>]
let symmetricTests =
    testList "Symmetric" [
        testCase "round-trips a payload" <| fun _ ->
            let secret = Symmetric.generateSecret ()
            let encrypted = Symmetric.encrypt secret "payload"
            match Symmetric.decrypt secret encrypted with
            | Ok decrypted -> Expect.equal decrypted "payload" "should match original"
            | Error err    -> failtest err

        testCase "rejects a wrong secret" <| fun _ ->
            let encrypted = Symmetric.encrypt (Symmetric.generateSecret ()) "payload"
            match Symmetric.decrypt (Symmetric.generateSecret ()) encrypted with
            | Ok _     -> failtest "expected decryption to fail"
            | Error _  -> ()
    ]
```
