# Examples

All example code for this skill lives here. Examples are ordered by increasing complexity and each is self-contained. Neutral placeholder names are used throughout.

## Basic — encoding and hashing

```fsharp
open Feather.Cryptography.Encode
open Feather.Cryptography.Hash

let bytes = stringToBytes "hello world"              // UTF-8
let text = bytesToString bytes                         // "hello world"

let base64 = Base64.encodeString "hello world??>"     // "aGVsbG8gd29ybGQ/Pz4="
let base64Url = base64 |> Base64.toBase64Url           // "aGVsbG8gd29ybGQ_Pz4"
let roundTrip = base64Url |> Base64.fromBase64Url |> Base64.decodeString

let digest = SHA256.sha256Hex "hello world"
// "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

let digestBytes = SHA256.sha256 bytes                  // 32 bytes

let checksum = Crc32.crc32OfString "hello world"       // "d4a1185" (no zero padding)
let checksumFixed = Crc32.crc32 bytes |> sprintf "%08x" // "0d4a1185"
```

## Symmetric encryption with a secret

`Symmetric` takes any secret string; generate one once and keep it in a secrets manager.

```fsharp
open Feather.Cryptography.Cryptography

let secret = Symmetric.generateSecret ()   // 43-char base64url string

let token = Symmetric.encrypt secret "user-42|2026-01-01"
// base64url of nonce ++ ciphertext ++ tag; different on every call

match Symmetric.decrypt secret token with
| Ok plaintext -> printfn "decrypted: %s" plaintext
| Error message -> printfn "rejected: %s" message

// Wrong secret or tampered token -> Error "Decryption failed: wrong secret or corrupted data"
let rejected = Symmetric.decrypt (Symmetric.generateSecret ()) token
```

## Password hashing

```fsharp
open Feather.Cryptography.Cryptography

let stored = Bcrypt.hashPassword "correct horse"   // "$2b$10$..."; salted, differs per call

let isValid = Bcrypt.verifyPassword "correct horse" stored   // true
let isInvalid = Bcrypt.verifyPassword "wrong" stored         // false
```

## AES-256-GCM with AAD

Low-level primitive: persist `iv`, `ciphertext` and `tag`; supply the same AAD to decrypt. Failures throw.

```fsharp
open System.Security.Cryptography
open Feather.Cryptography.Encode
open Feather.Cryptography.Cryptography

let dek = AES256GCM.generateKey ()
let aad = AAD (stringToBytes "record-1")

let iv, ciphertext, tag = AES256GCM.encrypt dek (Some aad) (stringToBytes "payload")

let tryDecrypt aad =
    try AES256GCM.decrypt dek iv ciphertext tag aad |> bytesToString |> Ok
    with :? CryptographicException -> Error "authentication failed"

let decrypted = tryDecrypt (Some aad)                                    // Ok "payload"
let wrongAad = tryDecrypt (Some (AAD (stringToBytes "record-2"))) // Error
let missingAad = tryDecrypt None                                  // Error
```

## Envelope encryption with an RSA master key

The data is encrypted with a fresh DEK; the DEK is wrapped by `encryptDEK`. Here the KEK is an RSA key pair.

```fsharp
open Feather.ErrorHandling
open Feather.Cryptography.Encode
open Feather.Cryptography.Cryptography

let privateKey, publicKey = RSA256.createKeyPair ()

let encryptDEK (DEK dek) = asyncResult {
    return RSA256.encrypt publicKey dek
}

let decryptDEK encryptedDek = asyncResult {
    return DEK (RSA256.decrypt privateKey encryptedDek)
}

let aadFor (recordId: string) = Some (AAD (stringToBytes recordId))

let roundTrip: AsyncResult<string, string> = asyncResult {
    let! envelope =
        stringToBytes "Top secret data"
        |> EncryptedEnvelope.encrypt encryptDEK (aadFor "record-1")

    let! plaintext = envelope |> EncryptedEnvelope.decrypt decryptDEK (aadFor "record-1")
    return bytesToString plaintext
}

roundTrip |> Async.RunSynchronously   // Ok "Top secret data"
```

With a different AAD (or `None`), `decrypt` returns `Error "Envelope authentication failed"`.

## Batch envelope encryption

One call to the key service for many items. The batch DEK functions must return one output per input, in order.

```fsharp
open Feather.ErrorHandling
open Feather.Cryptography.Encode
open Feather.Cryptography.Cryptography

let privateKey, publicKey = RSA256.createKeyPair ()

let encryptDEKs (deks: DEK list) =
    deks
    |> List.map (fun (DEK dek) -> RSA256.encrypt publicKey dek)
    |> AsyncResult.ofSuccess

let decryptDEKs (encryptedDeks: EncryptedData list) =
    encryptedDeks
    |> List.map (RSA256.decrypt privateKey >> DEK)
    |> AsyncResult.ofSuccess

let roundTrip: AsyncResult<string list, string> = asyncResult {
    let! envelopes =
        [ "Data 1"; "Data 2"; "Data 3" ]
        |> List.map stringToBytes
        |> EncryptedEnvelope.encryptBatch encryptDEKs None

    let! plaintexts = envelopes |> EncryptedEnvelope.decryptBatch decryptDEKs None
    return plaintexts |> List.map bytesToString
}

roundTrip |> Async.RunSynchronously   // Ok [ "Data 1"; "Data 2"; "Data 3" ]
```

## Persisting an envelope

`EncryptedEnvelope` holds byte arrays; map it to a string DTO for JSON or a database row. The AAD is not part of the envelope.

```fsharp
open Feather.Cryptography.Encode
open Feather.Cryptography.Cryptography

type EnvelopeDto = {
    Version: int
    Algorithm: string
    Iv: string
    Ciphertext: string
    Tag: string
    Dek: string
}

[<RequireQualifiedAccess>]
module EnvelopeDto =
    let fromEnvelope (envelope: EncryptedEnvelope): EnvelopeDto =
        let (Version version) = envelope.Version
        let (Algorithm algorithm) = envelope.Algorithm
        let (IV iv) = envelope.Iv
        let (EncryptedData ciphertext) = envelope.Ciphertext
        let (Tag tag) = envelope.Tag
        let (EncryptedData dek) = envelope.DEK

        {
            Version = version
            Algorithm = algorithm
            Iv = Base64.encode iv
            Ciphertext = Base64.encode ciphertext
            Tag = Base64.encode tag
            Dek = Base64.encode dek
        }

    let toEnvelope (dto: EnvelopeDto): Result<EncryptedEnvelope, string> =
        try
            Ok {
                Version = Version dto.Version
                Algorithm = Algorithm dto.Algorithm
                Iv = IV (Base64.decode dto.Iv)
                Ciphertext = EncryptedData (Base64.decode dto.Ciphertext)
                Tag = Tag (Base64.decode dto.Tag)
                DEK = EncryptedData (Base64.decode dto.Dek)
            }
        with :? System.FormatException as e -> Error e.Message
```

## Integration — DEK wrapping via an external key service

Any KMS / Key Vault / HSM client replaces `RSA256` as the KEK. `IKeyService` stands in for the SDK client; Task calls are lifted with `AsyncResult.ofTaskCatch`, so a faulted Task becomes an `Error`.

```fsharp
open System.Threading.Tasks
open Feather.ErrorHandling
open Feather.Cryptography.Encode
open Feather.Cryptography.Cryptography

type IKeyService =
    abstract WrapKey: keyId: string * key: byte[] -> Task<byte[]>
    abstract UnwrapKey: keyId: string * wrapped: byte[] -> Task<byte[]>

[<RequireQualifiedAccess>]
type VaultError =
    | Encryption of string
    | Decryption of string

let encryptDEKWith (keyService: IKeyService) keyId (DEK dek) =
    keyService.WrapKey(keyId, dek)
    |> AsyncResult.ofTaskCatch (fun e -> $"Key wrap failed: {e.Message}")
    |> AsyncResult.map EncryptedData

let decryptDEKWith (keyService: IKeyService) keyId (EncryptedData wrapped) =
    keyService.UnwrapKey(keyId, wrapped)
    |> AsyncResult.ofTaskCatch (fun e -> $"Key unwrap failed: {e.Message}")
    |> AsyncResult.map DEK

let encryptDocument keyService keyId (documentId: string) (content: byte[]) =
    content
    |> EncryptedEnvelope.encrypt
        (encryptDEKWith keyService keyId)
        (Some (AAD (stringToBytes documentId)))
    |> AsyncResult.mapError VaultError.Encryption

let decryptDocument keyService keyId (documentId: string) (envelope: EncryptedEnvelope) =
    envelope
    |> EncryptedEnvelope.decrypt
        (decryptDEKWith keyService keyId)
        (Some (AAD (stringToBytes documentId)))
    |> AsyncResult.mapError VaultError.Decryption
```

## Test — envelope round-trip and tamper detection

Mirrors the library's Expecto tests.

```fsharp
module Feature.CryptographyTests

open Expecto
open Feather.ErrorHandling
open Feather.Cryptography.Cryptography

let privateKey, publicKey = RSA256.createKeyPair ()

let encryptDEK (DEK dek) = asyncResult { return RSA256.encrypt publicKey dek }
let decryptDEK encryptedDek = asyncResult { return DEK (RSA256.decrypt privateKey encryptedDek) }

let run xR = xR |> Async.RunSynchronously

[<Tests>]
let envelopeTests =
    testList "EncryptedEnvelope" [
        testCase "should decrypt to the original data when AAD matches" <| fun _ ->
            let aad = Some (AAD "record-1"B)

            let result =
                "payload"B
                |> EncryptedEnvelope.encrypt encryptDEK aad
                |> AsyncResult.bind (EncryptedEnvelope.decrypt decryptDEK aad)
                |> run

            Expect.equal result (Ok "payload"B) "Decrypted data should match original"

        testCase "should fail authentication when the ciphertext is tampered" <| fun _ ->
            let envelope = EncryptedEnvelope.encrypt encryptDEK None "payload"B |> run

            let result =
                envelope
                |> Result.map (fun envelope ->
                    let (EncryptedData ciphertext) = envelope.Ciphertext
                    let tampered = Array.copy ciphertext
                    tampered[0] <- tampered[0] ^^^ 1uy
                    { envelope with Ciphertext = EncryptedData tampered })
                |> Result.map (EncryptedEnvelope.decrypt decryptDEK None >> run)

            Expect.equal result (Ok (Error "Envelope authentication failed")) "Tampered envelope should be rejected"

        testCase "should reject a Symmetric token decrypted with another secret" <| fun _ ->
            let token = Symmetric.encrypt (Symmetric.generateSecret ()) "data"

            Expect.isError (Symmetric.decrypt (Symmetric.generateSecret ()) token) "Wrong secret should fail"
    ]
```
