module Feather.Cryptography.Cryptography.Test

open Expecto
open Feather.Cryptography.Encode
open Feather.Cryptography.Cryptography
open Feather.ErrorHandling

let okOrFail = function
    | Ok v -> v
    | Error err -> failwith err

let runOkOrFail xR =
    xR
    |> Async.RunSynchronously
    |> okOrFail

[<Tests>]
let cryptographyTests =
    testList "Cryptography" [
        testList "RSA256" [
            testCase "should create key pair" <| fun _ ->
                let privateKey, publicKey = RSA256.createKeyPair()

                match privateKey, publicKey with
                | PrivateKey pk, PublicKey pubk ->
                    Expect.isGreaterThan pk.Length 0 "Private key should not be empty"
                    Expect.isGreaterThan pubk.Length 0 "Public key should not be empty"

            testCase "should encrypt and decrypt data" <| fun _ ->
                let privateKey, publicKey = RSA256.createKeyPair()
                let plaintext = "Hello, RSA!"B

                let encrypted = RSA256.encrypt publicKey plaintext
                let decrypted = RSA256.decrypt privateKey encrypted

                Expect.equal decrypted plaintext "Decrypted data should match original"

            testCase "encrypted data should differ from plaintext" <| fun _ ->
                let _, publicKey = RSA256.createKeyPair()
                let plaintext = "Secret message"B

                let (EncryptedData encrypted) = RSA256.encrypt publicKey plaintext

                Expect.notEqual encrypted plaintext "Encrypted data should differ from plaintext"
        ]

        testList "AES256GCM" [
            testCase "should generate DEK" <| fun _ ->
                let (DEK dek) = AES256GCM.generateKey()

                Expect.equal dek.Length 32 "DEK should be 32 bytes (256 bits)"

            testCase "should encrypt and decrypt without AAD" <| fun _ ->
                let dek = AES256GCM.generateKey()
                let plaintext = "Hello, AES-GCM!"B

                let iv, ciphertext, tag = AES256GCM.encrypt dek None plaintext
                let decrypted = AES256GCM.decrypt dek iv ciphertext tag None

                Expect.equal decrypted plaintext "Decrypted data should match original"

            testCase "should encrypt and decrypt with AAD" <| fun _ ->
                let dek = AES256GCM.generateKey()
                let plaintext = "Sensitive data"B
                let aad = AAD "metadata"B

                let iv, ciphertext, tag = AES256GCM.encrypt dek (Some aad) plaintext
                let decrypted = AES256GCM.decrypt dek iv ciphertext tag (Some aad)

                Expect.equal decrypted plaintext "Decrypted data should match original"

            testCase "should fail decryption with wrong AAD" <| fun _ ->
                let dek = AES256GCM.generateKey()
                let plaintext = "Sensitive data"B
                let aad = AAD "metadata"B
                let wrongAad = AAD "wrong"B

                let iv, ciphertext, tag = AES256GCM.encrypt dek (Some aad) plaintext

                Expect.throws
                    (fun () -> AES256GCM.decrypt dek iv ciphertext tag (Some wrongAad) |> ignore)
                    "Should fail with wrong AAD"

            testCase "encrypted ciphertext should differ from plaintext" <| fun _ ->
                let dek = AES256GCM.generateKey()
                let plaintext = "Secret message"B

                let _, ciphertext, _ = AES256GCM.encrypt dek None plaintext

                Expect.notEqual ciphertext plaintext "Ciphertext should differ from plaintext"

            testCase "should generate different IVs for each encryption" <| fun _ ->
                let dek = AES256GCM.generateKey()
                let plaintext = "Same message"B

                let (IV iv1), _, _ = AES256GCM.encrypt dek None plaintext
                let (IV iv2), _, _ = AES256GCM.encrypt dek None plaintext

                Expect.notEqual iv1 iv2 "IVs should be different for each encryption"
        ]

        testList "EncryptedEnvelope" [
            testCase "should encrypt and decrypt data" <| fun _ ->
                let privateKey, publicKey = RSA256.createKeyPair()
                let plaintext = "Top secret data"B

                let encryptDEK (DEK dek) = asyncResult {
                    return RSA256.encrypt publicKey dek
                }

                let decryptDEK (encryptedDek) = asyncResult {
                    let dekBytes = RSA256.decrypt privateKey encryptedDek
                    return DEK dekBytes
                }

                let aad = None

                let envelope =
                    plaintext
                    |> EncryptedEnvelope.encrypt encryptDEK aad
                    |> runOkOrFail

                let decrypted =
                    envelope
                    |> EncryptedEnvelope.decrypt decryptDEK aad
                    |> runOkOrFail

                Expect.equal decrypted plaintext "Decrypted data should match original"

            testCase "should encrypt and decrypt with AAD" <| fun _ ->
                let privateKey, publicKey = RSA256.createKeyPair()
                let plaintext = "Top secret data"B
                let aad = AAD "document-id-123"B |> Some

                let encryptDEK (DEK dek) = asyncResult {
                    return RSA256.encrypt publicKey dek
                }

                let decryptDEK (encryptedDek) = asyncResult {
                    let dekBytes = RSA256.decrypt privateKey encryptedDek
                    return DEK dekBytes
                }

                let envelope =
                    plaintext
                    |> EncryptedEnvelope.encrypt encryptDEK aad
                    |> runOkOrFail

                let decrypted =
                    envelope
                    |> EncryptedEnvelope.decrypt decryptDEK aad
                    |> runOkOrFail

                Expect.equal decrypted plaintext "Decrypted data should match original"

            testCase "should set version and algorithm" <| fun _ ->
                let _, publicKey = RSA256.createKeyPair()
                let plaintext = "Data"B

                let encryptDEK (DEK dek) = asyncResult {
                    return RSA256.encrypt publicKey dek
                }

                let envelope =
                    EncryptedEnvelope.encrypt encryptDEK None plaintext
                    |> runOkOrFail

                let (Version version) = envelope.Version
                let (Algorithm algorithm) = envelope.Algorithm

                Expect.equal version 1 "Version should be 1"
                Expect.equal algorithm "AES-256-GCM" "Algorithm should be AES-256-GCM"
        ]

        testList "Bcrypt" [
            testCase "should hash and verify password" <| fun _ ->
                let password = "StrongPassword123!"
                let hashed = Bcrypt.hashPassword password

                let isValid = Bcrypt.verifyPassword password hashed
                let isInvalid = Bcrypt.verifyPassword "WrongPassword" hashed

                Expect.isTrue isValid "Password should be valid"
                Expect.isFalse isInvalid "Wrong password should be invalid"
        ]

        testList "Symmetric" [
            testCase "should generate a secret" <| fun _ ->
                let secret = Symmetric.generateSecret()
                Expect.isGreaterThan secret.Length 0 "Secret should not be empty"

            testCase "generated secrets should be unique" <| fun _ ->
                let s1 = Symmetric.generateSecret()
                let s2 = Symmetric.generateSecret()
                Expect.notEqual s1 s2 "Each generated secret should be unique"

            testCase "should encrypt and decrypt with generated secret" <| fun _ ->
                let secret = Symmetric.generateSecret()
                let plaintext = "Hello, symmetric world!"

                let encrypted = Symmetric.encrypt secret plaintext
                let decrypted = Symmetric.decrypt secret encrypted |> okOrFail

                Expect.equal decrypted plaintext "Decrypted text should match original"

            testCase "should encrypt and decrypt with arbitrary secret string" <| fun _ ->
                let secret = "some-aws-generated-secret-value-abc123"
                let plaintext = "Sensitive payload"

                let encrypted = Symmetric.encrypt secret plaintext
                let decrypted = Symmetric.decrypt secret encrypted |> okOrFail

                Expect.equal decrypted plaintext "Decrypted text should match original"

            testCase "encrypted output should differ from plaintext" <| fun _ ->
                let secret = Symmetric.generateSecret()
                let plaintext = "Secret message"

                let encrypted = Symmetric.encrypt secret plaintext

                Expect.notEqual encrypted plaintext "Encrypted output should differ from plaintext"

            testCase "same plaintext should produce different ciphertexts (random nonce)" <| fun _ ->
                let secret = Symmetric.generateSecret()
                let plaintext = "Same message"

                let e1 = Symmetric.encrypt secret plaintext
                let e2 = Symmetric.encrypt secret plaintext

                Expect.notEqual e1 e2 "Each encryption should produce a unique ciphertext"

            testCase "decryption with wrong secret should fail" <| fun _ ->
                let secret = Symmetric.generateSecret()
                let wrongSecret = Symmetric.generateSecret()
                let plaintext = "Sensitive data"

                let encrypted = Symmetric.encrypt secret plaintext
                let result = Symmetric.decrypt wrongSecret encrypted

                Expect.isError result "Decryption with wrong secret should fail"

            testCase "decryption of tampered ciphertext should fail" <| fun _ ->
                let secret = Symmetric.generateSecret()
                let encrypted = Symmetric.encrypt secret "data"
                let tampered = encrypted[0 .. encrypted.Length - 3] + "XX"

                let result = Symmetric.decrypt secret tampered

                Expect.isError result "Decryption of tampered data should fail"
        ]
    ]
