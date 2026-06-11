namespace Feather.Cryptography

module Cryptography =
    open System
    open System.Security.Cryptography
    open Feather.ErrorHandling

    type PrivateKey = PrivateKey of byte[]
    type PublicKey = PublicKey of byte[]

    /// Encrypted data wrapper
    type EncryptedData = EncryptedData of byte[]

    /// Key Encryption Key
    type KEK = KEK of byte[]

    /// Data Encryption Key
    type DEK = DEK of byte[]

    /// Initialization Vector
    type IV = IV of byte[]

    /// Authentication Tag
    type Tag = Tag of byte[]

    /// Additional Authenticated Data
    type AAD = AAD of byte[]

    /// Version of the encryption scheme
    type Version = Version of int

    /// Algorithm used for encryption
    type Algorithm = Algorithm of string

    [<RequireQualifiedAccess>]
    module Secret =
        let generateBase64Url (length: int): string =
            let bytes = Array.zeroCreate length
            RandomNumberGenerator.Fill(Span<byte>(bytes))
            let result = bytes |> Encode.Base64.encode |> Encode.Base64.toBase64Url
            Array.Clear(bytes, 0, bytes.Length)
            result

        let generateBytes length =
            generateBase64Url length
            |> Encode.Base64.fromBase64Url
            |> Encode.Base64.decode

    [<RequireQualifiedAccess>]
    module RSA256 =
        let createKeyPair () =
            use rsa = RSA.Create(2048)
            let privateKey = rsa.ExportRSAPrivateKey()
            let publicKey = rsa.ExportRSAPublicKey()
            PrivateKey privateKey, PublicKey publicKey

        let encrypt (PublicKey publicKey) (data: byte[]): EncryptedData =
            use rsa = RSA.Create()
            rsa.ImportRSAPublicKey(publicKey, ref Unchecked.defaultof<int>)
            let encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256)
            EncryptedData encrypted

        let decrypt (PrivateKey privateKey) (EncryptedData data): byte[] =
            use rsa = RSA.Create()
            rsa.ImportRSAPrivateKey(privateKey, ref Unchecked.defaultof<int>)
            rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256)

    [<RequireQualifiedAccess>]
    module AES256GCM =
        let private nonceSize = 12 // 96 bits recommended for GCM
        let private tagSize = 16 // 128 bits
        let private keySize = 32 // 256 bits

        let generateKey () : DEK =
            let key = Array.zeroCreate keySize
            use rng = RandomNumberGenerator.Create()
            rng.GetBytes(key)
            DEK key

        let encrypt (DEK key) (aad: AAD option) (plaintext: byte[]): IV * byte[] * Tag =
            let nonce = Array.zeroCreate nonceSize
            use rng = RandomNumberGenerator.Create()
            rng.GetBytes(nonce)

            let ciphertext = Array.zeroCreate plaintext.Length
            let tag = Array.zeroCreate tagSize

            use aesGcm = new AesGcm(key, tagSize)
            match aad with
            | Some (AAD aadBytes) -> aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aadBytes)
            | None -> aesGcm.Encrypt(nonce, plaintext, ciphertext, tag)

            IV nonce, ciphertext, Tag tag

        let decrypt (DEK key) (IV nonce) (ciphertext: byte[]) (Tag tag) (aad: AAD option): byte[] =
            let plaintext = Array.zeroCreate ciphertext.Length

            use aesGcm = new AesGcm(key, tagSize)
            match aad with
            | Some (AAD aadBytes) -> aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, aadBytes)
            | None -> aesGcm.Decrypt(nonce, ciphertext, tag, plaintext)

            plaintext

    type EncryptedEnvelope = {
        Version: Version
        Algorithm: Algorithm
        Iv: IV
        Ciphertext: EncryptedData
        Tag: Tag
        DEK: EncryptedData
    }

    [<RequireQualifiedAccess>]
    module EncryptedEnvelope =
        /// Encrypt data using envelope encryption: generates a DEK, encrypts data with it (AES-GCM),
        /// then encrypts the DEK with the provided encryptDEK function (e.g., vault, HSM)
        let encrypt (encryptDEK: DEK -> AsyncResult<EncryptedData, string>) (aad: AAD option) (data: byte[]): AsyncResult<EncryptedEnvelope, string> = asyncResult {
            // Generate a random DEK for this encryption
            let DEK dekBytes as dek = AES256GCM.generateKey()

            // Encrypt the data with the DEK using AES-GCM
            let iv, ciphertext, tag = AES256GCM.encrypt dek aad data

            // Encrypt the DEK with the provided function (vault, etc.)
            let! encryptedDEK = encryptDEK dek

            // Clear the DEK from memory
            Array.Clear(dekBytes, 0, dekBytes.Length)

            return {
                Version = Version 1
                Algorithm = Algorithm "AES-256-GCM"
                Iv = iv
                Ciphertext = EncryptedData ciphertext
                Tag = tag
                DEK = encryptedDEK
            }
        }

        let encryptBatch (encryptDEKs: DEK list -> AsyncResult<EncryptedData list, string>) (aad: AAD option) (data: byte[] list): AsyncResult<EncryptedEnvelope list, string> = asyncResult {
            // Generate a random DEK for each piece of data
            let deks = List.init data.Length (fun _ -> AES256GCM.generateKey())

            // Encrypt each piece of data with its corresponding DEK
            let encryptedDataList = List.map2 (fun dek data -> AES256GCM.encrypt dek aad data) deks data

            // Encrypt all DEKs in a batch
            let! encryptedDEKs = encryptDEKs deks

            // Clear all DEKs from memory
            deks |> List.iter (fun (DEK dekBytes) -> Array.Clear(dekBytes, 0, dekBytes.Length))

            // Combine the encrypted data and DEKs into envelopes
            let envelopes =
                List.map2 (fun (IV iv, ciphertext, Tag tag) (EncryptedData encryptedDEK) ->
                    {
                        Version = Version 1
                        Algorithm = Algorithm "AES-256-GCM"
                        Iv = IV iv
                        Ciphertext = EncryptedData ciphertext
                        Tag = Tag tag
                        DEK = EncryptedData encryptedDEK
                    }
                ) encryptedDataList encryptedDEKs

            return envelopes
        }

        /// Decrypt envelope-encrypted data: decrypts the DEK with private key,
        /// then uses the DEK to decrypt the actual data
        let decrypt (decryptDEK: EncryptedData -> AsyncResult<DEK, string>) (aad: AAD option) (envelope: EncryptedEnvelope): AsyncResult<byte[], string> = asyncResult {
            try
                // Decrypt the DEK using the private key
                let! (DEK dekBytes as dek) = decryptDEK envelope.DEK

                // Decrypt the data using the DEK
                let (EncryptedData ciphertext) = envelope.Ciphertext
                let plaintext = AES256GCM.decrypt dek envelope.Iv ciphertext envelope.Tag aad

                // Clear the DEK from memory
                Array.Clear(dekBytes, 0, dekBytes.Length)

                return plaintext
            with
            | :? CryptographicException ->
                return! Error "Envelope authentication failed"
        }

        let decryptBatch (decryptDEKs: EncryptedData list -> AsyncResult<DEK list, string>) (aad: AAD option) (envelopes: EncryptedEnvelope list): AsyncResult<byte[] list, string> = asyncResult {
            try
                // Decrypt all DEKs in a batch
                let! deks = envelopes |> List.map _.DEK |> decryptDEKs

                // Decrypt each piece of data with its corresponding DEK
                let plaintexts =
                    List.map2 (fun dek envelope ->
                        let (EncryptedData ciphertext) = envelope.Ciphertext
                        AES256GCM.decrypt dek envelope.Iv ciphertext envelope.Tag aad
                    ) deks envelopes

                // Clear all DEKs from memory
                deks |> List.iter (fun (DEK dekBytes) -> Array.Clear(dekBytes, 0, dekBytes.Length))

                return plaintexts
            with
            | :? CryptographicException ->
                return! Error "Envelope authentication failed"
        }

    [<RequireQualifiedAccess>]
    module Symmetric =
        let private keySize = 32  // 256 bits
        let private nonceSize = 12 // 96 bits
        let private tagSize = 16  // 128 bits

        /// Generate a random secret suitable for use with encrypt/decrypt.
        /// Returns a base64url-encoded 32-byte key.
        let generateSecret () : string =
            let key = Array.zeroCreate keySize
            RandomNumberGenerator.Fill(Span<byte>(key))
            let result = key |> Encode.Base64.encode |> Encode.Base64.toBase64Url
            Array.Clear(key, 0, key.Length)
            result

        /// Derive a 32-byte AES key from an arbitrary secret string using HKDF-SHA256.
        /// This means any string — including secrets from AWS Secrets Manager or CDK — works.
        let private deriveKey (secret: string) : byte[] =
            let ikm = Encode.stringToBytes secret
            HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, keySize, [||], [||])

        /// Encrypt plaintext string with the given secret using AES-256-GCM.
        /// Returns a base64url-encoded string (nonce ++ ciphertext ++ tag).
        let encrypt (secret: string) (plaintext: string) : string =
            let key = deriveKey secret
            try
                let nonce = Array.zeroCreate nonceSize
                RandomNumberGenerator.Fill(Span<byte>(nonce))
                let plaintextBytes = Encode.stringToBytes plaintext
                let ciphertext = Array.zeroCreate plaintextBytes.Length
                let tag = Array.zeroCreate tagSize
                use aesGcm = new AesGcm(key, tagSize)
                aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag)
                Array.concat [ nonce; ciphertext; tag ]
                |> Encode.Base64.encode
                |> Encode.Base64.toBase64Url
            finally
                Array.Clear(key, 0, key.Length)

        /// Decrypt a base64url-encoded ciphertext (produced by encrypt) with the given secret.
        let decrypt (secret: string) (encoded: string) : Result<string, string> =
            try
                let bytes = encoded |> Encode.Base64.fromBase64Url |> Encode.Base64.decode
                if bytes.Length < nonceSize + tagSize then
                    Error "Invalid ciphertext: too short"
                else
                    let nonce = bytes[0 .. nonceSize - 1]
                    let ciphertextLen = bytes.Length - nonceSize - tagSize
                    let ciphertext = bytes[nonceSize .. nonceSize + ciphertextLen - 1]
                    let tag = bytes[nonceSize + ciphertextLen ..]
                    let key = deriveKey secret
                    let plaintext = Array.zeroCreate ciphertextLen
                    try
                        use aesGcm = new AesGcm(key, tagSize)
                        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext)
                        Ok (Encode.bytesToString plaintext)
                    finally
                        Array.Clear(key, 0, key.Length)
                        Array.Clear(plaintext, 0, plaintext.Length)
            with
            | :? CryptographicException -> Error "Decryption failed: wrong secret or corrupted data"
            | :? FormatException -> Error "Decryption failed: invalid encoded format"

    [<RequireQualifiedAccess>]
    module Bcrypt =
        open BCrypt.Net

        let hashPassword (password: string): string =
            BCrypt.HashPassword(password)

        let verifyPassword (password: string) (hashed: string): bool =
            BCrypt.Verify(password, hashed)
