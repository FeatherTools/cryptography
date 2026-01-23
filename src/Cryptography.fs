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

    [<RequireQualifiedAccess>]
    module Bcrypt =
        open BCrypt.Net

        let hashPassword (password: string): string =
            BCrypt.HashPassword(password)

        let verifyPassword (password: string) (hashed: string): bool =
            BCrypt.Verify(password, hashed)
