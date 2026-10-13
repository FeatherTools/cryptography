---
name: feather-cryptography
description: Use whenever generating or reviewing F# code that encrypts, decrypts, hashes or encodes data with the Feather.Cryptography library — secret-string encryption via `Symmetric.generateSecret` / `Symmetric.encrypt` / `Symmetric.decrypt`, envelope encryption via `EncryptedEnvelope.encrypt` / `decrypt` / `encryptBatch` / `decryptBatch` with a caller-supplied DEK wrapper (RSA, KMS, vault, HSM), low-level `AES256GCM.generateKey` / `encrypt` / `decrypt`, `RSA256.createKeyPair` / `encrypt` / `decrypt`, password hashing via `Bcrypt.hashPassword` / `verifyPassword`, random secrets via `Secret.generateBase64Url` / `generateBytes`, hashing via `SHA256.sha256` / `sha256Hex` / `Crc32.crc32OfString`, or encoding via `Encode.stringToBytes` / `Base64.encodeString` / `toBase64Url` / `fromBase64Url`. Trigger also on mentions of `DEK`, `KEK`, `IV`, `Tag`, `AAD`, `EncryptedData`, `PrivateKey`, `PublicKey`, `EncryptedEnvelope`, AES-256-GCM, RSA-OAEP, HKDF, base64url, or "Envelope authentication failed".
---

# Feather-Cryptography

Library: [FeatherTools/cryptography](https://github.com/FeatherTools/cryptography)
NuGet: `Feather.Cryptography`

## Purpose

`Feather.Cryptography` is a small F# library of predefined cryptographic use-cases over .NET `System.Security.Cryptography` and BCrypt.Net: UTF-8 / Base64 / base64url encoding, SHA-256 and CRC32 hashing, RSA-2048 OAEP-SHA256 key wrapping, AES-256-GCM authenticated encryption, secret-string encryption (HKDF-derived AES key, base64url output), envelope encryption with a pluggable key-encryption step, and bcrypt password hashing. Byte arrays are wrapped in single-case unions (`DEK`, `IV`, `Tag`, `AAD`, `EncryptedData`, …) so keys, nonces and ciphertexts cannot be mixed up.

## When to Use

- Encrypting a string (token, config value, cookie payload) with one shared secret, e.g. from a secrets manager — `Symmetric`.
- Encrypting data at rest with a per-record data key wrapped by a master key held in RSA, a cloud KMS, a vault or an HSM — `EncryptedEnvelope`.
- Binding ciphertext to context (record id, tenant id) via additional authenticated data — `AAD`.
- Hashing and verifying user passwords — `Bcrypt`.
- Generating random secrets/tokens, SHA-256 hex digests, CRC32 checksums, or base64url strings for URLs and JWT segments.

## When NOT to Use

- Signing or verifying signatures, JWT creation/validation, certificates, TLS — not provided.
- Encrypting large payloads directly with `RSA256.encrypt` — RSA-2048 OAEP-SHA256 accepts at most 190 bytes; use it only to wrap keys.
- CRC32 or plain SHA-256 for passwords or integrity against an attacker — use `Bcrypt` for passwords and AES-GCM tags for tamper detection.
- Streaming or multi-gigabyte data — every API works on whole in-memory `byte[]` / `string`.
- You need to choose key sizes, iteration counts, bcrypt work factor or RSA padding — these are fixed.

## Main Concepts

- **Encode** — `stringToBytes` / `bytesToString` (UTF-8); `Encode.Base64` (`[<RequireQualifiedAccess>]`): `encode` / `decode`, `encodeString` / `decodeString`, `toBase64Url` / `fromBase64Url` (RFC 4648 URL-safe alphabet, no padding).
- **Hash.SHA256** — `sha256 : byte[] -> byte[]`, `sha256Hex : string -> string` (UTF-8 input, lower-case hex).
- **Hash.Crc32** — `crc32 : byte[] -> uint32`, `crc32OfAscii : string -> uint32`, `crc32OfString : string -> string` (ASCII input, lower-case hex without zero padding), `crc32byte` (single-step update).
- **Byte wrappers** (in `Feather.Cryptography.Cryptography`) — `PrivateKey`, `PublicKey`, `EncryptedData`, `KEK`, `DEK`, `IV`, `Tag`, `AAD`, all `of byte[]`; plus `Version of int` and `Algorithm of string`. No companion modules: construct and deconstruct with the case name.
- **Secret** — `generateBase64Url length` (CSPRNG bytes → base64url string; `length` is the byte count) and `generateBytes length`.
- **RSA256** — `createKeyPair ()` returns `PrivateKey * PublicKey` (2048-bit, PKCS#1 DER); `encrypt : PublicKey -> byte[] -> EncryptedData`; `decrypt : PrivateKey -> EncryptedData -> byte[]`. OAEP-SHA256 padding. Throws on failure.
- **AES256GCM** — `generateKey () : DEK` (32 bytes); `encrypt : DEK -> AAD option -> byte[] -> IV * byte[] * Tag` (random 12-byte IV, 16-byte tag); `decrypt : DEK -> IV -> byte[] -> Tag -> AAD option -> byte[]`. Throws `CryptographicException` on tag/AAD/key mismatch.
- **EncryptedEnvelope** — record `{ Version; Algorithm; Iv; Ciphertext; Tag; DEK }` (DEK holds the *wrapped* key as `EncryptedData`; AAD is not stored). Module functions take the DEK wrap/unwrap step as an `AsyncResult<_, string>` function and return `AsyncResult<_, string>`.
- **Symmetric** — `generateSecret () : string` (32 random bytes, base64url); `encrypt : secret:string -> plaintext:string -> string` (base64url of nonce ‖ ciphertext ‖ tag); `decrypt : secret:string -> encoded:string -> Result<string, string>`. Any string works as secret (HKDF-SHA256 key derivation, no salt).
- **Bcrypt** — `hashPassword : string -> string` (`$2b$10$…`), `verifyPassword : password:string -> hashed:string -> bool`.

## Related Libraries

- **Feather.ErrorHandling** — supplies `AsyncResult<_, _>`, the `asyncResult {}` CE used to write `encryptDEK` / `decryptDEK`, and helpers such as `AsyncResult.ofTaskCatch`, `AsyncResult.mapError`, `Result.orFail`.
- **BCrypt.Net-Core** — backs `Bcrypt`.

## Keywords for Search

Feather.Cryptography, FeatherTools cryptography, encryption, decryption, hashing, encoding, Encode, stringToBytes, bytesToString, Base64, encodeString, decodeString, toBase64Url, fromBase64Url, base64url, Hash, SHA256, sha256, sha256Hex, Crc32, crc32, crc32OfString, crc32OfAscii, Secret, generateBase64Url, generateBytes, RSA256, createKeyPair, PrivateKey, PublicKey, RSA-OAEP, OaepSHA256, AES256GCM, AES-256-GCM, generateKey, IV, nonce, Tag, AAD, additional authenticated data, DEK, KEK, EncryptedData, EncryptedEnvelope, envelope encryption, encryptBatch, decryptBatch, key wrapping, KMS, vault, HSM, Symmetric, generateSecret, HKDF, Bcrypt, hashPassword, verifyPassword, password hashing, asyncResult, AsyncResult, F#

## Reference Files

- For choosing between `Symmetric`, `EncryptedEnvelope` and the low-level primitives, error handling, AAD, key-material lifetime and testing, read `references/preferred-patterns.md`.
- For known pitfalls, README inaccuracies and incorrect assumptions, read `references/anti-patterns.md`.
- For worked, self-contained code examples ordered by increasing complexity, read `references/examples.md`.
