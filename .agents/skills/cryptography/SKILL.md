---
name: cryptography
description: Use whenever generating or reviewing F# code that opens Feather.Cryptography.Encode/Hash/Cryptography or calls Base64.encodeString, Base64.toBase64Url, SHA256.sha256Hex, Crc32.crc32OfString, RSA256.createKeyPair, AES256GCM.encrypt/decrypt, EncryptedEnvelope.encrypt/decrypt, Symmetric.encrypt/decrypt, or Bcrypt.hashPassword/verifyPassword. Trigger also on mentions of envelope encryption, DEK/KEK, AAD, base64url for JWTs, AES-256-GCM, RSA-OAEP, HKDF-derived symmetric secrets, or password hashing in F#.
---

# Cryptography

Library: [FeatherTools/cryptography](https://github.com/FeatherTools/cryptography)
NuGet: `Feather.Cryptography`

## Purpose

F# library of ready-made use-cases for encryption, decryption, hashing, and encoding. It wraps the .NET cryptographic primitives behind small qualified-access modules and single-case discriminated-union types so calling code passes well-typed keys, nonces, tags, and ciphertext instead of bare byte arrays.

## When to Use

- Encoding bytes/strings to Base64 or URL-safe base64url (e.g. for JWTs or query parameters).
- Hashing strings with SHA-256 or computing a CRC-32 checksum.
- Encrypting/decrypting with RSA (OAEP-SHA256), AES-256-GCM, envelope encryption (DEK wrapped by an external KEK service), or a single-secret symmetric helper.
- Hashing and verifying passwords with bcrypt.

## When NOT to Use

- As a general-purpose crypto framework: only the use-cases below are exposed.
- For integrity-only checks where a non-cryptographic checksum is wanted security-wise — `Crc32` is a checksum, not a secure hash.
- For key/secret storage or rotation: the library encrypts but does not persist or manage key material.

## Main Concepts

- `Encode` — UTF-8 string/byte conversion and Base64 (`Base64` submodule, including base64url helpers).
- `Hash` — `SHA256` (cryptographic hash, lowercase hex) and `Crc32` (checksum over ASCII bytes).
- `Cryptography` — the encryption module hosting the types and algorithm submodules below.
- `RSA256` — asymmetric RSA-2048 key-pair generation and OAEP-SHA256 encrypt/decrypt.
- `AES256GCM` — authenticated symmetric encryption producing `IV`, ciphertext, and `Tag`.
- `EncryptedEnvelope` — record bundling a payload encrypted by a per-message `DEK`, where the `DEK` itself is wrapped by a caller-supplied function (external KEK/vault).
- `Symmetric` — single-secret encrypt/decrypt where any string secret is run through HKDF-SHA256.
- `Bcrypt` — password hashing and verification.
- `Secret` — random base64url/byte secret generation.
- Wrapper types: `PrivateKey`, `PublicKey`, `EncryptedData`, `KEK`, `DEK`, `IV`, `Tag`, `AAD`, `Version`, `Algorithm`.

## Related Libraries

- `Feather.ErrorHandling` — supplies `AsyncResult`, the `asyncResult` computation expression, and `Result.orFail`; envelope APIs return `AsyncResult<_, string>`.
- `BCrypt.Net-Core` — backs the `Bcrypt` module.

## Keywords for Search

cryptography, encryption, decryption, hashing, F#, fsharp, Feather.Cryptography, Base64, base64url, JWT, SHA256, sha256Hex, CRC32, crc32OfString, RSA, RSA256, OAEP, AES, AES256GCM, AES-256-GCM, GCM, nonce, IV, Tag, AAD, DEK, KEK, envelope encryption, EncryptedEnvelope, Symmetric, HKDF, secret, generateSecret, Bcrypt, password hashing, AsyncResult

## Reference Files

For composition principles and recommended API usage, read `references/preferred-patterns.md`. For known pitfalls and incorrect assumptions, read `references/anti-patterns.md`. For worked code examples, read `references/examples.md`.
