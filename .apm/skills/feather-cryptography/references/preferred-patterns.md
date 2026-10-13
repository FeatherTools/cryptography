# Preferred Patterns

## Core Principles

- Pick the highest-level API that fits. `Symmetric` for "encrypt a string with a secret", `EncryptedEnvelope` for "encrypt data with a per-record key wrapped by a master key", `Bcrypt` for passwords. Reach for `AES256GCM` / `RSA256` directly only when building a custom scheme.
- Keep byte arrays wrapped. Pass `DEK`, `IV`, `Tag`, `AAD`, `EncryptedData`, `PrivateKey`, `PublicKey` through your code as-is; unwrap with a pattern (`let (EncryptedData bytes) = ...`) only at the storage/transport edge.
- Know which APIs throw and which return `Result`. `Symmetric.decrypt` returns `Result<string, string>`; `EncryptedEnvelope.*` return `AsyncResult<_, string>`; `AES256GCM`, `RSA256`, `Bcrypt.verifyPassword`, `Encode.Base64.decode` throw .NET exceptions. Lift throwing calls into `Result` at the boundary.
- Encryption is randomized. Every `Symmetric.encrypt`, `AES256GCM.encrypt` and `EncryptedEnvelope.encrypt` uses a fresh random nonce (and DEK), so the same plaintext never gives the same output — compare by decrypting, never by re-encrypting.

## Recommended API Usage

- Encoding text for crypto input: `Encode.stringToBytes` / `Encode.bytesToString` (UTF-8). For URL/JWT-safe text, `Base64.encode >> Base64.toBase64Url` and back with `Base64.fromBase64Url >> Base64.decode`. See `examples.md` → "Basic — encoding and hashing".
- Shared-secret string encryption: `Symmetric.generateSecret ()` once (store it in a secrets manager), then `Symmetric.encrypt secret plaintext` / `Symmetric.decrypt secret encoded`. See `examples.md` → "Symmetric encryption with a secret".
- Random tokens/keys: `Secret.generateBase64Url byteCount` for a string, `Secret.generateBytes byteCount` for raw bytes. 32 bytes yields a 43-character base64url string.
- Passwords: store `Bcrypt.hashPassword password`; check with `Bcrypt.verifyPassword password storedHash`. See `examples.md` → "Password hashing".
- Envelope encryption: write `encryptDEK : DEK -> AsyncResult<EncryptedData, string>` and `decryptDEK : EncryptedData -> AsyncResult<DEK, string>` around your key-wrapping service (or `RSA256`), then call `EncryptedEnvelope.encrypt encryptDEK aad data` and `EncryptedEnvelope.decrypt decryptDEK aad envelope`. See `examples.md` → "Envelope encryption with an RSA master key".
- Many records at once with one round-trip to the key service: `EncryptedEnvelope.encryptBatch encryptDEKs aad dataList` / `decryptBatch decryptDEKs aad envelopes`, where the batch functions map a `DEK list` to an `EncryptedData list` (and back) **in the same order and of the same length**. See `examples.md` → "Batch envelope encryption".
- Low-level AES-GCM: `AES256GCM.generateKey ()`, `AES256GCM.encrypt dek aad plaintext` → `iv, ciphertext, tag`; persist all three and pass them to `AES256GCM.decrypt dek iv ciphertext tag aad`. See `examples.md` → "AES-256-GCM with AAD".

## Error Handling

- `Symmetric.decrypt` returns `Error` with one of: `"Invalid ciphertext: too short"`, `"Decryption failed: wrong secret or corrupted data"`, `"Decryption failed: invalid encoded format"`. Treat all as "cannot decrypt"; do not branch on the text.
- `EncryptedEnvelope.decrypt` / `decryptBatch` turn a `CryptographicException` (wrong DEK, wrong AAD, tampered ciphertext/tag/IV, or an RSA unwrap failure inside `decryptDEK`) into `Error "Envelope authentication failed"`. Any other exception (including `ArgumentException` from mismatched batch lengths) propagates — make `decryptDEK` return `Error` instead of throwing.
- An `Error` returned by your `encryptDEK` / `decryptDEK` short-circuits and is returned unchanged, so put useful context in it.
- The error type is `string`. Map it into your own error DU at the boundary with `AsyncResult.mapError` / `Result.mapError`.
- Wrap throwing primitives once: `AES256GCM.decrypt` throws `AuthenticationTagMismatchException` (a `CryptographicException`); `RSA256.encrypt` throws for data over 190 bytes; `Bcrypt.verifyPassword` throws `SaltParseException` for a malformed hash; `Base64.decode` throws `FormatException`.

## Composition

- Write the DEK wrap/unwrap functions with `asyncResult {}`. For Task-based SDK clients, lift with `AsyncResult.ofTaskCatch (fun e -> e.Message)` so a faulted Task becomes an `Error`. See `examples.md` → "Integration — DEK wrapping via an external key service".
- AAD is not stored in the envelope. Derive it from data you already have at decrypt time (record id, tenant id, column name) and pass the same `AAD` to `encrypt` and `decrypt`; `None` on one side and `Some` on the other fails.
- An envelope produced by `encryptBatch` is an ordinary `EncryptedEnvelope`; it can be decrypted with single `decrypt` and vice versa.
- To persist an envelope, map each wrapped `byte[]` to a string with `Base64.encode` (or base64url) in a DTO and keep `Version` / `Algorithm` alongside it. See `examples.md` → "Persisting an envelope".

## Key Material Lifetime

- `EncryptedEnvelope.encrypt` / `encryptBatch` zero the generated DEK bytes after `encryptDEK` returns; `decrypt` / `decryptBatch` zero the DEK bytes returned by `decryptDEK` after use. Therefore `encryptDEK` must return a new array (never `EncryptedData dekBytes` itself), and `decryptDEK` must return a fresh `DEK` per call (never a cached instance).
- `Symmetric.encrypt` / `decrypt` derive the key from the secret on every call and clear it afterwards; there is nothing to cache.
- `AES256GCM` and `RSA256` do not clear anything; clear your own key arrays with `Array.Clear` when done.

## Integration with Other Libraries

- `Feather.ErrorHandling` is required for envelope encryption: open `Feather.ErrorHandling` for `asyncResult {}` and the `AsyncResult` module.
- RSA keys are PKCS#1 DER bytes (`ExportRSAPrivateKey` / `ExportRSAPublicKey`). To use keys from elsewhere, export them in that format and wrap with `PrivateKey` / `PublicKey`.
- A cloud KMS / Key Vault / HSM replaces `RSA256` as the KEK: only `encryptDEK` / `decryptDEK` change; the envelope format stays the same.

## Naming Conventions

- Open the module, not the namespace: `open Feather.Cryptography.Cryptography` (RSA, AES, envelope, `Symmetric`, `Secret`, `Bcrypt`, wrapper types), `open Feather.Cryptography.Encode`, `open Feather.Cryptography.Hash`.
- `Secret`, `RSA256`, `AES256GCM`, `EncryptedEnvelope`, `Symmetric`, `Bcrypt` and `Encode.Base64` are `[<RequireQualifiedAccess>]`; always qualify them. `Hash.SHA256` and `Hash.Crc32` are not.
- After `open Feather.Cryptography.Hash`, `SHA256` refers to the library module and shadows `System.Security.Cryptography.SHA256`; qualify one of them when both are needed.
- Name DEK functions `encryptDEK` / `decryptDEK` (and plural for batch), matching the library parameter names.

## Testing Recommendations

- Test encryption by round-trip (`decrypt (encrypt x) = x`) plus negative cases: wrong secret / wrong AAD / tampered ciphertext must yield `Error` (or throw, for `AES256GCM`). Do not assert on ciphertext values.
- Assert hashes against known vectors: `SHA256.sha256Hex "hello world"` is `"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"`, `Crc32.crc32OfString "hello world"` is `"d4a1185"`.
- In envelope tests use `RSA256.createKeyPair ()` as the KEK and run the `AsyncResult` with `Async.RunSynchronously`. See `examples.md` → "Test — envelope round-trip and tamper detection".
- `RSA256.createKeyPair ()` generates a 2048-bit key per call; create it once per test list when many cases need it.
