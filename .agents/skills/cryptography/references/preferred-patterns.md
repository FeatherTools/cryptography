# Preferred Patterns

For all runnable code referenced below, see `references/examples.md`.

## Core Principles

- Every module is `[<RequireQualifiedAccess>]`; always call through the module name (`Base64.encode`, `RSA256.encrypt`, `AES256GCM.decrypt`), never `open` the submodule to drop the prefix.
- Keys, nonces, tags, ciphertext, and authenticated data are single-case DUs (`PrivateKey`, `PublicKey`, `DEK`, `IV`, `Tag`, `AAD`, `EncryptedData`). Construct and pattern-match them explicitly; do not pass raw `byte[]` where a wrapper is expected.
- Plaintext and binary payloads are `byte[]`; use the `Encode` helpers to cross the string boundary rather than calling `System.Text.Encoding` directly.
- Transmit binary output as text with base64url (`Base64.toBase64Url`) when it must survive URLs or JWTs; reverse with `Base64.fromBase64Url` before decoding.

## Recommended API Usage

- Encoding round-trips: pair `Base64.encodeString`/`decodeString`, and `Base64.toBase64Url`/`fromBase64Url`. See `examples.md` → Encoding.
- Hashing: `SHA256.sha256Hex` returns lowercase hex; `SHA256.sha256` returns raw bytes; `Crc32.crc32OfString` returns a hex checksum. See `examples.md` → Hashing.
- Asymmetric: generate once with `RSA256.createKeyPair`, then `RSA256.encrypt`/`decrypt`. See `examples.md` → RSA.
- Authenticated symmetric: `AES256GCM.generateKey` yields a `DEK`; `encrypt` returns the `IV`, ciphertext, and `Tag` you must retain for `decrypt`. See `examples.md` → AES-GCM.
- Single-secret helper: `Symmetric.encrypt`/`decrypt` take any string secret and a string payload; `Symmetric.generateSecret` produces a strong one. See `examples.md` → Symmetric.
- Passwords: `Bcrypt.hashPassword` then `Bcrypt.verifyPassword`. See `examples.md` → Bcrypt.

## Error Handling

- `RSA256` and `AES256GCM` raise on failure (a wrong key, tag, or `AAD` throws `CryptographicException`); wrap calls in `try/with` if the failure is expected.
- `Symmetric.decrypt` returns `Result<string, string>` — match on `Ok`/`Error` instead of catching exceptions; it already maps tampering and bad encoding to descriptive `Error` values.
- `EncryptedEnvelope.decrypt`/`decryptBatch` catch `CryptographicException` internally and surface it as `Error "Envelope authentication failed"`, so handle the `AsyncResult` error channel rather than exceptions.

## Composition

- `EncryptedEnvelope.encrypt` and `decrypt` are parameterised by a caller-supplied `encryptDEK: DEK -> AsyncResult<EncryptedData, string>` and `decryptDEK: EncryptedData -> AsyncResult<DEK, string>`. This is where an external KEK/vault/HSM is plugged in; the library never sees the master key.
- Use `encryptBatch`/`decryptBatch` when wrapping many `DEK`s in one round-trip to the key service; they preserve list order between inputs and outputs.
- The `AAD` argument, when supplied to `encrypt`, must be supplied identically to `decrypt`; it is authenticated but not encrypted.

## Integration with Feather.ErrorHandling

- Envelope APIs return `AsyncResult<_, string>`; build the `encryptDEK`/`decryptDEK` callbacks with the `asyncResult` computation expression.
- Run an `AsyncResult` to a value with `AsyncResult.runSynchronously` and unwrap with `Result.orFail` at the edge (tests, scripts), or keep composing within `asyncResult` in production code.

## Naming Conventions

- Bind destructured wrappers at the call site (`let (DEK dekBytes) = ...`, `let (IV nonce), ciphertext, (Tag tag) = ...`) to name the inner bytes clearly.
- Mirror the library's vocabulary in your own code: `dek`, `kek`, `iv`, `tag`, `aad`, `ciphertext`, `plaintext`.

## Testing Recommendations

- The suite uses Expecto; assert round-trips (`encrypt` then `decrypt` equals the original) and negative cases (wrong `AAD`/secret fails). See `examples.md` → Test.
- For known-answer tests, `SHA256.sha256Hex "hello world"` and `Crc32.crc32OfString "hello world"` have stable expected values shown in `examples.md` → Hashing.
