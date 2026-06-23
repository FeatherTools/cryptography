# Anti-Patterns

Each item is **mistake → why → fix**. Code lives only in `references/examples.md`.

## Common Mistakes

- **Using `Crc32` to protect or fingerprint data securely** → CRC-32 is a non-cryptographic checksum for detecting accidental corruption; it is trivially forgeable → use `SHA256.sha256Hex`/`sha256` when integrity must resist tampering.

- **Expecting `SHA256.sha256Hex` to return uppercase hex** → it lowercases the output → compare against lowercase expected values (e.g. `b94d27b9...`), or normalise both sides before comparing.

- **Assuming `Crc32.crc32OfString` encodes the input as UTF-8** → it encodes via ASCII before hashing → for non-ASCII input convert bytes yourself and call `Crc32.crc32`, and never assume the checksum matches a UTF-8 CRC from another tool.

- **Treating standard Base64 and base64url as interchangeable** → JWTs and URLs require base64url (`+/=` replaced/stripped); plain `Base64.encode` output breaks them → pipe through `Base64.toBase64Url` for transport and `Base64.fromBase64Url` before `Base64.decode`.

- **Discarding the `IV` and `Tag` returned by `AES256GCM.encrypt`** → decryption needs the exact nonce and authentication tag; without them the ciphertext is unrecoverable → store/transmit all three (`IV`, ciphertext, `Tag`) together.

- **Reusing or hand-rolling a nonce for AES-GCM** → the library already generates a fresh random nonce per `encrypt` call, and nonce reuse with the same key destroys GCM security → call `AES256GCM.encrypt` again for each message and keep the returned `IV`; never inject your own.

- **Mismatching `AAD` between encrypt and decrypt** → GCM authenticates the `AAD`, so any difference (including `Some` vs `None`) throws/fails authentication → pass the identical `AAD` value to both sides.

- **Ignoring the `Result` from `Symmetric.decrypt`** → it returns `Result<string, string>` and reports wrong-secret/corrupted/format errors as `Error`, not exceptions → match on `Ok`/`Error` rather than assuming success or wrapping in `try/with`.

- **Catching exceptions around `EncryptedEnvelope.decrypt`** → it already converts `CryptographicException` into `Error "Envelope authentication failed"` on the `AsyncResult` error channel → handle the error channel; a `try/with` will never fire for auth failure.

- **Hashing passwords with `SHA256`** → fast hashes are unsuitable for passwords (no work factor, brute-forceable) → use `Bcrypt.hashPassword`/`Bcrypt.verifyPassword`.

## Do Not Use / Avoid

- **`open`-ing the qualified submodules to shorten calls** → the modules are `[<RequireQualifiedAccess>]` for disambiguation (`SHA256`, `Base64`, etc. collide with .NET names) → keep the module prefix.

- **Passing raw `byte[]` where a wrapper type is expected** → functions take `DEK`, `IV`, `Tag`, `AAD`, `PublicKey`, etc., and the compiler will reject bare arrays → wrap explicitly (`DEK bytes`, `AAD bytes`).

- **Embedding a master/KEK key inside the encrypt/decrypt callbacks naively** → the envelope design deliberately delegates DEK wrapping to your `encryptDEK`/`decryptDEK` so the master key can stay in an external service → route DEK wrapping through that external key service rather than holding the KEK in process.

## Wrong Abstractions

- **Building your own envelope by manually combining `RSA256` + `AES256GCM`** → `EncryptedEnvelope` already generates the per-message `DEK`, encrypts the payload, wraps the `DEK`, and clears key bytes from memory → use `EncryptedEnvelope.encrypt`/`decrypt` (and the batch variants for bulk).
