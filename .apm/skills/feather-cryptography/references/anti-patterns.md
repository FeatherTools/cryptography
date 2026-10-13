# Anti-Patterns

Format: **mistake → why it is wrong → fix**.

## Outdated / Non-existent API

- **Calling `EncryptedEnvelope.decrypt decryptDEK envelope`** → the README shows this two-argument form, but `decrypt` takes the AAD before the envelope (`decryptDEK -> AAD option -> EncryptedEnvelope -> AsyncResult<byte[], string>`); the envelope lands in the `AAD option` slot and it does not compile → `EncryptedEnvelope.decrypt decryptDEK aad envelope`, passing `None` when no AAD was used.

- **Calling `AsyncResult.runSynchronously`** → the README envelope example uses it, but `Feather.ErrorHandling` has no such function; it does not compile → `Async.RunSynchronously` (an `AsyncResult` is an `Async<Result<_, _>>`), or better, stay inside `asyncResult {}` and bind with `let!`.

- **Reading `envelope.AAD` or expecting the envelope to carry the AAD** → the README lists "Optional AAD" among envelope contents, but `EncryptedEnvelope` has only `Version`, `Algorithm`, `Iv`, `Ciphertext`, `Tag`, `DEK` → keep the AAD's source data yourself and rebuild the same `AAD` for decryption.

- **Looking for `PrivateKey.value`, `DEK.create`, `AAD.ofString` or similar companion functions** → the wrapper types have no companion modules → construct with the case (`AAD bytes`) and deconstruct with a pattern (`let (DEK bytes) = dek`).

- **Expecting `Crc32.crc32OfString` to return 8 hex digits** → it formats with `%x`, so leading zeros are dropped (`"hello world"` → `"d4a1185"`, not `"0d4a1185"`) → use `Crc32.crc32` (a `uint32`) and format with `"%08x"` when a fixed width is needed.

## Key Material

- **Returning the DEK's own array from `encryptDEK` (e.g. `fun (DEK d) -> asyncResult { return EncryptedData d }`)** → `EncryptedEnvelope.encrypt` zeroes the DEK bytes after `encryptDEK` returns, so the envelope's `DEK` field becomes all zeros and the data is unrecoverable → always return newly produced bytes (the output of RSA/KMS wrapping).

- **Caching a `DEK` and returning the same instance from `decryptDEK`** → `decrypt` / `decryptBatch` zero the returned DEK bytes after use; the first decrypt succeeds and every later one fails with `"Envelope authentication failed"` → unwrap fresh on each call, or return `DEK (Array.copy cached)`.

- **Reusing one `DEK` for many `AES256GCM.encrypt` calls without bound, or persisting it in plaintext** → the DEK is the whole secret; GCM with random 96-bit nonces also has a per-key message limit → use `EncryptedEnvelope`, which creates a new DEK per item and stores it only wrapped.

- **Generating a `Symmetric` secret per message, or deriving it from user input** → `Symmetric.decrypt` needs the exact same secret string, and HKDF without salt adds no strengthening to a weak secret → generate once with `Symmetric.generateSecret ()`, store it in a secrets manager, and use `Bcrypt` for anything password-like.

## Algorithm Misuse

- **Encrypting payloads with `RSA256.encrypt`** → RSA-2048 OAEP-SHA256 accepts at most 190 bytes and throws above that → use it to wrap a `DEK` only; encrypt data with `EncryptedEnvelope` or `AES256GCM`.

- **Hashing passwords with `SHA256.sha256Hex` or `Crc32`** → fast unsalted hashes are trivially brute-forced → `Bcrypt.hashPassword` / `Bcrypt.verifyPassword`.

- **Comparing bcrypt hashes for equality (`Bcrypt.hashPassword input = storedHash`)** → every hash has a random salt, so it never matches → `Bcrypt.verifyPassword input storedHash`.

- **Using `Crc32` as a security check** → CRC32 detects accidental corruption only and is trivially forgeable → rely on the AES-GCM tag (built into `Symmetric` and `EncryptedEnvelope`) or SHA-256.

- **Feeding non-ASCII text to `Crc32.crc32OfString` / `crc32OfAscii`** → input is encoded as ASCII, so every non-ASCII character becomes `?` (`"é"` and `"?"` hash the same) → `Crc32.crc32 (Encode.stringToBytes text)`.

## Error Handling

- **Calling `AES256GCM.decrypt`, `RSA256.decrypt`, `Bcrypt.verifyPassword` or `Base64.decode` on untrusted input without a guard** → they throw (`AuthenticationTagMismatchException`, `CryptographicException`, `SaltParseException`, `FormatException`) → guard the single call with `try ... with` into a `Result`, or use `Symmetric` / `EncryptedEnvelope`, which return errors.

- **Throwing from `encryptDEK` / `decryptDEK` (or awaiting an SDK `Task` without a catch)** → only `CryptographicException` is converted to `Error`; other exceptions escape the `AsyncResult` → lift Task calls with `AsyncResult.ofTaskCatch` and return `Error` for failures.

- **Passing a batch DEK function that drops, reorders or filters items** → `encryptBatch` / `decryptBatch` pair DEKs and items by position with `List.map2`; a length mismatch throws `ArgumentException` (not converted to `Error`) and reordering silently pairs wrong keys, which then fails authentication → return exactly one output per input, in input order.

- **Branching on `Symmetric.decrypt` error text** → the messages are informational and may change → treat any `Error` as "cannot decrypt" and map it to your own error case.

## Output Assumptions

- **Asserting on ciphertext or expecting deterministic output** → nonces and DEKs are random per call → assert on round-trip results.

- **Expecting `Base64.toBase64Url` output to have padding, or passing unpadded base64url to `Base64.decode`** → `toBase64Url` strips `=` and `decode` requires standard base64 → always go through `Base64.fromBase64Url` before `Base64.decode`.

- **Treating `Secret.generateBase64Url n` as an `n`-character string** → `n` is the number of random bytes; the string is about `4n/3` characters (32 → 43) → pass the byte count you need.
