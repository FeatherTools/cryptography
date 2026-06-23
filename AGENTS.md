# AGENTS.md — Feather.Cryptography

This repo ships Agent Skill for the `Feather.Cryptography` library. Compatible agents discover it automatically; see `.agents/skills/cryptography/SKILL.md`.

## Project Purpose

`Feather.Cryptography` is an F# library of predefined use-cases for encryption, decryption, hashing, and encoding. It wraps .NET cryptographic primitives behind small `[<RequireQualifiedAccess>]` modules and single-case discriminated-union types, so calling code passes well-typed keys, nonces, tags, and ciphertext instead of bare byte arrays. It exposes Base64/base64url encoding, SHA-256 and CRC32 hashing, RSA-OAEP key wrapping, AES-256-GCM, envelope encryption (DEK/KEK) with batch variants, HKDF-derived symmetric string encryption, and bcrypt password hashing.

## Tech Stack

- **Language:** F# (`net10.0`)
- **Package manager:** Paket
- **Build system:** FAKE (run via `build.sh`)
- **Test framework:** Expecto (with `YoloDev.Expecto.TestSdk`)
- **NuGet package id:** `Feather.Cryptography`
- **Repository URL:** https://github.com/FeatherTools/cryptography

## Key Dependencies

- `FSharp.Core ~> 10.0` — F# core library.
- `BCrypt.Net-Core ~> 1.6` — bcrypt password hashing/verification (`Cryptography.Bcrypt`).
- `Feather.ErrorHandling ~> 2.0` — provides the `AsyncResult` type and `asyncResult` computation expression used by the envelope encryption APIs.

## Commands

```bash
# Restore local dotnet tools (fake-cli, paket, dotnet-fsharplint) and Paket dependencies
dotnet tool restore
dotnet tool run paket restore

# Full pipeline: Clean -> AssemblyInfo -> Build -> Lint -> Tests -> Release -> Publish
./build.sh

# Individual targets
./build.sh -t build
./build.sh -t lint
./build.sh -t tests

# Useful flags (passed as extra args)
./build.sh -t tests no-lint   # run lint but do not fail on lint results
./build.sh no-clean           # skip the Clean step (used on CI)
```

## Project Structure

```
Cryptography.fsproj          # Library project: package id, version, compile order
build.sh                     # Entry point: tool restore + paket restore + FAKE run
paket.dependencies           # Dependency manifest (main + Build group)
paket.references             # Library package references
paket.lock                   # Locked dependency versions
CHANGELOG.md                 # Keep-a-changelog style history (Unreleased on top)
README.md                    # Packed into the NuGet package
src/
  Encode.fs                  # Encode module: Base64 / base64url + UTF8 helpers
  Hash.fs                    # Hash module: SHA256, Crc32
  Cryptography.fs            # Core crypto: Secret, RSA256, AES256GCM, EncryptedEnvelope, Symmetric, Bcrypt
tests/
  Tests.fs                   # Test entry point
  EncodingTests.fs           # Tests for Encode
  HashTests.fs               # Tests for Hash
  CryptographyTests.fs       # Tests for Cryptography
  tests.fsproj               # Expecto test project
build/
  Build.fs                   # FAKE build entry point + project definition
  Targets.fs                 # FAKE target definitions and hierarchy
  Utils.fs                   # Build helpers
  SafeBuildHelpers.fs        # SAFE-stack helpers (unused by this library)
  build.fsproj               # Build project
.config/
  dotnet-tools.json          # Pinned local tools: fake-cli, paket, dotnet-fsharplint
.github/
  workflows/                 # CI/CD: pr-check, tests, publish
.agents/skills/cryptography/ # Agent Skill for consumers of the library
```

## Architecture

The library is organized as one namespace, `Feather.Cryptography`, split across three source files compiled in order (`Encode.fs` → `Hash.fs` → `Cryptography.fs`). Each public surface is a `[<RequireQualifiedAccess>]` module, and cryptographic values are wrapped in single-case discriminated unions for type safety.

Core types and components:

1. **`Encode`** (`src/Encode.fs`) — `bytesToString`/`stringToBytes` UTF-8 helpers and the `Base64` module (`encode`, `decode`, `encodeString`, `decodeString`, `toBase64Url`, `fromBase64Url`).
2. **`Hash.SHA256`** (`src/Hash.fs`) — `sha256` (bytes) and `sha256Hex` (lowercase hex string).
3. **`Hash.Crc32`** (`src/Hash.fs`) — CRC32 lookup-table implementation; `crc32`, `crc32OfAscii`, `crc32OfString`.
4. **`Cryptography.Secret`** — random secret generation: `generateBase64Url`, `generateBytes`.
5. **`Cryptography.RSA256`** — RSA-2048 with OAEP-SHA256: `createKeyPair`, `encrypt`, `decrypt`.
6. **`Cryptography.AES256GCM`** — AES-256-GCM: `generateKey`, `encrypt`, `decrypt` (96-bit nonce, 128-bit tag, optional AAD).
7. **`Cryptography.EncryptedEnvelope`** — envelope encryption (`EncryptedEnvelope` record) using a per-item DEK wrapped by a caller-supplied function: `encrypt`, `decrypt`, `encryptBatch`, `decryptBatch`.
8. **`Cryptography.Symmetric`** — string-in/string-out AES-256-GCM with HKDF-SHA256 key derivation: `generateSecret`, `encrypt`, `decrypt`.
9. **`Cryptography.Bcrypt`** — `hashPassword`, `verifyPassword`.

### Pattern: Single-case DU wrappers

Cryptographic byte arrays are wrapped in single-case discriminated unions (`PrivateKey`, `PublicKey`, `EncryptedData`, `KEK`, `DEK`, `IV`, `Tag`, `AAD`, `Version`, `Algorithm`) instead of being passed as raw `byte[]`. This makes function signatures self-documenting and prevents accidentally swapping, for example, a nonce for a tag. The `EncryptedEnvelope` record composes these types together, and the envelope APIs accept caller-supplied DEK-wrapping functions (`DEK -> AsyncResult<EncryptedData, string>`) so key management (vault, HSM, etc.) stays outside the library.

## Conventions

- All source lives under a single `namespace Feather.Cryptography`.
- Public modules use `[<RequireQualifiedAccess>]`; callers invoke them fully qualified (e.g. `AES256GCM.encrypt`).
- Cryptographic values are modeled as single-case DUs rather than bare `byte[]`.
- Key material is zeroed after use with `Array.Clear` to limit exposure in memory.
- Shared internal helpers live in an `[<AutoOpen>] module internal Utils` (e.g. `String.toLower`).
- The build injects `InternalsVisibleTo "tests"` so tests can reach internal members.
- Compile order is explicit in `Cryptography.fsproj` via `<Compile Include="...">` entries — files must appear in dependency order.
- Async, fallible operations return `AsyncResult<_, string>` via the `asyncResult` computation expression from `Feather.ErrorHandling`.

## CI/CD

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `pr-check.yaml` | `pull_request` | Blocks merging of `fixup!` commits and runs ShellCheck on shell scripts (with `SHELLCHECK_OPTS: -e SC1090`). |
| `tests.yaml` | `pull_request` and nightly `cron` (`0 3 * * *`) | Sets up .NET 10, then runs `./build.sh -t tests no-lint` on `ubuntu-latest`. |
| `publish.yaml` | `push` of a tag matching `[0-9]+\.[0-9]+\.[0-9]+` | Sets up .NET 10, then runs `./build.sh -t publish no-lint` to pack and push the package to NuGet.org using the `NUGET_API_KEY` secret. |

## Release Process

1. Bump `<Version>` in `Cryptography.fsproj`.
2. Move the relevant entries from the `## Unreleased` section of `CHANGELOG.md` into a new dated version section (e.g. `## 2.3.0 - 2026-06-11`).
3. Commit the changes.
4. Create and push a Git tag of the form `X.Y.Z` (matching `[0-9]+\.[0-9]+\.[0-9]+`).
5. The `publish.yaml` workflow runs on the tag push and publishes the package to NuGet.org.

## Pitfalls

- **Do not remove the `Array.Clear` calls** that wipe DEKs and derived keys — they intentionally scrub key material from memory after use.
- **Preserve the `<Compile>` order** in `Cryptography.fsproj` (`Encode.fs` → `Hash.fs` → `Cryptography.fs`); F# requires dependencies to be compiled before their consumers.
- **`Crc32` hashes ASCII, not UTF-8** (`crc32OfAscii` uses `Encoding.ASCII`), unlike the SHA-256 helpers which use UTF-8 — non-ASCII input will not round-trip the way you might expect.
- **AES-256-GCM sizes are fixed** (12-byte nonce, 16-byte tag, 32-byte key); changing them will break compatibility with previously produced ciphertext and with the `Symmetric` `nonce ++ ciphertext ++ tag` layout.
- **`Symmetric` derives its key with HKDF-SHA256** from the secret string; the same secret must be used for `encrypt` and `decrypt`, and the encoded output is base64url, not standard base64.
- **`AssemblyInfo.fs` is generated** by the FAKE `AssemblyInfo` target from `CHANGELOG.md` and Git metadata — do not edit it by hand; update the changelog/version instead.
- **CI currently runs with `no-lint`** and there is no `fsharplint.json` or `.editorconfig` in the repo, so `fsharplint` uses its default rules and lint failures do not block CI; do not assume lint is enforced on PRs.
