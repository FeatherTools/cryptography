module Feather.Cryptography.Hash.Test

open Expecto
open Feather.Cryptography.Hash

[<Tests>]
let hashTest =
    testList "Hash" [
        testCase "should calculate sha256 hex" <| fun _ ->
            let input = "hello world"
            let hash = input |> SHA256.sha256Hex
            let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

            Expect.equal hash expected "Hashes should match"

        testCase "should calculate crc32" <| fun _ ->
            let input = "hello world"
            let hash = input |> Crc32.crc32OfString
            let expected = "d4a1185"

            Expect.equal hash expected "Hashes should match"
    ]
