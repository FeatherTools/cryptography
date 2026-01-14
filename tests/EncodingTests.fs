module Feather.Cryptography.Encoding.Test

open Expecto
open Feather.Cryptography.Encode
open System.Text.RegularExpressions

[<Tests>]
let hashTest =
    testList "Encode" [
        testCase "should encode string to bytes and back" <| fun _ ->
            let input = "hello world"
            let bytes = input |> stringToBytes
            let output = bytes |> bytesToString

            Expect.equal output input "Strings should match"

        testCase "should encode string to base64 and back" <| fun _ ->
            let input = "hello world"
            let encoded = input |> Base64.encodeString
            let output = encoded |> Base64.decodeString

            Expect.equal output input "Strings should match"

        testCase "should encode string to base64url and back" <| fun _ ->
            let input = "hello world"
            let encoded = input |> Base64.encodeString |> Base64.toBase64Url
            let output = encoded |> Base64.fromBase64Url |> Base64.decodeString

            Expect.equal output input "Strings should match"
            Expect.isRegexMatch encoded (Regex "^[A-Za-z0-9_-]+$") "Base64Url should match regex"
    ]
