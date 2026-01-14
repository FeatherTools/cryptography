namespace Feather.Cryptography

open System
open System.Text

[<AutoOpen>]
module internal Utils =
    module String =
        let toLower (string: string) =
            string.ToLower()

module Encode =
    let bytesToString (bytes: byte[]) =
        Encoding.UTF8.GetString bytes

    let stringToBytes (str: string) =
        Encoding.UTF8.GetBytes str

    [<RequireQualifiedAccess>]
    module Base64 =
        let encode (bytes: byte[]) =
            Convert.ToBase64String bytes

        let decode (base64: string) =
            Convert.FromBase64String base64

        let encodeString = stringToBytes >> encode
        let decodeString = decode >> bytesToString

        /// Convert standard base64 to base64url format (RFC 4648)
        /// Used for JWT signatures which require base64url encoding
        let toBase64Url (base64: string) =
            base64
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=')

        /// Convert URL-safe Base64 back to standard Base64
        let fromBase64Url (base64Url: string) =
            let padded =
                match base64Url.Length % 4 with
                | 0 -> base64Url
                | 2 -> base64Url + "=="
                | 3 -> base64Url + "="
                | _ -> base64Url

            padded
                .Replace('-', '+')
                .Replace('_', '/')
