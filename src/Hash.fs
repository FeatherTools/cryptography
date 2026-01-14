namespace Feather.Cryptography


module Hash =
    open System
    open System.Security.Cryptography

    module SHA256 =
        let sha256 (input: byte[]) : byte[] =
            use sha256 = SHA256.Create()
            sha256.ComputeHash input

        let sha256Hex (data: string) =
            data
            |> Encode.stringToBytes
            |> sha256
            |> BitConverter.ToString
            |> Seq.filter ((<>) '-')
            |> String.Concat
            |> String.toLower

    /// https://titanwolf.org/Network/Articles/Article?AID=9c8c1045-c819-4827-84c6-9c9977a63bdc
    module Crc32 =
        //Generator polynomial (modulo 2) for the reversed CRC32 algorithm.
        let private sGenerator = uint32 0xEDB88320

        //Generate lookup table
        let private lutIntermediate input =
            if (input &&& uint32 1) <> uint32 0
            then sGenerator ^^^ (input >>> 1)
            else input >>> 1

        let private lutEntry input =
            seq { 0..7 }
            |> Seq.fold (fun acc x -> lutIntermediate acc) input

        let private crc32lut =
            [ uint32 0 .. uint32 0xFF ]
            |> List.map lutEntry

        let crc32byte (register: uint32) (byte: byte) =
            crc32lut.[Convert.ToInt32((register &&& uint32 0xFF) ^^^ Convert.ToUInt32(byte))] ^^^ (register >>> 8)

        //CRC32 of a byte array
        let crc32 (input : byte[]) =
            let result = Array.fold crc32byte (uint32 0xFFFFFFFF) input
            ~~~result

        //CRC32 from ASCII string
        let crc32OfAscii (inputAscii : string) =
            let bytes = System.Text.Encoding.ASCII.GetBytes(inputAscii)
            crc32 bytes

        //CRC32 from ASCII string
        let crc32OfString = crc32OfAscii >> sprintf "%x"
