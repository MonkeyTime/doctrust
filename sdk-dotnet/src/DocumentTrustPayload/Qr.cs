using System.IO.Compression;
using System.Text;

namespace DocumentTrustPayload;

public static class Qr
{
    private const string CompactPrefix = "dtp1z.";

    public static string EncodeTransportPayload(string payloadJson)
    {
        var data = Encoding.UTF8.GetBytes(payloadJson);
        using var output = new MemoryStream();
        using (var zlib = new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(data, 0, data.Length);
        }

        return CompactPrefix + Crypto.Base64UrlEncode(output.ToArray());
    }

    public static string DecodeTransportPayload(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            throw new ArgumentException("Transport payload must be a non-empty string", nameof(input));
        }

        if (!input.StartsWith(CompactPrefix, StringComparison.Ordinal))
        {
            return input;
        }

        var compressed = Crypto.Base64UrlDecode(input[CompactPrefix.Length..]);
        using var inputStream = new MemoryStream(compressed);
        using var deflate = new DeflateStream(inputStream, CompressionMode.Decompress);
        using var output = new MemoryStream();
        deflate.CopyTo(output);
        return Encoding.UTF8.GetString(output.ToArray());
    }

    public static bool IsCompactTransportPayload(string input)
    {
        return input.StartsWith(CompactPrefix, StringComparison.Ordinal);
    }
}
