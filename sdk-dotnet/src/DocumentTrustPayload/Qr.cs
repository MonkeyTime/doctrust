using System.IO.Compression;
using System.Text;

namespace DocumentTrustPayload;

public static class Qr
{
    private const string CompactPrefix = "dtp1z.";
    private const int MaxDecompressedBytes = 1024 * 1024;

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
        var buffer = new byte[8192];
        var total = 0;
        int read;
        while ((read = deflate.Read(buffer, 0, buffer.Length)) > 0)
        {
            total += read;
            if (total > MaxDecompressedBytes)
            {
                throw new ArgumentException("Compact transport payload is too large", nameof(input));
            }

            output.Write(buffer, 0, read);
        }
        return Encoding.UTF8.GetString(output.ToArray());
    }

    public static bool IsCompactTransportPayload(string input)
    {
        return input.StartsWith(CompactPrefix, StringComparison.Ordinal);
    }
}
