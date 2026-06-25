using System.Globalization;
using System.Text;
using System.Text.Json;

namespace DocumentTrustPayload;

public static class Canonicalize
{
    public static string JsonToCanonicalString(JsonElement element)
    {
        var sb = new StringBuilder();
        WriteElement(sb, element);
        return sb.ToString();
    }

    private static void WriteElement(StringBuilder sb, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                sb.Append('{');
                var props = element.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal).ToArray();
                for (var i = 0; i < props.Length; i++)
                {
                    if (i > 0) sb.Append(',');
                    sb.Append(JsonSerializer.Serialize(props[i].Name));
                    sb.Append(':');
                    WriteElement(sb, props[i].Value);
                }
                sb.Append('}');
                break;
            case JsonValueKind.Array:
                sb.Append('[');
                var items = element.EnumerateArray().ToArray();
                for (var i = 0; i < items.Length; i++)
                {
                    if (i > 0) sb.Append(',');
                    WriteElement(sb, items[i]);
                }
                sb.Append(']');
                break;
            case JsonValueKind.String:
                sb.Append(JsonSerializer.Serialize(element.GetString()));
                break;
            case JsonValueKind.Number:
                sb.Append(element.GetRawText());
                break;
            case JsonValueKind.True:
                sb.Append("true");
                break;
            case JsonValueKind.False:
                sb.Append("false");
                break;
            case JsonValueKind.Null:
                sb.Append("null");
                break;
            default:
                throw new InvalidOperationException($"Unsupported JSON value kind: {element.ValueKind}");
        }
    }
}
