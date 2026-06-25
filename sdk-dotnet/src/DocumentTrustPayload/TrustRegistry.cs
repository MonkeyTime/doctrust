using System.Text.Json;

namespace DocumentTrustPayload;

public static class TrustRegistry
{
    public static JsonElement LoadTrustRegistryFromFile(string filePath)
    {
        var json = File.ReadAllText(filePath);
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    public static (string PublicKeyPem, string? KeyId) ResolveTrustAnchorPublicKey(JsonElement registry, JsonElement issuer)
    {
        if (!registry.TryGetProperty("anchors", out var anchors) || anchors.ValueKind != JsonValueKind.Array)
        {
            throw new ArgumentException("Trust registry must contain an anchors array");
        }

        var issuerId = issuer.GetProperty("issuer_id").GetString();
        var trustAnchorId = issuer.GetProperty("trust_anchor_id").GetString();

        var anchor = anchors.EnumerateArray().FirstOrDefault(item =>
            item.ValueKind == JsonValueKind.Object &&
            item.TryGetProperty("trust_anchor_id", out var id) &&
            string.Equals(id.GetString(), trustAnchorId, StringComparison.Ordinal));

        if (anchor.ValueKind == JsonValueKind.Undefined)
        {
            throw new ArgumentException($"Unknown trust anchor: {trustAnchorId}");
        }

        if (anchor.TryGetProperty("status", out var status) && !string.Equals(status.GetString(), "active", StringComparison.Ordinal))
        {
            throw new ArgumentException($"Trust anchor is not active: {trustAnchorId}");
        }

        if (anchor.TryGetProperty("issuer_id", out var registryIssuerId) && !string.Equals(registryIssuerId.GetString(), issuerId, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Issuer mismatch for trust anchor: {trustAnchorId}");
        }

        if (!anchor.TryGetProperty("public_keys", out var publicKeys) || publicKeys.ValueKind != JsonValueKind.Array)
        {
            throw new ArgumentException($"Trust anchor has no public keys: {trustAnchorId}");
        }

        foreach (var key in publicKeys.EnumerateArray())
        {
            if (key.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            if (key.TryGetProperty("status", out var keyStatus) && string.Equals(keyStatus.GetString(), "revoked", StringComparison.Ordinal))
            {
                continue;
            }

            var pem = key.GetProperty("public_key_pem").GetString();
            if (string.IsNullOrWhiteSpace(pem))
            {
                continue;
            }

            return (pem, key.TryGetProperty("key_id", out var keyId) ? keyId.GetString() : null);
        }

        throw new ArgumentException($"Trust anchor has no active public key: {trustAnchorId}");
    }
}
