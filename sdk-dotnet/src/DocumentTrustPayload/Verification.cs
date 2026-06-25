using System.Text.Json;

namespace DocumentTrustPayload;

public sealed record VerificationResult(
    bool Ok,
    string IssuerId,
    string TrustAnchorId,
    string? TrustAnchorKeyId,
    string DocumentId,
    string Algorithm);

public static class Verification
{
    public static string CanonicalPayloadBody(string payloadJson)
    {
        var payload = ValidatePayload(payloadJson);
        return Canonicalize.JsonToCanonicalString(StripSignature(payload));
    }

    public static VerificationResult VerifySignedPayload(
        string payloadJson,
        string? publicKeyPem = null,
        JsonElement? trustRegistry = null,
        DateTimeOffset? now = null)
    {
        var payload = ValidatePayload(payloadJson);
        VerifyTimeWindow(payload, now ?? DateTimeOffset.UtcNow);

        string? resolvedKeyId = null;
        if (string.IsNullOrWhiteSpace(publicKeyPem))
        {
            if (trustRegistry is null)
            {
                throw new PayloadValidationException("Missing publicKeyPem or trustRegistry");
            }

            var resolved = TrustRegistry.ResolveTrustAnchorPublicKey(trustRegistry.Value, payload.GetProperty("issuer"));
            publicKeyPem = resolved.PublicKeyPem;
            resolvedKeyId = resolved.KeyId;
        }

        var canonicalBody = Canonicalize.JsonToCanonicalString(StripSignature(payload));
        var signature = Crypto.Base64UrlDecode(payload.GetProperty("sig").GetString()!);
        var ok = Crypto.VerifyCanonicalPayload(canonicalBody, signature, publicKeyPem!, payload.GetProperty("alg").GetString()!);

        if (!ok)
        {
            throw new SignatureVerificationException("Signature verification failed");
        }

        return new VerificationResult(
            true,
            payload.GetProperty("issuer").GetProperty("issuer_id").GetString()!,
            payload.GetProperty("issuer").GetProperty("trust_anchor_id").GetString()!,
            resolvedKeyId,
            payload.GetProperty("document").GetProperty("document_id").GetString()!,
            payload.GetProperty("alg").GetString()!);
    }

    public static VerificationResult VerifyTransportPayload(
        string transportPayload,
        string? publicKeyPem = null,
        JsonElement? trustRegistry = null,
        DateTimeOffset? now = null)
    {
        var payloadJson = Qr.DecodeTransportPayload(transportPayload);
        return VerifySignedPayload(payloadJson, publicKeyPem, trustRegistry, now);
    }

    public static string SignPayload(string payloadJson, string privateKeyPem)
    {
        var payload = ValidatePayloadForSigning(payloadJson);
        var canonicalBody = Canonicalize.JsonToCanonicalString(StripSignature(payload));
        var sig = Crypto.SignCanonicalPayload(canonicalBody, privateKeyPem, payload.GetProperty("alg").GetString()!);
        return Canonicalize.JsonToCanonicalString(AddSignature(payload, Crypto.Base64UrlEncode(sig)));
    }

    public static PaymentProfileValidationResult ValidatePaymentProfile(string payloadJson, PaymentProfileExpectation? expected = null)
    {
        var payload = ValidatePayloadForSigning(payloadJson);
        var document = payload.GetProperty("document");
        expected ??= new PaymentProfileExpectation();

        var requiredFields = new[]
        {
            "document_id",
            "document_type",
            "beneficiary_name",
            "iban",
            "amount",
            "currency",
            "reference",
            "due_date",
            "transaction_id",
            "communication"
        };

        var missingFields = requiredFields
            .Where(field => !HasPresentValue(document, field))
            .ToArray();

        var mismatches = new List<string>();
        if (payload.GetProperty("intent").GetString() != "payment") mismatches.Add("intent");
        if (!Matches(document, "document_type", "invoice")) mismatches.Add("document_type");
        if (expected.DocumentType is not null && !Matches(document, "document_type", expected.DocumentType)) mismatches.Add("document_type");
        if (expected.BeneficiaryName is not null && !Matches(document, "beneficiary_name", expected.BeneficiaryName)) mismatches.Add("beneficiary_name");
        if (expected.Iban is not null && !Matches(document, "iban", expected.Iban)) mismatches.Add("iban");
        if (expected.Amount is not null && !Matches(document, "amount", expected.Amount.Value)) mismatches.Add("amount");
        if (expected.Currency is not null && !Matches(document, "currency", expected.Currency)) mismatches.Add("currency");
        if (expected.Reference is not null && !Matches(document, "reference", expected.Reference)) mismatches.Add("reference");
        if (expected.DueDate is not null && !Matches(document, "due_date", expected.DueDate)) mismatches.Add("due_date");
        if (expected.TransactionId is not null && !Matches(document, "transaction_id", expected.TransactionId)) mismatches.Add("transaction_id");
        if (expected.Communication is not null && !Matches(document, "communication", expected.Communication)) mismatches.Add("communication");

        return new PaymentProfileValidationResult(
            missingFields.Length == 0 && mismatches.Count == 0,
            "payment.invoice",
            missingFields,
            mismatches);
    }

    private static JsonElement ValidatePayload(string payloadJson)
    {
        using var doc = JsonDocument.Parse(payloadJson);
        var payload = doc.RootElement.Clone();
        ValidatePayloadElement(payload);
        return payload;
    }

    private static JsonElement ValidatePayloadForSigning(string payloadJson)
    {
        using var doc = JsonDocument.Parse(payloadJson);
        var payload = doc.RootElement.Clone();
        ValidatePayloadElement(payload, requireSignature: false);
        return payload;
    }

    private static void ValidatePayloadElement(JsonElement payload, bool requireSignature = true)
    {
        if (payload.ValueKind != JsonValueKind.Object)
        {
            throw new PayloadValidationException("Payload must be a JSON object");
        }

        RequireString(payload, "version");
        RequireString(payload, "intent");
        RequireString(payload, "issued_at");
        RequireString(payload, "expires_at");
        RequireString(payload, "nonce");
        RequireString(payload, "alg");
        if (requireSignature)
        {
            RequireString(payload, "sig");
        }

        if (payload.GetProperty("version").GetString() != "1")
        {
            throw new PayloadValidationException($"Unsupported version: {payload.GetProperty("version").GetString()}");
        }

        var issuer = payload.GetProperty("issuer");
        if (issuer.ValueKind != JsonValueKind.Object)
        {
            throw new PayloadValidationException("Missing or invalid issuer object");
        }

        RequireString(issuer, "issuer_id", "issuer.issuer_id");
        RequireString(issuer, "display_name", "issuer.display_name");
        RequireString(issuer, "trust_anchor_id", "issuer.trust_anchor_id");

        var document = payload.GetProperty("document");
        if (document.ValueKind != JsonValueKind.Object)
        {
            throw new PayloadValidationException("Missing or invalid document object");
        }

        RequireString(document, "document_id", "document.document_id");
    }

    private static void RequireString(JsonElement parent, string propertyName, string? label = null)
    {
        if (!parent.TryGetProperty(propertyName, out var value) || value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw new PayloadValidationException($"Missing or invalid {label ?? propertyName}");
        }
    }

    private static void VerifyTimeWindow(JsonElement payload, DateTimeOffset now)
    {
        var issuedAt = DateTimeOffset.Parse(payload.GetProperty("issued_at").GetString()!, null, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal);
        var expiresAt = DateTimeOffset.Parse(payload.GetProperty("expires_at").GetString()!, null, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal);

        if (now < issuedAt)
        {
            throw new PayloadValidationException("Payload is not yet valid");
        }

        if (now > expiresAt)
        {
            throw new PayloadValidationException("Payload has expired");
        }
    }

    private static JsonElement StripSignature(JsonElement payload)
    {
        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms))
        {
            writer.WriteStartObject();
            foreach (var prop in payload.EnumerateObject().Where(p => p.Name != "sig").OrderBy(p => p.Name, StringComparer.Ordinal))
            {
                writer.WritePropertyName(prop.Name);
                prop.Value.WriteTo(writer);
            }
            writer.WriteEndObject();
        }

        using var doc = JsonDocument.Parse(ms.ToArray());
        return doc.RootElement.Clone();
    }

    private static JsonElement AddSignature(JsonElement payload, string sig)
    {
        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms))
        {
            writer.WriteStartObject();
            foreach (var prop in payload.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
            {
                writer.WritePropertyName(prop.Name);
                prop.Value.WriteTo(writer);
            }
            writer.WriteString("sig", sig);
            writer.WriteEndObject();
        }

        using var doc = JsonDocument.Parse(ms.ToArray());
        return doc.RootElement.Clone();
    }

    private static bool HasPresentValue(JsonElement document, string propertyName)
    {
        if (!document.TryGetProperty(propertyName, out var value))
        {
            return false;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => !string.IsNullOrWhiteSpace(value.GetString()),
            JsonValueKind.Number => true,
            _ => value.ValueKind is not JsonValueKind.Null and not JsonValueKind.Undefined
        };
    }

    private static bool Matches(JsonElement document, string propertyName, string expected)
    {
        return document.TryGetProperty(propertyName, out var value) && string.Equals(GetComparable(value), expected, StringComparison.Ordinal);
    }

    private static bool Matches(JsonElement document, string propertyName, decimal expected)
    {
        return document.TryGetProperty(propertyName, out var value) &&
               decimal.TryParse(GetComparable(value), System.Globalization.NumberStyles.Number, System.Globalization.CultureInfo.InvariantCulture, out var parsed) &&
               parsed == expected;
    }

    private static string GetComparable(JsonElement value)
    {
        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? string.Empty,
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => value.GetRawText()
        };
    }
}
