namespace DocumentTrustPayload;

public static class DocumentTrustPayloadSdk
{
    public static string CanonicalPayloadBody(string payloadJson) => Verification.CanonicalPayloadBody(payloadJson);
    public static string SignPayload(string payloadJson, string privateKeyPem) => Verification.SignPayload(payloadJson, privateKeyPem);
    public static VerificationResult VerifySignedPayload(string payloadJson, string? publicKeyPem = null, System.Text.Json.JsonElement? trustRegistry = null, DateTimeOffset? now = null)
        => Verification.VerifySignedPayload(payloadJson, publicKeyPem, trustRegistry, now);
    public static VerificationResult VerifyTransportPayload(string transportPayload, string? publicKeyPem = null, System.Text.Json.JsonElement? trustRegistry = null, DateTimeOffset? now = null)
        => Verification.VerifyTransportPayload(transportPayload, publicKeyPem, trustRegistry, now);
    public static PaymentProfileValidationResult ValidatePaymentProfile(string payloadJson, PaymentProfileExpectation? expected = null)
        => Verification.ValidatePaymentProfile(payloadJson, expected);
    public static string EncodeTransportPayload(string payloadJson) => Qr.EncodeTransportPayload(payloadJson);
    public static string DecodeTransportPayload(string transportPayload) => Qr.DecodeTransportPayload(transportPayload);
    public static bool IsCompactTransportPayload(string input) => Qr.IsCompactTransportPayload(input);
    public static System.Text.Json.JsonElement LoadTrustRegistryFromFile(string filePath) => TrustRegistry.LoadTrustRegistryFromFile(filePath);
}
