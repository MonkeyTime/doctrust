using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using DocumentTrustPayload;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new Exception(message);
    }
}

var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var privatePem = ecdsa.ExportPkcs8PrivateKeyPem();
var publicPem = ecdsa.ExportSubjectPublicKeyInfoPem();

var payload = """
{
  "version": "1",
  "issuer": {
    "issuer_id": "company:acme-eu",
    "display_name": "ACME Europe SARL",
    "trust_anchor_id": "registry:acme-trust-root"
  },
  "document": {
    "document_id": "INV-2026-000184",
    "document_type": "invoice",
    "beneficiary_name": "ACME Europe SARL",
    "iban": "BE68 5390 0754 7034",
    "amount": 1499.95,
    "currency": "EUR",
    "reference": "RF18539007547034",
    "due_date": "2026-07-15",
    "transaction_id": "TX-2026-06-25-000184",
    "communication": "Invoice INV-2026-000184"
  },
  "intent": "payment",
  "issued_at": "2026-06-25T10:00:00Z",
  "expires_at": "2026-07-15T23:59:59Z",
  "nonce": "6f7a1d8c4f2b4b4b8f0a",
  "alg": "ES256"
}
""";

var signed = DocumentTrustPayloadSdk.SignPayload(payload, privatePem);
var result = DocumentTrustPayloadSdk.VerifySignedPayload(signed, publicPem, now: new DateTimeOffset(2026, 6, 26, 0, 0, 0, TimeSpan.Zero));
Assert(result.Ok, "ES256 verify should pass");
Assert(result.DocumentId == "INV-2026-000184", "Document id mismatch");

var transport = DocumentTrustPayloadSdk.EncodeTransportPayload(signed);
Assert(DocumentTrustPayloadSdk.IsCompactTransportPayload(transport), "Transport should be compact");
var transportResult = DocumentTrustPayloadSdk.VerifyTransportPayload(transport, publicPem, now: new DateTimeOffset(2026, 6, 26, 0, 0, 0, TimeSpan.Zero));
Assert(transportResult.Ok, "Transport verify should pass");

var publicPemJson = JsonSerializer.Serialize(publicPem);
var trustRegistry = JsonNode.Parse($$"""
{
  "version": "1",
  "anchors": [
    {
      "trust_anchor_id": "registry:acme-trust-root",
      "issuer_id": "company:acme-eu",
      "status": "active",
      "public_keys": [
        {
          "key_id": "acme-eu-es256-2026-06",
          "alg": "ES256",
          "status": "active",
          "public_key_pem": {{publicPemJson}}
        }
      ]
    }
  ]
}
""")!.AsObject();
using var trustRegistryJsonDoc = JsonDocument.Parse(trustRegistry.ToJsonString());
var registryResult = DocumentTrustPayloadSdk.VerifySignedPayload(signed, trustRegistry: trustRegistryJsonDoc.RootElement.Clone(), now: new DateTimeOffset(2026, 6, 26, 0, 0, 0, TimeSpan.Zero));
Assert(registryResult.Ok, "Registry verify should pass");

var edKeyGen = new Ed25519KeyPairGenerator();
edKeyGen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
var edKeyPair = edKeyGen.GenerateKeyPair();

string WritePem(object obj)
{
    using var sw = new StringWriter();
    var pemWriter = new PemWriter(sw);
    pemWriter.WriteObject(obj);
    return sw.ToString();
}

var edPrivatePem = WritePem(edKeyPair.Private);
var edPublicPem = WritePem(edKeyPair.Public);

var edPayload = """
{
  "version": "1",
  "issuer": {
    "issuer_id": "company:acme-eu",
    "display_name": "ACME Europe SARL",
    "trust_anchor_id": "registry:acme-trust-root"
  },
  "document": {
    "document_id": "INV-2026-000185"
  },
  "intent": "payment",
  "issued_at": "2026-06-25T10:00:00Z",
  "expires_at": "2026-07-15T23:59:59Z",
  "nonce": "6f7a1d8c4f2b4b4b8f0b",
  "alg": "Ed25519"
}
""";

var edSigned = DocumentTrustPayloadSdk.SignPayload(edPayload, edPrivatePem);
var edResult = DocumentTrustPayloadSdk.VerifySignedPayload(edSigned, edPublicPem, now: new DateTimeOffset(2026, 6, 26, 0, 0, 0, TimeSpan.Zero));
Assert(edResult.Ok, "Ed25519 verify should pass");

var paymentProfile = DocumentTrustPayloadSdk.ValidatePaymentProfile(payload, new PaymentProfileExpectation(
    BeneficiaryName: "ACME Europe SARL",
    Iban: "BE68 5390 0754 7034",
    Amount: 1499.95m,
    Currency: "EUR",
    Reference: "RF18539007547034",
    TransactionId: "TX-2026-06-25-000184"));

Assert(paymentProfile.Ok, "Payment profile should validate");
Assert(paymentProfile.MissingFields.Count == 0, "Payment profile should not miss fields");
Assert(paymentProfile.Mismatches.Count == 0, "Payment profile should not mismatch");

Console.WriteLine("All .NET reference tests passed.");
