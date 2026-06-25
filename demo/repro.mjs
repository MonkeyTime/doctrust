import crypto from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const demoDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(demoDir, "..");
const sdk = await import(pathToFileURL(path.join(repoRoot, "sdk-js", "src", "index.js")).href);

const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ format: "pem", type: "spki" });
const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" });

const payload = {
  version: "1",
  issuer: {
    issuer_id: "company:acme-eu",
    display_name: "ACME Europe SARL",
    trust_anchor_id: "registry:acme-trust-root"
  },
  document: {
    document_id: "INV-2026-000184",
    document_type: "invoice",
    beneficiary_name: "ACME Europe SARL",
    iban: "BE68 5390 0754 7034",
    amount: 1499.95,
    currency: "EUR",
    reference: "RF18539007547034",
    due_date: "2026-07-15",
    transaction_id: "TX-2026-06-25-000184",
    communication: "Invoice INV-2026-000184"
  },
  intent: "payment",
  issued_at: "2026-06-25T10:00:00Z",
  expires_at: "2026-07-15T23:59:59Z",
  nonce: "demo-000184",
  alg: "Ed25519"
};

const signed = sdk.signPayload(payload, privateKeyPem);
const transport = sdk.encodeTransportPayload(JSON.stringify(signed));
const trustRegistry = {
  version: "1",
  anchors: [
    {
      trust_anchor_id: "registry:acme-trust-root",
      issuer_id: "company:acme-eu",
      status: "active",
      public_keys: [
        {
          key_id: "acme-eu-ed25519-demo",
          alg: "Ed25519",
          status: "active",
          public_key_pem: publicKeyPem
        }
      ]
    }
  ]
};

const result = sdk.verifyTransportPayload(transport, {
  trustRegistry,
  now: new Date("2026-06-26T00:00:00Z")
});

const tampered = JSON.parse(JSON.stringify(signed));
tampered.document.iban = "BE00 0000 0000 0000";

let tamperRejected = false;
try {
  sdk.verifySignedPayload(tampered, {
    trustRegistry,
    now: new Date("2026-06-26T00:00:00Z")
  });
} catch {
  tamperRejected = true;
}

console.log(JSON.stringify({
  verified: result.ok,
  issuer: result.issuerId,
  document: result.documentId,
  transportPrefix: transport.slice(0, 6),
  tamperRejected
}, null, 2));
