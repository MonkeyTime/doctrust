import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { signPayload, verifySignedPayload } from "../src/index.js";

test("verifies using a trust registry", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" });
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" });

  const payload = {
    version: "1",
    issuer: {
      issuer_id: "company:acme-eu",
      display_name: "ACME Europe SARL",
      trust_anchor_id: "registry:acme-trust-root"
    },
    document: {
      document_id: "INV-2026-000184"
    },
    intent: "payment",
    issued_at: "2026-06-25T10:00:00Z",
    expires_at: "2026-07-15T23:59:59Z",
    nonce: "6f7a1d8c4f2b4b4b8f0a",
    alg: "Ed25519"
  };

  const signed = signPayload(payload, privateKeyPem);
  const trustRegistry = {
    version: "1",
    anchors: [
      {
        trust_anchor_id: "registry:acme-trust-root",
        issuer_id: "company:acme-eu",
        status: "active",
        public_keys: [
          {
            key_id: "acme-eu-ed25519-2026-06",
            alg: "Ed25519",
            status: "active",
            public_key_pem: publicKeyPem
          }
        ]
      }
    ]
  };

  const result = verifySignedPayload(signed, {
    trustRegistry,
    now: new Date("2026-06-26T00:00:00Z")
  });

  assert.equal(result.ok, true);
  assert.equal(result.trustAnchorId, "registry:acme-trust-root");
  assert.equal(result.trustAnchorKeyId, "acme-eu-ed25519-2026-06");
});
