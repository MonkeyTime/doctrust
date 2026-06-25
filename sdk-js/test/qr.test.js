import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { encodeTransportPayload, decodeTransportPayload, isCompactTransportPayload, signPayload, verifyTransportPayload } from "../src/index.js";

test("encodes and decodes compact transport payloads", () => {
  const json = '{"hello":"world","n":1}';
  const compact = encodeTransportPayload(json);

  assert.equal(isCompactTransportPayload(compact), true);
  assert.equal(decodeTransportPayload(compact), json);
});

test("passes through raw json transport payloads", () => {
  const json = '{"hello":"world"}';
  assert.equal(isCompactTransportPayload(json), false);
  assert.equal(decodeTransportPayload(json), json);
});

test("verifies compact transport payloads end to end", () => {
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
  const transport = encodeTransportPayload(JSON.stringify(signed));
  const result = verifyTransportPayload(transport, { publicKeyPem, now: new Date("2026-06-26T00:00:00Z") });

  assert.equal(result.ok, true);
  assert.equal(result.documentId, "INV-2026-000184");
});

test("rejects oversized compact transport payloads", () => {
  const oversizedJson = `"${"A".repeat(1024 * 1024 + 1)}"`;
  const compact = encodeTransportPayload(oversizedJson);

  assert.throws(() => decodeTransportPayload(compact));
});
