import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { signPayload, verifySignedPayload, canonicalize, validatePaymentProfile } from "../src/index.js";

test("canonicalize sorts object keys", () => {
  const value = { b: 1, a: { d: 4, c: 3 } };
  assert.equal(canonicalize(value), '{"a":{"c":3,"d":4},"b":1}');
});

test("signs and verifies an Ed25519 payload", () => {
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
      document_id: "INV-2026-000184",
      beneficiary_name: "ACME Europe SARL",
      iban: "BE68 5390 0754 7034",
      amount: 1499.95,
      currency: "EUR",
      reference: "RF18539007547034"
    },
    intent: "payment",
    issued_at: "2026-06-25T10:00:00Z",
    expires_at: "2026-07-15T23:59:59Z",
    nonce: "6f7a1d8c4f2b4b4b8f0a",
    alg: "Ed25519"
  };

  const signed = signPayload(payload, privateKeyPem);
  const result = verifySignedPayload(signed, { publicKeyPem, now: new Date("2026-06-26T00:00:00Z") });

  assert.equal(result.ok, true);
  assert.equal(result.issuerId, "company:acme-eu");
  assert.equal(result.documentId, "INV-2026-000184");
});

test("rejects tampered fields", () => {
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
  signed.document.document_id = "INV-2026-999999";

  assert.throws(() => verifySignedPayload(signed, { publicKeyPem }), /Signature verification failed/);
});

test("validates payment profile fields", () => {
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
    nonce: "6f7a1d8c4f2b4b4b8f0a",
    alg: "Ed25519"
  };

  const result = validatePaymentProfile(payload, {
    beneficiary_name: "ACME Europe SARL",
    iban: "BE68 5390 0754 7034",
    amount: 1499.95,
    currency: "EUR",
    reference: "RF18539007547034",
    transaction_id: "TX-2026-06-25-000184"
  });

  assert.equal(result.ok, true);
  assert.deepEqual(result.mismatches, []);
  assert.deepEqual(result.missingFields, []);
});
