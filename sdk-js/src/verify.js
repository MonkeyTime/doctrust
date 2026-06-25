import { canonicalize } from "./canonicalize.js";
import { base64UrlDecode, verifyCanonicalPayload } from "./crypto.js";
import { PayloadValidationError, SignatureVerificationError } from "./errors.js";
import { resolveTrustAnchorPublicKey } from "./trust-registry.js";
import { decodeTransportPayload } from "./qr.js";

function validateRequiredString(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    throw new PayloadValidationError(`Missing or invalid ${name}`);
  }
}

function validateDocumentPaymentField(document, fieldName) {
  const value = document[fieldName];
  if (value === undefined || value === null || value === "") {
    return false;
  }
  return true;
}

function compareExpectedValue(actual, expected) {
  if (expected === undefined) {
    return true;
  }

  if (typeof actual === "number" || typeof expected === "number") {
    return Number(actual) === Number(expected);
  }

  return String(actual) === String(expected);
}

function validatePayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new PayloadValidationError("Payload must be a JSON object");
  }

  validateRequiredString(payload.version, "version");
  validateRequiredString(payload.intent, "intent");
  validateRequiredString(payload.issued_at, "issued_at");
  validateRequiredString(payload.expires_at, "expires_at");
  validateRequiredString(payload.nonce, "nonce");
  validateRequiredString(payload.alg, "alg");
  validateRequiredString(payload.sig, "sig");

  if (payload.version !== "1") {
    throw new PayloadValidationError(`Unsupported version: ${payload.version}`);
  }

  if (!payload.issuer || typeof payload.issuer !== "object" || Array.isArray(payload.issuer)) {
    throw new PayloadValidationError("Missing or invalid issuer object");
  }

  validateRequiredString(payload.issuer.issuer_id, "issuer.issuer_id");
  validateRequiredString(payload.issuer.display_name, "issuer.display_name");
  validateRequiredString(payload.issuer.trust_anchor_id, "issuer.trust_anchor_id");

  if (!payload.document || typeof payload.document !== "object" || Array.isArray(payload.document)) {
    throw new PayloadValidationError("Missing or invalid document object");
  }

  validateRequiredString(payload.document.document_id, "document.document_id");

  return payload;
}

function validatePaymentProfilePayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new PayloadValidationError("Payload must be a JSON object");
  }

  validateRequiredString(payload.version, "version");
  validateRequiredString(payload.intent, "intent");
  validateRequiredString(payload.issued_at, "issued_at");
  validateRequiredString(payload.expires_at, "expires_at");
  validateRequiredString(payload.nonce, "nonce");
  validateRequiredString(payload.alg, "alg");

  if (payload.version !== "1") {
    throw new PayloadValidationError(`Unsupported version: ${payload.version}`);
  }

  if (!payload.issuer || typeof payload.issuer !== "object" || Array.isArray(payload.issuer)) {
    throw new PayloadValidationError("Missing or invalid issuer object");
  }

  validateRequiredString(payload.issuer.issuer_id, "issuer.issuer_id");
  validateRequiredString(payload.issuer.display_name, "issuer.display_name");
  validateRequiredString(payload.issuer.trust_anchor_id, "issuer.trust_anchor_id");

  if (!payload.document || typeof payload.document !== "object" || Array.isArray(payload.document)) {
    throw new PayloadValidationError("Missing or invalid document object");
  }

  validateRequiredString(payload.document.document_id, "document.document_id");

  return payload;
}

function stripSignature(payload) {
  const { sig, ...body } = payload;
  return body;
}

function verifyTimeWindow(payload, now) {
  const issuedAt = Date.parse(payload.issued_at);
  const expiresAt = Date.parse(payload.expires_at);
  const currentTime = now instanceof Date ? now.getTime() : Date.parse(now);

  if (Number.isNaN(issuedAt) || Number.isNaN(expiresAt) || Number.isNaN(currentTime)) {
    throw new PayloadValidationError("Invalid timestamp in payload");
  }

  if (currentTime < issuedAt) {
    throw new PayloadValidationError("Payload is not yet valid");
  }

  if (currentTime > expiresAt) {
    throw new PayloadValidationError("Payload has expired");
  }
}

export function canonicalPayloadBody(payload) {
  return canonicalize(stripSignature(validatePayload(payload)));
}

export function verifySignedPayload(payload, options = {}) {
  const verifiedPayload = validatePayload(payload);
  verifyTimeWindow(verifiedPayload, options.now ?? new Date());

  let publicKeyPem = options.publicKeyPem;
  let trustAnchorKeyId = null;

  if (!publicKeyPem) {
    const trustRegistry = options.trustRegistry;
    if (!trustRegistry) {
      throw new PayloadValidationError("Missing publicKeyPem or trustRegistry option");
    }

    const resolved = resolveTrustAnchorPublicKey(trustRegistry, verifiedPayload.issuer);
    publicKeyPem = resolved.publicKeyPem;
    trustAnchorKeyId = resolved.keyId;
  }

  const canonicalBody = canonicalize(stripSignature(verifiedPayload));
  const signature = base64UrlDecode(verifiedPayload.sig);
  const ok = verifyCanonicalPayload(canonicalBody, signature, publicKeyPem, verifiedPayload.alg);

  if (!ok) {
    throw new SignatureVerificationError("Signature verification failed");
  }

  return {
    ok: true,
    issuerId: verifiedPayload.issuer.issuer_id,
    trustAnchorId: verifiedPayload.issuer.trust_anchor_id,
    trustAnchorKeyId,
    documentId: verifiedPayload.document.document_id,
    algorithm: verifiedPayload.alg
  };
}

export function verifyTransportPayload(transportPayload, options = {}) {
  const payloadJson = decodeTransportPayload(transportPayload);
  const payload = JSON.parse(payloadJson);
  return verifySignedPayload(payload, options);
}

export function validatePaymentProfile(payload, expected = {}) {
  const verifiedPayload = validatePaymentProfilePayload(payload);
  const document = verifiedPayload.document;

  const requiredFields = [
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
  ];

  const missingFields = requiredFields.filter((field) => !validateDocumentPaymentField(document, field));
  const mismatches = [];

  if (verifiedPayload.intent !== "payment") {
    mismatches.push("intent");
  }

  if (document.document_type !== "invoice") {
    mismatches.push("document_type");
  }

  const comparisons = [
    ["document_type", expected.document_type],
    ["beneficiary_name", expected.beneficiary_name],
    ["iban", expected.iban],
    ["amount", expected.amount],
    ["currency", expected.currency],
    ["reference", expected.reference],
    ["due_date", expected.due_date],
    ["transaction_id", expected.transaction_id],
    ["communication", expected.communication]
  ];

  for (const [field, expectedValue] of comparisons) {
    if (expectedValue !== undefined && !compareExpectedValue(document[field], expectedValue)) {
      mismatches.push(field);
    }
  }

  const ok = missingFields.length === 0 && mismatches.length === 0;

  return {
    ok,
    profile: "payment.invoice",
    missingFields,
    mismatches
  };
}
