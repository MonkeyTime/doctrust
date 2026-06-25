import { canonicalize } from "./canonicalize.js";
import { base64UrlEncode, signCanonicalPayload } from "./crypto.js";
import { PayloadValidationError } from "./errors.js";

function stripSignature(payload) {
  const { sig, ...body } = payload;
  return body;
}

export function signPayload(payload, privateKeyPem) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new PayloadValidationError("Payload must be a JSON object");
  }

  if (typeof payload.alg !== "string" || payload.alg.length === 0) {
    throw new PayloadValidationError("Missing alg");
  }

  const canonicalBody = canonicalize(stripSignature(payload));
  const signature = signCanonicalPayload(canonicalBody, privateKeyPem, payload.alg);

  return {
    ...stripSignature(payload),
    sig: base64UrlEncode(signature)
  };
}
