import crypto from "node:crypto";

export function base64UrlEncode(buffer) {
  return Buffer.from(buffer).toString("base64url");
}

export function base64UrlDecode(value) {
  return Buffer.from(value, "base64url");
}

export function signCanonicalPayload(canonicalBytes, privateKeyPem, algorithm) {
  const key = crypto.createPrivateKey(privateKeyPem);

  if (algorithm === "Ed25519") {
    return crypto.sign(null, Buffer.from(canonicalBytes), key);
  }

  if (algorithm === "ES256") {
    const signer = crypto.createSign("sha256");
    signer.update(canonicalBytes);
    signer.end();
    return signer.sign(key);
  }

  throw new Error(`Unsupported algorithm: ${algorithm}`);
}

export function verifyCanonicalPayload(canonicalBytes, signature, publicKeyPem, algorithm) {
  const key = crypto.createPublicKey(publicKeyPem);

  if (algorithm === "Ed25519") {
    return crypto.verify(null, Buffer.from(canonicalBytes), key, signature);
  }

  if (algorithm === "ES256") {
    const verifier = crypto.createVerify("sha256");
    verifier.update(canonicalBytes);
    verifier.end();
    return verifier.verify(key, signature);
  }

  throw new Error(`Unsupported algorithm: ${algorithm}`);
}
