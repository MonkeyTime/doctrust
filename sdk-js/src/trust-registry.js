import { readFileSync } from "node:fs";

export function loadTrustRegistryFromFile(filePath) {
  const raw = readFileSync(filePath, "utf8");
  return JSON.parse(raw);
}

function validateRegistryObject(registry) {
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) {
    throw new TypeError("Trust registry must be a JSON object");
  }

  if (!Array.isArray(registry.anchors)) {
    throw new TypeError("Trust registry must contain an anchors array");
  }

  return registry;
}

export function resolveTrustAnchorPublicKey(registry, issuer) {
  const validatedRegistry = validateRegistryObject(registry);
  const anchor = validatedRegistry.anchors.find(
    (item) => item && item.trust_anchor_id === issuer.trust_anchor_id
  );

  if (!anchor) {
    throw new Error(`Unknown trust anchor: ${issuer.trust_anchor_id}`);
  }

  if (anchor.status !== "active") {
    throw new Error(`Trust anchor is not active: ${issuer.trust_anchor_id}`);
  }

  if (anchor.issuer_id !== issuer.issuer_id) {
    throw new Error(`Issuer mismatch for trust anchor: ${issuer.trust_anchor_id}`);
  }

  if (!Array.isArray(anchor.public_keys) || anchor.public_keys.length === 0) {
    throw new Error(`Trust anchor has no public keys: ${issuer.trust_anchor_id}`);
  }

  const currentKey = anchor.public_keys.find((key) => key && key.status === "active");

  if (!currentKey || typeof currentKey.public_key_pem !== "string") {
    throw new Error(`Trust anchor has no active public key: ${issuer.trust_anchor_id}`);
  }

  return {
    trustAnchorId: anchor.trust_anchor_id,
    publicKeyPem: currentKey.public_key_pem,
    keyId: currentKey.key_id ?? null,
    algorithm: currentKey.alg ?? null
  };
}
