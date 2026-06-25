import json
from pathlib import Path


def load_trust_registry_from_file(file_path: str):
    return json.loads(Path(file_path).read_text(encoding="utf-8"))


def _validate_registry(registry):
    if not isinstance(registry, dict):
        raise TypeError("Trust registry must be a JSON object")
    anchors = registry.get("anchors")
    if not isinstance(anchors, list):
        raise TypeError("Trust registry must contain an anchors array")
    return registry


def resolve_trust_anchor_public_key(registry, issuer):
    validated_registry = _validate_registry(registry)
    anchor = next(
        (item for item in validated_registry["anchors"] if isinstance(item, dict) and item.get("trust_anchor_id") == issuer["trust_anchor_id"]),
        None,
    )
    if anchor is None:
        raise ValueError(f"Unknown trust anchor: {issuer['trust_anchor_id']}")
    if anchor.get("status") != "active":
        raise ValueError(f"Trust anchor is not active: {issuer['trust_anchor_id']}")
    if anchor.get("issuer_id") != issuer["issuer_id"]:
        raise ValueError(f"Issuer mismatch for trust anchor: {issuer['trust_anchor_id']}")

    public_keys = anchor.get("public_keys")
    if not isinstance(public_keys, list) or not public_keys:
        raise ValueError(f"Trust anchor has no public keys: {issuer['trust_anchor_id']}")

    current_key = next((item for item in public_keys if isinstance(item, dict) and item.get("status") == "active"), None)
    if current_key is None or not isinstance(current_key.get("public_key_pem"), str):
        raise ValueError(f"Trust anchor has no active public key: {issuer['trust_anchor_id']}")

    return {
        "trust_anchor_id": anchor["trust_anchor_id"],
        "public_key_pem": current_key["public_key_pem"],
        "key_id": current_key.get("key_id"),
        "algorithm": current_key.get("alg"),
    }
