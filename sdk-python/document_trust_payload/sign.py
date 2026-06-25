from .canonicalize import canonicalize
from .crypto import base64url_encode, sign_canonical_payload
from .errors import PayloadValidationError


def _strip_signature(payload):
    body = dict(payload)
    body.pop("sig", None)
    return body


def sign_payload(payload, private_key_pem: str):
    if not isinstance(payload, dict):
        raise PayloadValidationError("Payload must be a JSON object")

    algorithm = payload.get("alg")
    if not isinstance(algorithm, str) or not algorithm:
        raise PayloadValidationError("Missing alg")

    canonical_body = canonicalize(_strip_signature(payload))
    signature = sign_canonical_payload(canonical_body.encode("utf-8"), private_key_pem, algorithm)
    signed = _strip_signature(payload)
    signed["sig"] = base64url_encode(signature)
    return signed
