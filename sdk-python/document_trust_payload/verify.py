import json
from datetime import datetime, timezone

from .canonicalize import canonicalize
from .crypto import base64url_decode, verify_canonical_payload
from .errors import PayloadValidationError, SignatureVerificationError
from .qr import decode_transport_payload
from .trust_registry import resolve_trust_anchor_public_key


def _validate_required_string(value, name):
    if not isinstance(value, str) or not value:
        raise PayloadValidationError(f"Missing or invalid {name}")


def _validate_payload(payload):
    if not isinstance(payload, dict):
        raise PayloadValidationError("Payload must be a JSON object")

    _validate_required_string(payload.get("version"), "version")
    _validate_required_string(payload.get("intent"), "intent")
    _validate_required_string(payload.get("issued_at"), "issued_at")
    _validate_required_string(payload.get("expires_at"), "expires_at")
    _validate_required_string(payload.get("nonce"), "nonce")
    _validate_required_string(payload.get("alg"), "alg")
    _validate_required_string(payload.get("sig"), "sig")

    if payload["version"] != "1":
        raise PayloadValidationError(f"Unsupported version: {payload['version']}")

    issuer = payload.get("issuer")
    if not isinstance(issuer, dict):
        raise PayloadValidationError("Missing or invalid issuer object")

    _validate_required_string(issuer.get("issuer_id"), "issuer.issuer_id")
    _validate_required_string(issuer.get("display_name"), "issuer.display_name")
    _validate_required_string(issuer.get("trust_anchor_id"), "issuer.trust_anchor_id")

    document = payload.get("document")
    if not isinstance(document, dict):
        raise PayloadValidationError("Missing or invalid document object")

    _validate_required_string(document.get("document_id"), "document.document_id")
    return payload


def _validate_payment_profile_payload(payload):
    if not isinstance(payload, dict):
        raise PayloadValidationError("Payload must be a JSON object")

    _validate_required_string(payload.get("version"), "version")
    _validate_required_string(payload.get("intent"), "intent")
    _validate_required_string(payload.get("issued_at"), "issued_at")
    _validate_required_string(payload.get("expires_at"), "expires_at")
    _validate_required_string(payload.get("nonce"), "nonce")
    _validate_required_string(payload.get("alg"), "alg")

    if payload["version"] != "1":
        raise PayloadValidationError(f"Unsupported version: {payload['version']}")

    issuer = payload.get("issuer")
    if not isinstance(issuer, dict):
        raise PayloadValidationError("Missing or invalid issuer object")

    _validate_required_string(issuer.get("issuer_id"), "issuer.issuer_id")
    _validate_required_string(issuer.get("display_name"), "issuer.display_name")
    _validate_required_string(issuer.get("trust_anchor_id"), "issuer.trust_anchor_id")

    document = payload.get("document")
    if not isinstance(document, dict):
        raise PayloadValidationError("Missing or invalid document object")

    _validate_required_string(document.get("document_id"), "document.document_id")
    return payload


def _strip_signature(payload):
    body = dict(payload)
    body.pop("sig", None)
    return body


def _parse_time(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _verify_time_window(payload, now):
    issued_at = _parse_time(payload["issued_at"])
    expires_at = _parse_time(payload["expires_at"])
    current_time = now if isinstance(now, datetime) else _parse_time(now)

    if current_time < issued_at:
        raise PayloadValidationError("Payload is not yet valid")
    if current_time > expires_at:
        raise PayloadValidationError("Payload has expired")


def canonical_payload_body(payload):
    return canonicalize(_strip_signature(_validate_payload(payload)))


def verify_signed_payload(payload, public_key_pem: str | None = None, trust_registry=None, now=None):
    verified_payload = _validate_payload(payload)
    _verify_time_window(verified_payload, now or datetime.now(timezone.utc))

    resolved_key_id = None
    if public_key_pem is None:
        if trust_registry is None:
            raise PayloadValidationError("Missing public_key_pem or trust_registry")
        resolved = resolve_trust_anchor_public_key(trust_registry, verified_payload["issuer"])
        public_key_pem = resolved["public_key_pem"]
        resolved_key_id = resolved.get("key_id")

    canonical_body = canonicalize(_strip_signature(verified_payload)).encode("utf-8")
    signature = base64url_decode(verified_payload["sig"])
    ok = verify_canonical_payload(canonical_body, signature, public_key_pem, verified_payload["alg"])

    if not ok:
        raise SignatureVerificationError("Signature verification failed")

    return {
        "ok": True,
        "issuer_id": verified_payload["issuer"]["issuer_id"],
        "trust_anchor_id": verified_payload["issuer"]["trust_anchor_id"],
        "trust_anchor_key_id": resolved_key_id,
        "document_id": verified_payload["document"]["document_id"],
        "algorithm": verified_payload["alg"],
    }


def verify_transport_payload(transport_payload, public_key_pem: str | None = None, trust_registry=None, now=None):
    payload_json = decode_transport_payload(transport_payload)
    payload = json.loads(payload_json)
    return verify_signed_payload(payload, public_key_pem=public_key_pem, trust_registry=trust_registry, now=now)


def _present(value):
    return value is not None and value != ""


def _compare_expected(actual, expected):
    if expected is None:
        return True
    if isinstance(actual, (int, float)) or isinstance(expected, (int, float)):
        return float(actual) == float(expected)
    return str(actual) == str(expected)


def validate_payment_profile(payload, expected=None):
    verified_payload = _validate_payment_profile_payload(payload)
    document = verified_payload["document"]
    expected = expected or {}

    required_fields = [
        "document_id",
        "document_type",
        "beneficiary_name",
        "iban",
        "amount",
        "currency",
        "reference",
        "due_date",
        "transaction_id",
        "communication",
    ]

    missing_fields = [field for field in required_fields if not _present(document.get(field))]
    mismatches = []

    if verified_payload.get("intent") != "payment":
        mismatches.append("intent")

    if document.get("document_type") != "invoice":
        mismatches.append("document_type")

    for field in [
        "document_type",
        "beneficiary_name",
        "iban",
        "amount",
        "currency",
        "reference",
        "due_date",
        "transaction_id",
        "communication",
    ]:
        if field in expected and not _compare_expected(document.get(field), expected.get(field)):
            mismatches.append(field)

    return {
        "ok": not missing_fields and not mismatches,
        "profile": "payment.invoice",
        "missing_fields": missing_fields,
        "mismatches": mismatches,
    }
