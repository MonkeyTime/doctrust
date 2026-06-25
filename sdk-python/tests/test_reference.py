import json
import unittest
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from document_trust_payload import (
    encode_transport_payload,
    decode_transport_payload,
    is_compact_transport_payload,
    sign_payload,
    validate_payment_profile,
    verify_signed_payload,
    verify_transport_payload,
)


def _private_pem(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _public_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.private_key_pem = _private_pem(self.private_key)
        self.public_key_pem = _public_pem(self.public_key)
        self.payload = {
            "version": "1",
            "issuer": {
                "issuer_id": "company:acme-eu",
                "display_name": "ACME Europe SARL",
                "trust_anchor_id": "registry:acme-trust-root",
            },
            "document": {
                "document_id": "INV-2026-000184",
                "document_type": "invoice",
                "beneficiary_name": "ACME Europe SARL",
                "iban": "BE68 5390 0754 7034",
                "amount": 1499.95,
                "currency": "EUR",
                "reference": "RF18539007547034",
                "due_date": "2026-07-15",
                "transaction_id": "TX-2026-06-25-000184",
                "communication": "Invoice INV-2026-000184",
            },
            "intent": "payment",
            "issued_at": "2026-06-25T10:00:00Z",
            "expires_at": "2026-07-15T23:59:59Z",
            "nonce": "6f7a1d8c4f2b4b4b8f0a",
            "alg": "Ed25519",
        }

    def test_sign_and_verify(self):
        signed = sign_payload(self.payload, self.private_key_pem)
        result = verify_signed_payload(signed, public_key_pem=self.public_key_pem, now=datetime(2026, 6, 26, tzinfo=timezone.utc))
        self.assertTrue(result["ok"])
        self.assertEqual(result["document_id"], "INV-2026-000184")

    def test_qr_compact_roundtrip(self):
        signed = sign_payload(self.payload, self.private_key_pem)
        compact_json = json.dumps(signed, separators=(",", ":"))
        transport = encode_transport_payload(compact_json)
        self.assertTrue(is_compact_transport_payload(transport))
        self.assertEqual(decode_transport_payload(transport), compact_json)
        result = verify_transport_payload(transport, public_key_pem=self.public_key_pem, now=datetime(2026, 6, 26, tzinfo=timezone.utc))
        self.assertTrue(result["ok"])

    def test_rejects_tampering(self):
        signed = sign_payload(self.payload, self.private_key_pem)
        signed["document"]["iban"] = "BE00 0000 0000 0000"
        with self.assertRaises(Exception):
            verify_signed_payload(signed, public_key_pem=self.public_key_pem, now=datetime(2026, 6, 26, tzinfo=timezone.utc))

    def test_validate_payment_profile(self):
        result = validate_payment_profile(self.payload, {
            "beneficiary_name": "ACME Europe SARL",
            "iban": "BE68 5390 0754 7034",
            "amount": 1499.95,
            "currency": "EUR",
            "reference": "RF18539007547034",
            "due_date": "2026-07-15",
            "transaction_id": "TX-2026-06-25-000184",
            "communication": "Invoice INV-2026-000184",
        })
        self.assertTrue(result["ok"])
        self.assertEqual(result["missing_fields"], [])
        self.assertEqual(result["missing_expected_fields"], [])
        self.assertEqual(result["mismatches"], [])

    def test_rejects_unsafe_numeric_coercion(self):
        payload = dict(self.payload)
        payload["document"] = dict(self.payload["document"])
        payload["document"]["amount"] = "9007199254740993"
        result = validate_payment_profile(payload, {
            "beneficiary_name": "ACME Europe SARL",
            "iban": "BE68 5390 0754 7034",
            "amount": 9007199254740992,
            "currency": "EUR",
            "reference": "RF18539007547034",
            "due_date": "2026-07-15",
            "transaction_id": "TX-2026-06-25-000184",
            "communication": "Invoice INV-2026-000184",
        })
        self.assertFalse(result["ok"])
        self.assertEqual(result["mismatches"], ["amount"])
        self.assertEqual(result["missing_expected_fields"], [])

    def test_rejects_oversized_compact_payloads(self):
        compact = encode_transport_payload('"' + ("A" * (1024 * 1024 + 1)) + '"')
        with self.assertRaises(Exception):
            decode_transport_payload(compact)

    def test_rejects_missing_issuer_binding_in_trust_registry(self):
        signed = sign_payload(self.payload, self.private_key_pem)
        trust_registry = {
            "version": "1",
            "anchors": [
                {
                    "trust_anchor_id": "registry:acme-trust-root",
                    "status": "active",
                    "public_keys": [
                        {
                            "key_id": "acme-eu-ed25519-2026-06",
                            "alg": "Ed25519",
                            "status": "active",
                            "public_key_pem": self.public_key_pem,
                        }
                    ],
                }
            ],
        }
        with self.assertRaises(Exception):
            verify_signed_payload(signed, trust_registry=trust_registry, now=datetime(2026, 6, 26, tzinfo=timezone.utc))


if __name__ == "__main__":
    unittest.main()
