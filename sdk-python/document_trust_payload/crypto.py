import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def sign_canonical_payload(canonical_bytes: bytes, private_key_pem: str, algorithm: str) -> bytes:
    key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)

    if algorithm == "Ed25519":
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise ValueError("Expected Ed25519 private key")
        return key.sign(canonical_bytes)

    if algorithm == "ES256":
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("Expected EC private key")
        return key.sign(canonical_bytes, ec.ECDSA(hashes.SHA256()))

    raise ValueError(f"Unsupported algorithm: {algorithm}")


def verify_canonical_payload(canonical_bytes: bytes, signature: bytes, public_key_pem: str, algorithm: str) -> bool:
    key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))

    try:
        if algorithm == "Ed25519":
            if not isinstance(key, ed25519.Ed25519PublicKey):
                raise ValueError("Expected Ed25519 public key")
            key.verify(signature, canonical_bytes)
            return True

        if algorithm == "ES256":
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise ValueError("Expected EC public key")
            key.verify(signature, canonical_bytes, ec.ECDSA(hashes.SHA256()))
            return True

        raise ValueError(f"Unsupported algorithm: {algorithm}")
    except Exception:
        return False
