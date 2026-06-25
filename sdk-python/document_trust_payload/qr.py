import base64
import zlib

COMPACT_QR_PREFIX = "dtp1z."


def encode_transport_payload(payload_json: str) -> str:
    compressed = zlib.compress(payload_json.encode("utf-8"), level=9, wbits=-15)
    return COMPACT_QR_PREFIX + base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")


def decode_transport_payload(input_value: str) -> str:
    if not isinstance(input_value, str) or not input_value:
        raise TypeError("Transport payload must be a non-empty string")

    if input_value.startswith(COMPACT_QR_PREFIX):
        encoded = input_value[len(COMPACT_QR_PREFIX) :]
        padding = "=" * (-len(encoded) % 4)
        compressed = base64.urlsafe_b64decode(encoded + padding)
        return zlib.decompress(compressed, wbits=-15).decode("utf-8")

    return input_value


def is_compact_transport_payload(input_value: str) -> bool:
    return isinstance(input_value, str) and input_value.startswith(COMPACT_QR_PREFIX)
