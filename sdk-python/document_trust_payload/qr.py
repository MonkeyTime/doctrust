import base64
import zlib

COMPACT_QR_PREFIX = "dtp1z."
MAX_DECOMPRESSED_BYTES = 1024 * 1024


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
        decompressor = zlib.decompressobj(wbits=-15)
        output = bytearray()
        output.extend(decompressor.decompress(compressed, MAX_DECOMPRESSED_BYTES))
        if decompressor.unconsumed_tail:
            raise ValueError("Compact transport payload is too large")
        output.extend(decompressor.flush(MAX_DECOMPRESSED_BYTES - len(output)))
        if len(output) > MAX_DECOMPRESSED_BYTES or not decompressor.eof:
            raise ValueError("Compact transport payload is too large")
        return output.decode("utf-8")

    return input_value


def is_compact_transport_payload(input_value: str) -> bool:
    return isinstance(input_value, str) and input_value.startswith(COMPACT_QR_PREFIX)
