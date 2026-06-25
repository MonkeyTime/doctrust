import json
from typing import Any


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not (value == value and value not in (float("inf"), float("-inf"))):
            raise TypeError("Payload contains a non-finite number")
        return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_serialize(item) for item in value) + "]"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value.keys()):
            item = value[key]
            parts.append(f"{json.dumps(str(key), ensure_ascii=False)}:{_serialize(item)}")
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"Unsupported payload value type: {type(value).__name__}")


def canonicalize(value: Any) -> str:
    return _serialize(value)
