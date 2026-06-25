function normalizeNumber(value) {
  if (!Number.isFinite(value)) {
    throw new TypeError("Payload contains a non-finite number");
  }
  return JSON.stringify(value);
}

function serialize(value) {
  if (value === null) {
    return "null";
  }

  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "number":
      return normalizeNumber(value);
    case "boolean":
      return value ? "true" : "false";
    case "object":
      if (Array.isArray(value)) {
        return `[${value.map((item) => serialize(item)).join(",")}]`;
      }

      {
        const keys = Object.keys(value).sort();
        const pairs = [];
        for (const key of keys) {
          const item = value[key];
          if (item === undefined) {
            continue;
          }
          pairs.push(`${JSON.stringify(key)}:${serialize(item)}`);
        }
        return `{${pairs.join(",")}}`;
      }
    default:
      throw new TypeError(`Unsupported payload value type: ${typeof value}`);
  }
}

export function canonicalize(value) {
  return serialize(value);
}
