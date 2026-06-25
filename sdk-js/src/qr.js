import zlib from "node:zlib";

const COMPACT_QR_PREFIX = "dtp1z.";
const MAX_DECOMPRESSED_BYTES = 1024 * 1024;

export function encodeTransportPayload(payloadJson) {
  const compressed = zlib.deflateRawSync(Buffer.from(payloadJson, "utf8"));
  return `${COMPACT_QR_PREFIX}${compressed.toString("base64url")}`;
}

export function decodeTransportPayload(input) {
  if (typeof input !== "string" || input.length === 0) {
    throw new TypeError("Transport payload must be a non-empty string");
  }

  if (input.startsWith(COMPACT_QR_PREFIX)) {
    const compressed = Buffer.from(input.slice(COMPACT_QR_PREFIX.length), "base64url");
    const decoded = zlib.inflateRawSync(compressed, { maxOutputLength: MAX_DECOMPRESSED_BYTES });
    return decoded.toString("utf8");
  }

  return input;
}

export function isCompactTransportPayload(input) {
  return typeof input === "string" && input.startsWith(COMPACT_QR_PREFIX);
}
