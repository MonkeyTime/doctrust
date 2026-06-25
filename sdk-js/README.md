# JavaScript SDK

Reference SDK for encoding and verifying Document Trust Payload messages.

Included:

- canonical JSON serialization
- signature generation and verification
- a small CLI verifier
- local trust registry integration points
- compact QR transport helpers
- invoice profile guidance
- payment profile guidance

The trust registry is currently a simple JSON file containing anchors and active public keys. See [examples/trust-registry.json](/C:/Users/admin/Documents/antisocialengineering/examples/trust-registry.json).

The compact QR transport uses the `dtp1z.` prefix plus base64url-encoded zlib-compressed JSON.

Use `verifyTransportPayload(...)` when the input is a QR transport string rather than a parsed JSON object.

CLI examples:

- `dtp-verify payload.json --public-key issuer.pem`
- `dtp-verify payload.json --registry trust-registry.json`

Run the tests from this folder with `npm test`.
