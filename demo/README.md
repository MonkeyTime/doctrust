# Reproducible demo

This demo shows the full DocTrust flow:

1. generate an issuer key pair,
2. sign a payment payload,
3. wrap it in the compact QR transport envelope,
4. verify it through the local trust registry,
5. validate the payment profile against expected transfer details,
6. prove tampering is rejected.

## Run it

From the repository root:

```bash
cd sdk-js
node ../demo/repro.mjs
```

## What it demonstrates

- canonical payload signing
- trust registry resolution
- compact QR transport encoding
- payment profile validation
- verification failure on tampering
