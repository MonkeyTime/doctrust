# Verification flow

1. User scans the QR code or opens the signed document.
2. Application extracts the payload.
3. Application canonicalizes the payload bytes.
4. Application loads the issuer public key from the trust registry.
5. Application verifies the signature locally.
6. Application compares beneficiary name, IBAN, amount, and reference with the active payment context.
7. Application shows a clear result:
   - verified
   - verified but expired
   - untrusted issuer
   - signature invalid

If the verification fails, payment software should stop the transfer or require an explicit override.
