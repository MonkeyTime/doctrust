# Security considerations

## Threats addressed

- IBAN replacement in invoices
- Beneficiary name tampering
- Document re-signing by an unauthorized party
- Replay of stale or expired payment instructions

## Threats not fully addressed

- A user trusting the wrong issuer
- Fraudulent issuer enrollment
- Compromised private keys
- Social engineering outside the signed payload

## Required safeguards

- Key revocation
- Expiration
- Trust registry auditability
- Strong issuer enrollment
- Clear verifier UI

## Implementation warning

Do not treat the QR code as a source of truth by itself. The QR code is only a transport layer for a signed payload.
