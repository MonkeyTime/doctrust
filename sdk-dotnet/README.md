# .NET SDK

Reference SDK for encoding and verifying Document Trust Payload messages.

Initial scope:

- canonical JSON serialization
- signature generation and verification for `ES256` and `Ed25519`
- compact QR transport encoding and decoding
- local trust registry lookup
- invoice profile guidance
- payment profile guidance

The current .NET reference project is implemented as a small library plus a console-style test harness in `tests/`.

Run it with:

```bash
dotnet run --project tests/DocumentTrustPayload.Tests.csproj
```
