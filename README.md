# DocTrust

Signed payloads for invoices and payment instructions.

Project page: https://monkeytime.github.io/doctrust/

DocTrust is a small open standard draft for embedding machine-verifiable proof into documents and QR codes. It aims to help software detect tampering of critical fields such as IBAN, beneficiary name, amount, and payment reference before a transfer is approved.

## Why it exists

Email and PDF workflows are easy to imitate. DocTrust adds a signed payload and a trust registry so verification software can check:

- who issued the document,
- whether the payload changed,
- whether the issuer key is trusted,
- whether the payment details match the expected transaction.

## Current scope

- signed JSON payloads
- QR transport with a compact `dtp1z.` envelope
- local trust registry lookup
- reference SDKs in JavaScript, Python, and .NET
- minimal invoice and payment profiles

## What it is not

- a replacement for legal identity verification
- a general anti-phishing cure
- proof that an issuer is honest

## Repository layout

- `spec/` - protocol and format specification
- `governance/` - trust registry governance and operating model
- `schemas/` - machine-readable schemas
- `conformance/` - versioned conformance vectors
- `examples/` - payload and registry examples
- `sdk-js/` - JavaScript reference SDK
- `sdk-python/` - Python reference SDK
- `sdk-dotnet/` - .NET reference SDK
- `SECURITY.md` - vulnerability disclosure policy

## Getting started

1. Read the protocol in `spec/v1.md`.
2. Inspect the sample payload in `examples/invoice.json`.
3. Run the reference SDK tests in each language folder.

## Status

This repository is early-stage but executable. The current focus is to tighten the specification, keep the SDKs aligned, and add conformance tests and integration examples.

## Releases

- [0.1.0 notes](RELEASES/0.1.0.md)
- [0.2.0 notes](RELEASES/0.2.0.md)
