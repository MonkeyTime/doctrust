# Contributing

Thanks for helping improve DocTrust.

## What to work on

- spec clarifications
- interoperability tests
- SDK parity between JavaScript, Python, and .NET
- demo flows and documentation
- trust registry and verification profiles
- payment profile validation and conformance vectors

## Before you open a pull request

1. Read `spec/v1.md`.
2. Check whether the change affects the canonical payload or the trust model.
3. Check whether the change affects the invoice or payment profile.
4. Add or update a test when behavior changes.
5. Keep examples small and reproducible.

## Local checks

- JavaScript SDK: `cd sdk-js && node --test`
- Python SDK: `cd sdk-python && python -m unittest discover -s tests`
- .NET SDK: `cd sdk-dotnet && dotnet run --project tests/DocumentTrustPayload.Tests.csproj -p:UseSharedCompilation=false`

## Style

- Keep files ASCII unless the file already uses non-ASCII.
- Prefer small, focused commits.
- When changing the spec, update the examples and the relevant SDK behavior together.

## Release work

Releases should include:

- a tagged version
- release notes
- at least one reproducible demo path
- passing reference tests
- a short changelog entry for spec, SDK, and demo changes
