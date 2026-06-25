# Conformance Vectors

This directory contains versioned, reproducible fixtures for DocTrust v0.2.0.

## Purpose

- give SDKs a shared test corpus,
- make expected behavior explicit,
- reduce drift between JavaScript, Python, and .NET,
- document the boundary between valid and invalid payment profiles.

## Contents

- `v0.2.0/manifest.json` - machine-readable summary of each vector
- `v0.2.0/*.json` - sample payloads and expected outcomes

## How to use them

Implementations should read the manifest, load each vector, and compare the observed result with the expected result.
