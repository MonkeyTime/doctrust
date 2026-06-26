# DocTrust Trust Registry Governance v0.1

## 1. Purpose

The trust registry publishes the relationship between an issuer, a trust anchor, and the active public keys that can verify DocTrust payloads.

Its role is not to judge the content of a document, but to answer a narrower question:

- is this key currently authorized for this issuer and trust anchor?

## 2. Operating model

The registry SHOULD be operated by a neutral body such as:

- a consortium
- a foundation
- an association
- another independent governance entity

The technical operator MAY host the infrastructure, but enrollment, status changes, and policy updates MUST follow public rules.

## 3. Governance principles

- explicit issuer binding
- explicit anchor status
- explicit key status
- deterministic local verification
- signed and versioned publication
- offline-capable consumption

## 4. Required data

Each trust anchor entry SHOULD contain:

- `trust_anchor_id`
- `issuer_id`
- `status`
- `public_keys`
- `updated_at`
- `policy_version`

Each public key entry SHOULD contain:

- `key_id`
- `alg`
- `status`
- `public_key_pem`
- `valid_from`
- `valid_to`

## 5. Allowed states

Anchor states:

- `active`
- `suspended`
- `revoked`
- `retired`

Key states:

- `active`
- `rotated`
- `revoked`
- `expired`

Verification software SHOULD accept only keys whose status is `active`, unless a local policy explicitly defines another outcome.

## 6. Enrollment

An issuer MAY be enrolled after:

- administrative validation
- ownership or contractual verification
- initial key publication
- approval under the registry policy

The enrollment process SHOULD be documented and auditable.

## 7. Rotation and revocation

- Key rotation is expected and SHOULD be routine.
- A new key becomes `active`.
- The previous key MAY move to `rotated` or `retired`.
- Revocation MUST be available for key compromise or issuer removal.

Every status change SHOULD be:

- signed
- timestamped
- versioned
- retained in history

## 8. Publication

The registry SHOULD be published as:

- a signed JSON snapshot
- a versioned offline bundle
- optionally a delta feed for incremental updates

Implementations SHOULD be able to cache the registry locally without losing determinism.

## 9. Security requirements

The registry MUST reject or flag:

- anchors without an explicit `issuer_id`
- keys without explicit status
- duplicate `trust_anchor_id` records
- unsigned or malformed updates
- active anchors with no usable active key

## 10. What the registry is not

The registry is not:

- a legal identity authority
- a full KYC service
- proof that an issuer is honest
- a substitute for payment policy

It is a trust publication layer that supports offline verification.

## 11. Recommended verifier behavior

A verifier SHOULD:

1. resolve the anchor by `trust_anchor_id`
2. confirm the `issuer_id` matches
3. require an `active` anchor
4. require an `active` key
5. reject mismatched algorithms or revoked states
6. combine the registry result with the document context before authorizing payment

## 12. Versioning

This governance document is versioned independently from the payload specification.

Substantive changes SHOULD increment the governance version and be announced in the repository releases.
