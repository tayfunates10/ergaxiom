# Capability Runtime v1

## Purpose

The Capability Runtime converts a short-lived signed token into one narrowly scoped authorization receipt. It replaces the unsafe assumption that a token identifier written in an Operator Plan is sufficient authority to control an application, file, network endpoint or secret.

A token is accepted only when its cryptographic signature, immutable bindings, subject, time window, usage counter and grant all pass deterministic checks.

## Signed token structure

Capability Token schema `0.1.0` separates:

- `payload`: the canonical data covered by the signature;
- `signature`: an Ed25519 signature encoded as unpadded base64url.

The payload contains:

- token, issuer and key identifiers;
- executor and optional device binding;
- issue, not-before and expiry times as epoch seconds;
- maximum authorized uses;
- a nonce;
- exact Work Contract, Profession Capsule and Operator Plan digests;
- exact plan step and operator identifiers;
- one capability, resource, access and constraint grant.

## Canonical signing bytes

The Proof Kernel now exports `canonical_json_bytes`. Hashing and signature verification therefore share the same recursive object-key ordering and JSON serialization implementation.

A producer signs the canonical JSON bytes of `payload`. The signature does not cover a differently formatted representation and does not depend on source-file whitespace or object-key insertion order.

## Trusted key registry

The runtime accepts Ed25519 public keys only through a local trusted-key registry indexed by:

```text
issuer_id + key_id
```

A key supplied inside the token is never trusted. Unknown issuer/key combinations fail closed.

Key rotation, revocation and transparency-log distribution are deferred, but the API is structured so those checks can be added before signature acceptance.

## Authorization pipeline

1. Decode the signed token.
2. Require the supported token schema version.
3. Check nonce length and usage bounds.
4. Resolve the issuer/key pair from the trusted registry.
5. Canonically serialize the payload.
6. Decode and verify the Ed25519 signature.
7. Validate issue, not-before and expiry times against a trusted clock supplied by the caller.
8. Match contract and capsule digests.
9. Match plan ID and canonical plan digest.
10. Resolve the exact plan step.
11. Match the operator and require the token ID to be declared by that step.
12. Match the active executor and device.
13. Require the grant to exactly equal one sealed Work Contract permission.
14. Reject token-ID reuse with a different signed token digest.
15. Enforce the maximum-use counter.
16. Produce an immutable authorization receipt and increment usage.

Usage is consumed only after every preceding check succeeds.

## Grant non-escalation

The Contract Runtime now carries the Work Contract permission list into `CompiledContract`. A token grant must exactly match:

- capability;
- resource;
- access mode;
- constraint object.

A correctly signed token is therefore still rejected when its issuer attempts to grant broader access than the sealed Work Contract permits.

## Replay and identity controls

Usage state is indexed by issuer and token ID. The first accepted token digest is pinned to that identity.

- Reusing the same signed token is permitted only up to `max_uses`.
- Re-signing a different payload with the same issuer/token ID is rejected as a token-ID collision.
- Executor or device mismatch is rejected before usage is consumed.

## Authorization receipt

A successful decision records:

- canonical full-token and payload digests;
- issuer and key identifiers;
- executor and device;
- plan, step and operator;
- exact grant;
- trusted authorization time;
- current use number and maximum uses.

Future trace versions will bind each execution event to the authorization-receipt digest instead of trusting a free token identifier.

## Security tests

The integration suite covers:

- valid signed authorization;
- payload tampering after signing;
- correctly signed permission escalation;
- wrong plan digest;
- expired token;
- replay beyond maximum uses;
- issuer reuse of a token ID for a different payload;
- executor and device mismatch.

## Deferred capabilities

Future versions will add:

- key revocation and validity windows;
- signed trusted-clock attestations;
- authorization-receipt binding in execution traces;
- wildcard and subset-safe resource constraint evaluation;
- secret-use receipts without exposing secret values;
- organization policy overlays;
- hardware-backed device and executor identities.
