# Attestation Runtime v1

## Purpose

Attestation Runtime turns an independently accepted Evidence Bundle into two durable audit artifacts:

- a deterministic Replay Manifest;
- an Ed25519-signed Acceptance Certificate.

The runtime never accepts a caller-supplied success assessment. Certificate issuance calls Evidence Runtime itself, which re-verifies authorized execution and recomputes Proof Kernel acceptance.

## Issuance pipeline

1. Validate non-empty manifest, certificate, issuer and key identifiers.
2. Re-run Evidence Runtime against the sealed Work Contract, Operator Plan and Evidence Bundle.
3. Refuse issuance unless the recomputed decision is `ACCEPTED`.
4. Refuse accepted assessments containing mandatory failed or unknown counts.
5. Decode the independently accepted Evidence Bundle.
6. Build a deterministic Replay Manifest.
7. Canonically hash the Replay Manifest.
8. Build an Acceptance Certificate payload bound to the manifest and accepted bundle.
9. Sign canonical certificate-payload bytes with Ed25519.

## Replay Manifest contents

The manifest binds:

- Work Contract digest;
- Profession Capsule digest;
- Operator Plan ID and digest;
- Evidence Bundle ID, run ID and canonical digest;
- Authorized Execution Trace digest;
- environment digest;
- sorted artifact digest inventory;
- sorted authorization-receipt digests;
- sorted proof-evidence IDs;
- expected decision and verified assurance;
- mandatory passed, failed and unknown counts.

Artifact, receipt and proof inventories are sorted before serialization. The same accepted run and manifest ID therefore produce the same Replay Manifest independent of certificate ID or issuance time.

## Acceptance Certificate contents

The signed payload binds:

- certificate issuer and trusted key ID;
- issuance epoch;
- contract, capsule and plan seals;
- bundle and authorized-trace digests;
- Replay Manifest digest;
- assurance level;
- mandatory proof counters;
- decision `ACCEPTED`.

Schema `0.1.0` requires failed and unknown mandatory counts to be zero.

## Verification levels

### Cryptographic package verification

`verify_attestation`:

- resolves the issuer/key from a local trusted registry;
- verifies the Ed25519 signature over canonical payload bytes;
- recomputes the Replay Manifest digest;
- compares all duplicated manifest/payload bindings;
- rejects non-accepted decisions or invalid counters;
- returns canonical certificate and manifest digests.

### Source-bound verification

`verify_attestation_against_bundle` additionally:

- re-runs Evidence Runtime against the supplied bundle and plan;
- rebuilds the Replay Manifest from live sources;
- requires the recomputed manifest to equal the certified manifest byte-for-byte.

## Fail-closed invariants

- A `BLOCKED` or `REJECTED` bundle cannot receive a certificate.
- A caller cannot bypass assessment by supplying a precomputed decision.
- Bundle mutation after issuance invalidates source-bound verification.
- Replay Manifest mutation breaks its certificate digest binding.
- Certificate payload mutation breaks the Ed25519 signature.
- Unknown issuer keys are rejected.
- Accepted certificates cannot contain failed or unknown mandatory obligations.
- The certificate cannot silently refer to another contract, capsule, plan, bundle or trace.

## Phase 1 significance

Together with Proof Kernel property tests, this runtime completes the Phase 1 evidence-sealing objective:

- proof acceptance is fail-closed;
- accepted evidence is sealed into deterministic replay material;
- final acceptance is externally verifiable with a trusted signature;
- mutations are detectable without trusting the original executor.
