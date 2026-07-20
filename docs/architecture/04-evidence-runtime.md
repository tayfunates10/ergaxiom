# Evidence Runtime v1

## Purpose

The Evidence Runtime imports one Evidence Bundle, verifies its bindings and artifact references, feeds admissible proof results into a sealed Contract Session, and compares the bundle's claimed decision with the decision independently recomputed by the Proof Kernel.

An Evidence Bundle is a transport format. It is not trusted merely because it contains the word `ACCEPTED`.

## Evidence Bundle 0.2.0

Schema version `0.2.0` introduces two mandatory proof-result fields:

- `evidence_id` uniquely identifies one immutable validation result;
- `subject_artifact_id` identifies the exact artifact whose digest is bound into the Proof Kernel evidence record.

The old top-level `decision` is renamed `claimed_decision`. This makes its trust status explicit.

## Assessment pipeline

1. Decode the Evidence Bundle.
2. Require the supported schema version.
3. Verify the bundle's Work Contract ID and SHA-256 digest.
4. Verify the Profession Capsule SHA-256 digest.
5. Require the execution trace to conform to the sealed operator plan.
6. Require the claimed assurance level to match an assurance level established outside the bundle.
7. Index artifacts and reject duplicate identifiers.
8. Resolve each proof result to a compiled proof obligation.
9. Verify claim ID and mandatory status.
10. Resolve the subject artifact and bind its digest to the proof record.
11. Require all referenced evidence artifacts to exist and carry the `evidence` role.
12. Submit the result through the Contract Runtime validator allowlist.
13. Recompute all obligation states and the final decision in the Proof Kernel.
14. Recompute mandatory passed, failed and unknown counts.
15. Reject the bundle if any claimed decision field differs.
16. Canonically hash the accepted bundle.

## Assurance is not self-declared

`claimed_decision.assurance_level` is not used as the source of truth. The caller must provide a `verified_assurance_level`, which will later come from signed environment attestations, validator execution identities and policy evaluation.

A bundle claiming `E5` while the trusted environment establishes only `E2` is rejected before evidence ingestion.

## Trace conformance

Version 1 fails closed when `trace.conforms_to_plan` is false. Authorized deviation handling will require a future signed authorization model. A free-form deviation description is not sufficient to preserve acceptance.

## Tamper resistance covered by tests

The integration suite verifies rejection of:

- forged claimed decisions;
- missing proof results hidden behind an `ACCEPTED` claim;
- bundles bound to another Work Contract;
- nonconforming execution traces;
- evidence references pointing to non-evidence artifacts;
- assurance levels asserted only by the bundle itself.

## Deferred capabilities

Future versions will add:

- signature verification;
- trusted timestamp validation;
- artifact byte re-hashing from resolved URIs;
- operator-plan runtime and trace replay;
- environment attestation verification;
- evidence payload schemas per validator;
- append-only transparency logging and revocation.
