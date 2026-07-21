# Graphic Certified Delivery v1

## Goal

This runtime converts a successful Graphic Designer functional-twin run into a cryptographically authorized, independently assessed and signed delivery package. It is the first complete Ergaxiom path from sealed professional intent to a verifiable acceptance certificate.

## Acceptance order

The order is mandatory and fail-closed:

1. Validate one signed capability token for every sealed Operator Plan step.
2. Verify token signature, time bounds, executor/device identity, exact contract/capsule/plan/step/operator bindings and exact Work Contract grant.
3. Execute the Graphic Designer functional twin through Operator Simulation and Occupational Twin.
4. Independently ingest all generated proof evidence into Proof Kernel.
5. Stop if the Proof Kernel decision is not `ACCEPTED`.
6. Build an Authorized Execution Trace whose events are bound to canonical authorization-receipt digests.
7. Independently verify the receipt-bound trace against the sealed Operator Plan.
8. Build Evidence Bundle `0.4.0` with input, output and validator-evidence artifacts.
9. Recompute the Evidence Bundle decision with Evidence Runtime.
10. Stop if the recomputed decision is not `ACCEPTED`.
11. Build a deterministic Replay Manifest and sign an Acceptance Certificate with Ed25519.
12. Verify the signature and recompute the replay manifest against the source Evidence Bundle before returning success.

## Capability model

The four Graphic Designer operators receive separate single-use tokens:

- `design.create_canvas`: design-editor control in the isolated workspace,
- `design.place_asset`: immutable contract-input read,
- `design.compose_text`: design-editor control in the isolated workspace,
- `design.export_raster`: contract-output write.

A token valid for one step cannot authorize another step because every token is bound to the exact plan ID, plan digest, step ID and operator ID. Authorization occurs before any input is staged into the Occupational Twin.

## Trace construction

Each succeeded plan step emits two events:

- `STARTED`, bound to the step authorization receipt and before-snapshot digest,
- `SUCCEEDED`, bound to the same receipt and after-snapshot digest.

The existing Execution Runtime independently enforces event sequence, dependency order, state transitions, token identity, stable receipt use and plan/capsule/contract digest bindings.

## Evidence transport

The Evidence Bundle contains:

- the three immutable contract inputs,
- the editable design master,
- the deterministic PNG delivery,
- one immutable JSON evidence artifact per mandatory validator result,
- nine proof results for eight mandatory obligations,
- four authorization receipts and eight receipt-bound trace events,
- captured sandbox/runtime/application identity.

The minimum text-contrast obligation receives two independent validator records and therefore satisfies its `diverse` independence requirement only when both methods pass.

## Certificate boundary

The certificate issuer does not accept a caller-provided success flag. It re-runs Evidence Runtime and only signs an independently recomputed `ACCEPTED` decision with zero mandatory failed or unknown obligations.

The returned certificate is immediately verified against a local trusted public-key registry and the exact source Evidence Bundle. Mutation of the bundle, trace, replay manifest, certificate payload or signature is detected.

## Failure semantics

- Invalid token signature or grant: no workspace staging or execution.
- Functional-twin failure: no Evidence Bundle.
- Failed or unknown mandatory proof: no Evidence Bundle or certificate.
- Invalid receipt-bound trace: no Evidence Bundle.
- Evidence Runtime mismatch: no certificate.
- Attestation verification mismatch: no certified result.

A failed certification attempt never returns a verified-work certificate.
