# Execution Runtime v1

## Purpose

The Execution Runtime closes the authorization gap between a signed capability token and an execution trace.

Before this layer, an Operator Plan trace could name a capability-token ID, but the trace did not prove that the token had been cryptographically authorized or that the authorization applied to the exact sealed plan, step and operator that produced the event.

The runtime verifies an `AuthorizedExecutionTrace` whose events reference immutable `AuthorizationReceipt` records created by the Capability Runtime.

## Trust boundary

The runtime trusts only:

- a previously compiled `CompiledPlan`;
- authorization receipts produced after successful Capability Runtime validation;
- canonical JSON SHA-256 from the Proof Kernel;
- the existing deterministic Operator Plan trace state machine.

The following fields are untrusted claims and are independently recomputed:

- each declared receipt digest;
- each event-to-receipt reference;
- the trace's claimed authorized conformance;
- receipt bindings to contract, capsule, plan, step, operator and token;
- the underlying plan-state conformance.

## Verification pipeline

1. Require authorized-execution-trace schema `0.1.0`.
2. Bind the trace envelope to the exact compiled plan ID and digest.
3. Canonically serialize every authorization receipt and recompute its SHA-256 digest.
4. Reject duplicate or forged receipt-digest declarations.
5. Validate receipt usage counters and sealed contract, capsule and plan bindings.
6. Resolve every receipt reference carried by an execution event.
7. Require tokenized, non-skipped plan events to carry a receipt.
8. Match receipt step, operator and token IDs to the event.
9. Require one stable receipt per plan step.
10. Prevent a receipt from being reused across different steps.
11. Reject receipt records that are never used by an event.
12. Run the existing deterministic Operator Plan trace state machine.
13. Accept authorized conformance only when both authorization checks and plan-trace checks have zero violations.
14. Compare the recomputed result with the trace's claimed result.

## Authorization receipt bindings

Capability Runtime receipts now contain:

- contract digest;
- profession-capsule digest;
- plan ID;
- plan digest;
- step ID;
- operator ID;
- token ID and token/payload digests;
- issuer, key, executor and optional device identity;
- exact capability grant;
- trusted authorization time;
- use number and maximum uses.

The Execution Runtime does not re-verify the original Ed25519 signature. That responsibility remains in Capability Runtime. Instead, it proves that the immutable receipt used by the trace is the exact receipt whose canonical digest was declared and that its sealed bindings match the active compiled plan.

## Fail-closed invariants

- A raw capability-token ID is not authorization evidence.
- A forged receipt digest cannot authorize an event.
- A receipt from another contract, capsule or plan cannot authorize the current trace.
- A receipt for another step, operator or token cannot authorize an event.
- A step cannot silently switch receipts after execution begins.
- One receipt cannot be reused across different plan steps.
- Unused receipt records are rejected rather than ignored.
- A valid receipt cannot compensate for an invalid plan state transition.
- A valid plan trace cannot compensate for missing or invalid authorization receipts.
- A claimed authorized-conformance boolean never overrides the recomputed result.

## Current integration boundary

Version 1 exposes the receipt-bound trace verifier as a standalone Rust crate. The next integration phase will make Evidence Runtime consume this verified authorized trace instead of directly accepting raw `TraceEvent` records.
