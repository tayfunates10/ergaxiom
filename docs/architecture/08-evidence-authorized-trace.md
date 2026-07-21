# Evidence Runtime and Authorized Execution

## Purpose

Evidence Runtime v0.3 upgrades Evidence Bundle schema to `0.4.0` and requires every bundle to carry an `AuthorizedExecutionTrace`.

The former bundle format carried raw Operator Plan events. Those events could name capability-token IDs, but Evidence Runtime had no proof that the tokens had been cryptographically authorized or that the resulting authorization receipts matched the exact execution events.

## New acceptance order

Evidence Runtime now evaluates a bundle in this order:

1. Decode Evidence Bundle schema `0.4.0`.
2. Verify contract, profession-capsule and operator-plan bindings.
3. Compare bundle assurance with the externally verified assurance level.
4. Invoke Execution Runtime on the embedded Authorized Execution Trace.
5. Reject forged authorized-conformance claims.
6. Reject any plan-state or authorization-receipt violation.
7. Index output and evidence artifacts.
8. Admit validator results through Contract Runtime allowlists.
9. Recompute mandatory proof-obligation states in Proof Kernel.
10. Compare the bundle's claimed decision and counters with the recomputed decision.
11. Canonically hash the complete accepted bundle.

Proof evidence is never submitted to Proof Kernel before the authorized execution trace passes.

## Schema composition

Evidence Bundle schema `0.4.0` references the sibling `authorized-execution-trace.schema.json` document instead of duplicating its receipt and event structures. This keeps the execution envelope independently versioned and prevents schema drift between Execution Runtime and Evidence Runtime.

## End-to-end validation

Integration tests build the complete chain:

- compile the real Graphic Designer Work Contract;
- compile the sealed four-step Operator Plan;
- issue four independently signed Ed25519 capability tokens;
- authorize each token against exact Work Contract permissions;
- produce four authorization receipts;
- bind each step's STARTED and SUCCEEDED events to its receipt digest;
- submit nine validator proof results;
- recompute the final ACCEPTED decision.

The test suite also rejects:

- forged claimed decisions;
- missing proof results hidden by claimed counters;
- bundle contract or plan binding changes;
- forged authorized-trace conformance claims;
- honestly reported but nonconforming execution;
- forged authorization-receipt digests;
- evidence artifacts with the wrong role;
- bundle-declared assurance above the externally verified level.

## Fail-closed invariants

- Raw trace events are no longer accepted by Evidence Runtime.
- A valid output cannot compensate for unauthorized execution.
- Valid proof results cannot compensate for receipt or plan violations.
- Valid authorization receipts cannot compensate for missing mandatory proof evidence.
- The bundle cannot self-assert either trace conformance, assurance or final acceptance.
