# Operator Simulation Runtime v1

## Purpose

The Operator Simulation Runtime executes a sealed `CompiledPlan` against the deterministic Occupational Twin before any live application bridge is allowed to act.

It proves that typed professional operations can be evaluated in plan order, under exact operator and artifact bindings, while preserving the Twin's atomic commit and rollback guarantees.

## Trust boundary

The simulator trusts only:

- a previously compiled Operator Plan;
- a caller-supplied Occupational Twin workspace;
- typed operations accepted by the Twin runtime;
- canonical JSON hashing from the Proof Kernel.

Simulation invocations are untrusted. They cannot override the sealed plan's:

- plan ID or digest;
- step identities and order;
- operator IDs and versions;
- dependency graph;
- declared input artifact IDs;
- declared output artifact IDs;
- mandatory-step requirements.

## Simulation pipeline

1. Require simulation-plan schema `0.1.0`.
2. Bind the simulation to the exact compiled plan ID and digest.
3. Index invocation records and detect duplicates or unknown steps.
4. Iterate the sealed plan in sequence order.
5. Require every dependency to have succeeded.
6. Compare invocation operator ID and version with the sealed step.
7. Compare the typed operation's operator ID with the sealed step.
8. Require exact, duplicate-free declared input and output artifact sets.
9. Apply an optional controlled fault to a cloned operation.
10. Submit the resulting typed operation to Occupational Twin.
11. Record `SUCCEEDED`, `REJECTED`, `ROLLED_BACK`, `BLOCKED`, or `MISSING`.
12. Block dependent steps after any failed prerequisite.
13. Seal the final workspace snapshot, Twin trace digest and simulation report digest.

## Controlled fault injection

Version 1 supports three explicit fault types:

- `FORCE_PRECONDITION_FAILURE`: appends an impossible input digest precondition;
- `FORCE_POSTCONDITION_FAILURE`: appends an impossible output digest postcondition;
- `CORRUPT_FIRST_WRITE`: replaces the first write command's bytes before Twin evaluation.

Faults never mutate the sealed plan or original invocation. They modify only the cloned operation submitted to the Twin. If a requested fault cannot apply, the step is blocked with `FAULT_NOT_APPLICABLE`.

## Determinism

A simulation report binds:

- simulation ID;
- plan ID and digest;
- initial snapshot digest;
- final workspace snapshot;
- step reports and violations;
- complete Occupational Twin trace digest;
- final conformance decision.

The `simulation_digest` is computed over all report fields except itself. Re-running the same sealed plan, workspace state and invocation set must produce the same report and digest.

## Fail-closed invariants

- A simulation bound to another plan cannot run.
- Unknown or duplicate invocations cannot be ignored.
- Missing mandatory invocations prevent conformance.
- A step cannot run before dependencies succeed.
- Operator identity or version mismatch blocks the step before workspace mutation.
- Declared artifact sets must exactly match the sealed step.
- Rejected or rolled-back operations prevent mandatory plan conformance.
- A failed prerequisite blocks dependent operations.
- Fault-induced writes remain subject to Twin postconditions and rollback.
- Report mutation invalidates the canonical simulation digest.

## Phase 2 significance

Together with Occupational Twin Runtime v1, this layer satisfies the deterministic pre-execution simulation objective:

- professional plans can be simulated before live execution;
- immutable source assets remain protected by the Twin;
- failures are atomic and rollback-safe;
- dependency and operator boundaries are explicit;
- complete state and trace digests are emitted;
- identical inputs produce identical final simulation reports.
