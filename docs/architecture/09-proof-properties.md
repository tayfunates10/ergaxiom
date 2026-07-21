# Proof Kernel Property Tests

## Purpose

Example tests prove selected scenarios. Property-based tests search a much larger state space and automatically shrink failures to the smallest reproducible counterexample.

The Proof Kernel property suite uses deterministic, bounded generators for proof obligations, validator evidence, assurance levels and unresolved contract unknowns.

## Generated dimensions

The suite varies:

- one to eight mandatory proof obligations;
- executor, independent and diverse proof requirements;
- zero to four evidence records per obligation;
- `TRUE`, `FALSE` and `UNKNOWN` evidence results;
- executor, independent and diverse evidence classes;
- repeated and distinct validator identities;
- zero or positive unresolved unknown counts;
- all assurance levels from E0 through E5;
- optional-only contract shapes;
- mutated contract digests.

The main generalized property runs 512 generated cases per CI execution. Additional focused properties run their own generated cases.

## Proven invariants

1. `ACCEPTED` is equivalent to all mandatory obligations being satisfied, zero unresolved unknowns and assurance meeting the policy minimum.
2. One missing mandatory proof prevents acceptance regardless of all other evidence.
3. Diverse proof requires at least two distinct independent validator identities.
4. Any mandatory `FALSE` evidence forces `REJECTED`, including conflicts with `TRUE` evidence.
5. Positive unresolved-unknown count blocks otherwise complete work.
6. Assurance below the contract policy blocks otherwise complete work.
7. Evidence bound to a mutated contract digest is rejected without changing kernel state.
8. A contract containing only optional obligations cannot be accepted.

## Failure behavior

When a property fails, Proptest shrinks obligation counts, evidence lists, validator IDs and generated values until it produces a minimal counterexample. CI therefore reports a replayable regression seed instead of only a large random case.

## Release significance

These tests directly enforce the Phase 1 roadmap exit criterion that automated generation cannot produce an accepted run with a missing mandatory proof. They complement, rather than replace, the explicit integration and adversarial tests in the rest of the workspace.
