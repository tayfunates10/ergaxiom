# Occupational Twin Runtime v1

## Purpose

The Occupational Twin Runtime provides an isolated, typed and replayable workspace state machine for professional work.

It does not automate a desktop application yet. It creates the deterministic substrate that later execution bridges must use:

- immutable input staging;
- content-addressed artifacts;
- environment identity capture;
- typed operation requests;
- precondition and postcondition evaluation;
- atomic commit or rollback;
- checkpoints and rollback journal;
- complete trace events;
- sealed final-state replay packages.

## Workspace state

Every artifact records:

- artifact ID;
- input, intermediate or output role;
- immutable or mutable status;
- media type;
- SHA-256 digest;
- byte size.

Immutable inputs are staged only when their supplied digest matches the actual bytes. They cannot be overwritten or deleted by typed operations.

## Environment identity

A twin workspace captures:

- operating system;
- architecture;
- runtime ID and version;
- trusted clock source;
- sandbox ID;
- application IDs, versions and digests.

Application identities are canonically sorted before the environment is hashed. Equivalent environments therefore produce the same environment digest regardless of input list ordering.

## State snapshots

A snapshot digest seals:

- schema version;
- workspace ID;
- monotonic revision;
- environment digest;
- sorted artifact metadata.

The current journal digest is carried beside the state digest but is deliberately not included inside the snapshot digest. This avoids a circular dependency between operation receipts, journal entries and the snapshots named by those receipts.

## Typed operations

An operation declares:

- operation and operator IDs;
- required input artifact IDs;
- permitted output artifact IDs;
- typed preconditions;
- typed write/delete commands;
- typed postconditions.

The runtime evaluates an operation in this order:

1. reject replayed operation IDs;
2. snapshot the current state;
3. verify declared inputs and preconditions;
4. require every mutation target to be declared;
5. reject duplicate command targets;
6. reject immutable artifact mutation;
7. decode command content into a candidate state;
8. evaluate postconditions on the candidate;
9. commit the candidate only when all checks pass;
10. otherwise preserve the original artifact state;
11. write an operation receipt to the journal;
12. append a trace event.

Precondition and command-policy failures produce `REJECTED`. Postcondition failures produce `ROLLED_BACK`. Neither changes artifact state.

## Checkpoints and rollback

A checkpoint stores an immutable copy of artifact state and the checkpoint snapshot digest. Rollback:

- restores checkpoint artifacts;
- advances the workspace revision;
- records both the historical restored digest and the new state digest;
- appends a rollback journal record;
- appends a trace event.

The new snapshot digest differs from the historical checkpoint digest because revision remains monotonic.

## Sealed replay package

A sealed final-state package contains:

- final workspace snapshot;
- environment, journal and trace digests;
- sorted required blob digest inventory;
- one base64url content-addressed blob per unique artifact digest.

Reproduction:

1. validates package schema;
2. decodes every blob;
3. recomputes each SHA-256 digest;
4. verifies exact blob inventory;
5. reconstructs each final artifact;
6. verifies artifact sizes;
7. recomputes the final snapshot digest.

## Fail-closed invariants

- Input digest mismatch cannot stage an artifact.
- Immutable inputs cannot be overwritten or deleted.
- Undeclared output mutation cannot commit.
- Failed preconditions cannot change artifact state.
- Failed postconditions roll candidate state back atomically.
- Replayed operation IDs are rejected.
- Rollback is journaled and traced.
- A modified sealed blob cannot reproduce the workspace.
- Environment ordering cannot change a semantically identical environment digest.

## Phase 2 status

This runtime implements the Phase 2 deterministic workspace substrate. The next Occupational Twin increment will add typed operator execution against this workspace, including explicit pre/post evaluators, simulation fault injection and bridge-independent operation traces.
