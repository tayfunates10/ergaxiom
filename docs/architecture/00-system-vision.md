# Ergaxiom System Vision

## Product definition

Ergaxiom is a verified profession operating system. It converts a user's natural-language intent into a typed work contract, selects capabilities from an installed profession capsule, executes the work through permission-scoped application bridges, and accepts the result only when every declared proof obligation has passed.

Ergaxiom is not a generic macro recorder and is not a model that clicks through screens until a task appears complete. The language model may interpret, propose, and explain. It does not own truth.

## Foundational invariant

> A job is not complete because an agent says it is complete. A job is complete only when its acceptance contract is satisfied by independently reproducible evidence.

## System boundaries

The first product target is Windows. Cross-platform portability is preserved by separating the profession kernel and proof system from operating-system and application bridges.

The first profession capsule is Graphic Designer. It will begin with narrow, testable workflows such as social-media artwork, image cleanup, brand-rule conformance, and export validation.

## Core pipeline

1. **Intent capture** — Preserve the user's request, referenced assets, environment, and constraints.
2. **Contract compilation** — Produce a typed work contract with explicit unknowns, hard constraints, preferences, permissions, outputs, and proof obligations.
3. **Capability resolution** — Select certified operators from a versioned profession capsule.
4. **Plan synthesis** — Build a dependency graph of typed operations.
5. **Pre-execution proof gate** — Reject plans with unresolved inputs, missing permissions, unsupported operators, or unprovable acceptance conditions.
6. **Digital-twin execution** — Apply the plan to an isolated copy or simulated state when possible.
7. **Controlled execution** — Use deterministic APIs and application bridges before visual interaction.
8. **Independent verification** — Validate outputs and process traces through tools that are separate from the executor.
9. **Evidence compilation** — Produce hashes, measurements, trace records, validator results, and provenance metadata.
10. **Acceptance decision** — Accept, reject, or return `UNRESOLVED`; never infer success from appearance alone.

## Design principles

### Unknown is a first-class state

The system uses three-valued outcomes where necessary:

- `TRUE`: proven to satisfy the declared condition.
- `FALSE`: proven not to satisfy the declared condition.
- `UNKNOWN`: insufficient trustworthy evidence.

`UNKNOWN` never silently becomes `TRUE`.

### Typed operations over raw interaction

Preferred execution order:

1. Document or domain model
2. Application API
3. Signed application plugin
4. Command-line interface
5. Operating-system accessibility or automation API
6. Visual perception with state confirmation
7. Coordinate interaction as a constrained last resort

### Independent verification

An executor cannot be the sole verifier of its own work. Critical outputs require at least one independent validator, and high-assurance levels require validator diversity.

### Replayability

Every accepted job should be reproducible from:

- immutable input references,
- a versioned work contract,
- a versioned profession capsule,
- a versioned operator plan,
- recorded environment and application versions,
- deterministic parameters or declared randomness seeds.

### Least authority

Every operator receives only the capabilities needed for its declared action. File, network, application, secret, and user-identity permissions are explicit and auditable.

## Non-goals for the first release

- Claiming subjective taste is mathematically true.
- Automatically mastering arbitrary software in a live user environment.
- Performing irreversible financial, legal, communication, or deployment actions without explicit approval.
- Accepting a job based only on screenshots or model confidence.
- Supporting all professions before the verification kernel is proven.

## Initial acceptance target

The first milestone is successful when a narrow graphic-design job can be:

- compiled into a machine-readable contract,
- executed in an isolated workspace,
- verified against measurable technical and brand constraints,
- rejected when evidence is missing,
- delivered with a machine-readable evidence bundle.
