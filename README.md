# Ergaxiom

**Verified Profession Operating System**

Ergaxiom is a proof-driven operating layer for turning professional intent into executable, measurable, and independently verifiable computer work.

> Work is not complete until its declared constraints are proven.

## Status

Ergaxiom is in the research and architecture phase. The first target platform is Windows, and the first profession capsule focuses on narrow, verifiable graphic-design workflows.

The repository currently contains the Phase 0 normative foundation. It does not yet control desktop applications.

## What makes Ergaxiom different

A conventional desktop agent may infer that a task succeeded from a screenshot, a click, or model confidence. Ergaxiom separates interpretation, execution and acceptance:

1. Natural language is compiled into a typed **Work Contract**.
2. A versioned **Profession Capsule** supplies certified operators and validators.
3. Operations execute with explicit, resource-scoped permissions.
4. Independent validators evaluate every mandatory claim.
5. The run is accepted only when a sealed **Evidence Bundle** proves the contract.

The system uses `TRUE`, `FALSE`, and `UNKNOWN`. Missing evidence remains `UNKNOWN`; it never silently becomes success.

## Core principles

- Never guess hidden state.
- Convert natural-language requests into explicit work contracts.
- Separate creative generation from deterministic verification.
- Execute only typed, permission-scoped operations.
- Treat unknown requirements as unresolved, not as implicit approval.
- Prevent an executor from being the sole verifier of its own work.
- Deliver every accepted result with a reproducible evidence bundle.

## Phase 0 foundation

### Normative schemas

- [`schemas/work-contract.schema.json`](schemas/work-contract.schema.json)
- [`schemas/profession-capsule.schema.json`](schemas/profession-capsule.schema.json)
- [`schemas/evidence-bundle.schema.json`](schemas/evidence-bundle.schema.json)

### First profession and example

- [`professions/graphic-designer/profession.json`](professions/graphic-designer/profession.json)
- [`examples/work-contracts/social-media-static-post.json`](examples/work-contracts/social-media-static-post.json)

### Architecture

- [System vision](docs/architecture/00-system-vision.md)
- [Trust and verification model](docs/architecture/01-trust-model.md)
- [Repository layout](docs/repository-layout.md)
- [Capability-gated roadmap](docs/roadmap.md)

## Foundation validation

Install the development dependency and run:

```bash
python -m pip install -r requirements-dev.txt
python tools/validate_foundation.py
```

The validator checks:

- JSON Schema validity,
- contract and profession-capsule conformance,
- profession, job type, operator and validator references,
- mandatory constraints without proof obligations,
- unresolved mandatory unknowns,
- assurance-level downgrade attempts,
- required output declarations.

The same validation runs in GitHub Actions.

## Initial implementation order

1. Stabilize Phase 0 schemas and invariants.
2. Implement the Rust proof kernel and canonical hashing.
3. Add property-based tests for impossible acceptance states.
4. Build the occupational digital-twin workspace and trace model.
5. Implement independent graphic-artifact validators.
6. Add Windows and application execution bridges only after the proof boundary is operational.

## Project stage

Pre-alpha. Interfaces and specifications are expected to change. No correctness certificate should be issued by pre-alpha code.
