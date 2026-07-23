# Ergaxiom

**Verified Profession Operating System**

Ergaxiom is a proof-driven operating layer for turning professional intent into executable, measurable and independently verifiable computer work.

> Work is not complete until its declared constraints are proven.

## Status

Ergaxiom is an implementation-stage pre-alpha. Its proof and certification core is operational, but it is not yet a general-purpose desktop product.

The repository currently contains:

- a Rust proof kernel with `TRUE`, `FALSE` and `UNKNOWN` claim semantics,
- typed Work Contract and Profession Capsule compilation,
- signed capability authorization and receipt-bound execution traces,
- deterministic occupational-twin simulation, rollback and replay,
- signed Evidence Bundles and Ed25519 Acceptance Certificates,
- a proof-bound Windows UI Automation bridge demonstrated against a controlled WPF target,
- a pinned Inkscape adapter with signed execution evidence,
- independent PNG structure, sRGB, pixel, contrast, logo-geometry and text-bounds validators,
- independent editable-SVG approved-copy validation, and
- a bounded Static Social Media Post chain that can issue a final certificate over independently bound artifacts.

The current implementation does **not** yet provide a natural-language contract compiler, production desktop UI, arbitrary application learning or unrestricted control of desktop software. See [Current capability status](docs/status.md) for the exact claim boundary.

## What makes Ergaxiom different

A conventional desktop agent may infer that a task succeeded from a screenshot, a click or model confidence. Ergaxiom separates interpretation, execution and acceptance:

1. Intent is compiled into a typed **Work Contract**.
2. A versioned **Profession Capsule** supplies allowed operators and validators.
3. A sealed **Operator Plan** defines the exact execution graph.
4. Operations execute with signed, resource-scoped capability tokens.
5. Independent validators evaluate every mandatory claim.
6. A run is accepted only when a sealed **Evidence Bundle** proves the contract.
7. Accepted bundles can be issued as independently verifiable **Acceptance Certificates**.

Missing evidence remains `UNKNOWN`; it never silently becomes success.

## Core principles

- Never guess hidden state.
- Convert user intent into explicit work contracts.
- Separate creative generation from deterministic verification.
- Execute only typed, permission-scoped operations.
- Treat unknown requirements as unresolved, not as implicit approval.
- Prevent an executor from being the sole verifier of its own work.
- Bind every accepted output to reproducible evidence and a sealed execution trace.
- Label experimental capabilities honestly and never certify unsupported claims.

## Implemented trust chain

The current bounded Graphic Designer path is:

```text
Work Contract
  -> Profession Capsule
  -> Operator Plan
  -> Signed capability tokens
  -> Authorized execution trace
  -> Occupational Twin
  -> Signed Inkscape execution
  -> Signed sRGB normalization
  -> Independent PNG decoding
  -> Approved-copy validation
  -> Logo-geometry and clear-space validation
  -> Text-bounds and safe-area validation
  -> Rendered contrast validation
  -> Cross-validator artifact binding
  -> Evidence Bundle reassessment
  -> Ed25519 Acceptance Certificate
```

A click, application success response or self-declared validator result cannot independently complete this chain.

## Repository highlights

### Normative schemas

- [`schemas/work-contract.schema.json`](schemas/work-contract.schema.json)
- [`schemas/profession-capsule.schema.json`](schemas/profession-capsule.schema.json)
- [`schemas/evidence-bundle.schema.json`](schemas/evidence-bundle.schema.json)

### First profession and contract

- [`professions/graphic-designer/profession.json`](professions/graphic-designer/profession.json)
- [`examples/work-contracts/social-media-static-post.json`](examples/work-contracts/social-media-static-post.json)

### Architecture

- [System vision](docs/architecture/00-system-vision.md)
- [Trust and verification model](docs/architecture/01-trust-model.md)
- [Repository layout](docs/repository-layout.md)
- [Current capability status](docs/status.md)
- [Capability-gated roadmap](docs/roadmap.md)

### Runtime workspace

The Rust workspace contains 26 crates spanning contracts, authorization, execution, evidence, attestation, occupational simulation, Windows bridging, Inkscape execution and independent artifact verification.

## Validation

Install the Python development dependency and validate the normative foundation:

```bash
python -m pip install -r requirements-dev.txt
python tools/validate_foundation.py
```

Validate the Rust workspace:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

GitHub Actions also runs dedicated Windows and real Inkscape workflows. The real Inkscape workflow pins the executable identity and exercises edit, export, signed execution, PNG validation, sRGB normalization, independent pixel decoding, rendered contrast and final attestation regressions.

## Current priorities

1. Implement the deterministic intent-to-Work-Contract compiler.
2. Implement the typed planner service over certified capsule operators.
3. Build the Tauri and React desktop shell for contract review, permission approval, execution and evidence inspection.
4. Expand the Inkscape adapter beyond the bounded direct-text and raster-export path.
5. Certify the remaining Graphic Designer job types.
6. Build the isolated profession-learning laboratory.
7. Add cross-platform bridges only without weakening the proof kernel.

## Project stage

**Pre-alpha.** Interfaces and specifications are expected to change. Certificates are valid only for the exact bounded claims, artifacts, validators, application identities and test-supported paths represented in their Evidence Bundles. No certificate should be interpreted as proof of unsupported subjective quality or general-purpose desktop competence.
