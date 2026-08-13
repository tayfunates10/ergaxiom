# Ergaxiom

**Verified Profession Operating System**

Ergaxiom is a proof-driven operating layer for turning professional intent into executable, measurable and independently verifiable computer work.

> Work is not complete until its declared constraints are proven.

## Status

Ergaxiom is an implementation-stage pre-alpha. Its proof and certification core is operational, but it is not yet a general-purpose desktop product.

The repository currently contains:

- a Rust proof kernel with `TRUE`, `FALSE` and `UNKNOWN` claim semantics,
- typed Work Contract and Profession Capsule compilation plus an explicit digest-bound profession catalog,
- signed capability authorization and receipt-bound execution traces,
- deterministic occupational-twin simulation, rollback and replay,
- independently reassessed Evidence Bundles and Ed25519/P-256 Acceptance Certificates,
- a Tauri/React desktop inspection and digest-bound control shell,
- role-separated Windows DPAPI and TPM/CNG signing foundations with persistent governed trust state,
- a proof-bound Windows UI Automation bridge demonstrated against a controlled WPF target,
- a pinned Inkscape adapter with signed execution evidence,
- independent PNG structure, sRGB, pixel, contrast, logo-geometry and text-bounds validators,
- independent editable-SVG, brand and restricted-PDF validation, and
- four bounded Graphic Designer jobs that can issue final certificates over independently bound artifacts.

The current implementation does **not** yet provide unrestricted natural-language contract compilation, a signed production installer, completed desktop-to-installed-signer execution, arbitrary application learning or unrestricted control of desktop software. See [Current capability status](docs/status.md) for the exact claim boundary.

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
- [`schemas/profession-catalog.schema.json`](schemas/profession-catalog.schema.json)
- [`schemas/evidence-bundle.schema.json`](schemas/evidence-bundle.schema.json)

### Profession catalog and first profession

- [`professions/catalog.json`](professions/catalog.json)
- [`professions/graphic-designer/profession.json`](professions/graphic-designer/profession.json)
- [`examples/work-contracts/social-media-static-post.json`](examples/work-contracts/social-media-static-post.json)

New professions must enter through `tools/scaffold_profession.py`. The scaffold validates the existing catalog and capsule digests before mutation, confines paths to `professions/`, rejects duplicate identities and paths, and creates only draft, planned, production-disabled E0 capsules with network and live learning denied by default.

### Architecture

- [System vision](docs/architecture/00-system-vision.md)
- [Trust and verification model](docs/architecture/01-trust-model.md)
- [Repository layout](docs/repository-layout.md)
- [Profession extension boundary](docs/architecture/53-profession-catalog-and-extension-boundary.md)
- [Current capability status](docs/status.md)
- [Capability-gated roadmap](docs/roadmap.md)
- [Release readiness and external blockers](docs/release-readiness.md)
- [Security policy](SECURITY.md)

### Runtime workspace

The Rust workspace contains the proof kernel, contracts, authorization, execution, evidence, attestation, occupational simulation, Windows trust/signing, Inkscape execution and independent artifact-verification runtimes. `Cargo.toml` and the checked-in `Cargo.lock` are the authoritative workspace and dependency graph; CI rejects lock drift on release/security paths.

## Validation

Install the Python development dependency and validate the normative foundation, scaffold and deterministic release evidence:

```bash
python -m pip install -r requirements-dev.txt
python tools/validate_schema_catalog.py
python tools/validate_foundation.py
python -m unittest \
  tools.test_validate_foundation \
  tools.test_scaffold_profession \
  tools.release.test_generate_release_evidence
python -m compileall -q tools
```

Validate the desktop renderer and its dependency gate:

```bash
cd apps/desktop
npm ci
npm audit --audit-level=high
npm test
npm run build
cd ../..
```

Validate the Rust workspace and the checked-in lock graph:

```bash
cargo metadata --locked --format-version 1 --no-deps > /dev/null
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
git diff --check
```

GitHub Actions also runs dedicated Windows, RustSec and real Inkscape workflows. Release evidence is generated only from the exact source commit, binds both lockfiles plus a validated deterministic inventory of the profession catalog, every registered capsule, every example Work Contract and every foundation schema, and remains ineligible until the independent production signing and installer-provenance blockers are satisfied.

## Current priorities

1. Complete persistent desktop/backend routing through the installed production signer and full Evidence Bundle/Acceptance Certificate recovery chain.
2. Execute controlled physical-TPM provisioning, service installation and recovery ceremonies with retained evidence.
3. Add Authenticode, trusted timestamps and signed installer upgrade/rollback provenance.
4. Replace the bounded desktop fixture with persistent user-selected inputs across all four certified Graphic Designer jobs.
5. Build the isolated Profession Learning Laboratory.
6. Add new cataloged professions and cross-platform bridges only without weakening the proof kernel.

## Project stage

**Pre-alpha.** Interfaces and specifications are expected to change. Certificates are valid only for the exact bounded claims, artifacts, validators, application identities and test-supported paths represented in their Evidence Bundles. No certificate should be interpreted as proof of unsupported subjective quality or general-purpose desktop competence.
