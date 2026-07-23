# Ergaxiom Current Capability Status

This document records what the repository can currently prove. It is deliberately narrower than the long-term product vision.

A capability is marked **certified path** only when the repository has an automated evidence chain that reaches an independently verified Acceptance Certificate. **Demonstrated** means real execution exists but the complete profession-level claim set is not yet certified. **Implemented** means the deterministic component and attack tests exist. **Planned** means the capability is not present as a production runtime.

## Capability matrix

| Area | Status | Current boundary |
|---|---|---|
| Normative Work Contract, Profession Capsule and Evidence Bundle schemas | Implemented | Draft schemas remain versioned and subject to pre-alpha change. |
| Canonical JSON and SHA-256 sealing | Implemented | Used by contracts, plans, receipts, evidence and certificates. |
| Three-valued proof kernel | Implemented | Mandatory `FALSE`, `UNKNOWN`, missing and contradictory proof states fail closed. |
| Property-based impossible-acceptance tests | Implemented | Generated states cannot accept missing mandatory proof. |
| Work Contract and capsule runtime compilation | Implemented | Compiles existing typed JSON; natural-language intent compilation is not implemented. |
| Operator Plan compilation and trace conformance | Implemented | Plans may use only capsule-approved, version-pinned operators. |
| Signed capability tokens and authorization receipts | Implemented | Tokens are contract, capsule, plan, step, operator, executor and optional-device bound. |
| Authorized execution trace | Implemented | Receipt use and plan state are independently recomputed. |
| Occupational Twin | Implemented | Isolated deterministic workspace, immutable inputs, rollback, checkpoints and replay packages. |
| Evidence Runtime | Implemented | Evidence Bundles cannot self-assert acceptance. |
| Ed25519 Acceptance Certificates | Implemented | Issuance independently reassesses the exact Evidence Bundle before signing. |
| Windows Bridge protocol | Implemented | Signed pre-state, action-boundary state, post-state and TOCTOU checks. |
| Windows UI Automation host and Rust client | Demonstrated | Real bounded action against a controlled WPF target; not arbitrary Windows application control. |
| Inkscape adapter | Demonstrated | Pinned executable, direct text replacement and raster export for a restricted SVG profile. |
| Signed Inkscape execution evidence | Implemented | Source, editable SVG, raster, semantic snapshots, application identity and signature are bound. |
| Independent PNG container validation | Implemented | Chunk ordering, CRC, dimensions, media type and color-profile evidence. |
| Restricted sRGB normalization | Implemented | Adds sRGB evidence only to proven restricted SVG material without changing IDAT bytes. |
| Independent PNG pixel decoding | Implemented | Restricted 8-bit non-interlaced RGB/RGBA profile with independent zlib and filter reconstruction. |
| Rendered contrast validation | Implemented | Validates a declared text region using independently decoded pixels. |
| Rendered logo geometry and clear space | Implemented | Validates a declared placement against a transparent approved PNG mask. |
| Rendered text bounds, safe area and clipping guard | Implemented | Validates visible foreground inside a declared text-only analysis region. |
| Editable SVG approved-copy identity | Implemented | Independently parses one direct-text SVG element and compares exact approved UTF-8 copy. |
| Cross-validator final artifact binding | Implemented | Requires all raster validators to share the exact normalized PNG and pixel decode. |
| Static Social Media Post final certificate | Certified path | Synthetic end-to-end fixture reaches a new certificate over signed execution, normalization and independent artifact proofs. Real Inkscape regressions cover the bounded execution and prior attestation chain. |
| Natural-language Work Contract compiler | Planned | No model or deterministic intent compiler is currently exposed. |
| Typed planner service | Planned | Existing plan runtime validates supplied plans; it does not synthesize plans from intent. |
| Desktop product UI | Planned | No production Tauri/React shell is present. |
| General application learning | Planned | No live-learning or self-modifying production capability is allowed. |
| Background cleanup job | Planned | Profession definition mentions image editing, but no certified job path exists. |
| Brand-compliant export job | Planned | No complete job-specific contract and certification suite exists. |
| Print-ready poster preflight | Planned | No complete PDF/print validator chain exists. |
| Cross-platform bridges | Planned | The proof kernel is platform-neutral; only bounded Windows and Inkscape paths exist. |

## Phase assessment

### Phase 0 — Verifiable foundation

**Exit gate: satisfied.** Normative schemas, cross-document validation, first capsule and complete example contract are present and exercised by CI.

### Phase 1 — Proof kernel

**Exit gate: satisfied for v1.** Canonical sealing, three-valued acceptance, validator independence, capability authorization, evidence reassessment, replay manifests, signatures and property-based fail-closed tests are implemented.

### Phase 2 — Occupational digital twin

**Exit gate: satisfied for v1.** Immutable input staging, typed operations, atomic postconditions, rollback, trace conformance and replay material are implemented and attack-tested.

### Phase 3 — Windows execution bridge

**Status: demonstrated, not closed.** A genuine WPF UI Automation action is signed and independently verified. The phase remains open because production application coverage, application identity policy, broader UI patterns, recovery, code signing and real-user environment hardening are incomplete.

### Phase 4 — Graphic Designer Alpha

**Status: one bounded certified path, phase not closed.** Static Social Media Post has a complete deterministic certification path for the supported fixture and restricted Inkscape flow. The phase remains open until real artifact fixtures exercise every final validator in one permanent workflow, failure results produce an actionable user-facing error map, and the three other initial job types are certified.

### Phase 5 — Profession learning laboratory

**Status: not started.** Candidate operator learning, demonstration capture, synthetic-task generation, certification and capsule signing remain future work.

### Phase 6 — Cross-platform and additional professions

**Status: not started.** Additional platform bridges and profession capsules remain future work.

## Release labels

- **Experimental:** code or execution may be demonstrated but cannot issue a verified-work certificate for the unsupported claim.
- **Certified path:** the exact bounded claim set can reach an independently verifiable certificate through automated evidence.
- **Profession alpha:** every mandatory technical claim for the declared job types is covered by certified paths and failure maps.
- **Product alpha:** the desktop application can safely compile, review, authorize, execute and inspect those certified profession paths.

## Immediate gates

1. Deterministic intent-to-contract compiler for the existing Static Social Media Post contract.
2. Typed planner synthesis using only certified Graphic Designer operators.
3. Permanent real-Inkscape final-artifact validation and final-certificate CI path.
4. Desktop contract-review, permission, execution and evidence views.
5. Actionable error maps for failed validators.
6. Additional application operators and the remaining Graphic Designer jobs.
7. Secure local key storage, release signing and installer hardening.
8. Profession learning laboratory isolated from production execution.

## Non-negotiable rule

A passing model response, application return code, screenshot, click, keystroke, declared success field or executor-generated digest is never sufficient proof by itself. Unsupported claims remain `UNKNOWN` and cannot be promoted by product messaging, UI state or certificate wording.
