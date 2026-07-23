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
| Work Contract and capsule runtime compilation | Implemented | Compiles typed contracts and version-pinned profession capsules. |
| Deterministic intent-to-contract compilation | Implemented | The Static Social Media Post profile compiles a structured resolved intent. Unrestricted natural-language interpretation is not claimed. |
| Typed planner synthesis | Implemented | The Static Social Media Post profile synthesizes a deterministic plan using capsule-approved operators. General planning is not claimed. |
| Operator Plan compilation and trace conformance | Implemented | Plans may use only capsule-approved, version-pinned operators. |
| Signed capability tokens and authorization receipts | Implemented | Tokens are contract, capsule, plan, step, operator, executor and optional-device bound. |
| Authorized execution trace | Implemented | Receipt use and plan state are independently recomputed. |
| Occupational Twin | Implemented | Isolated deterministic workspace, immutable inputs, rollback, checkpoints and replay packages. |
| Evidence Runtime | Implemented | Evidence Bundles cannot self-assert acceptance. |
| Ed25519 Acceptance Certificates | Implemented | Issuance independently reassesses the exact Evidence Bundle before signing. |
| Windows Bridge protocol | Implemented | Signed pre-state, action-boundary state, post-state and TOCTOU checks. |
| Windows UI Automation host and Rust client | Demonstrated | Real bounded action against a controlled WPF target; not arbitrary Windows application control. |
| Inkscape adapter | Demonstrated | Exact binary binding, source immutability, action-boundary checks and a restricted proof-bound operator set with real Inkscape regression. |
| Proof-bound Inkscape canvas, layer, asset, text, color and geometry operators | Implemented | Ten version-pinned capabilities support canvas resize, layer creation, digest-bound asset placement, explicit text, fill, transform, align, distribute, editable SVG save and profiled PNG/SVG/PDF export. Unsupported SVG structures fail closed. |
| Signed Inkscape execution evidence | Implemented | Source, editable SVG, raster, semantic snapshots, application identity and signature are bound. |
| Independent PNG container validation | Implemented | Chunk ordering, CRC, dimensions, media type and color-profile evidence. |
| Restricted sRGB normalization | Implemented | Adds sRGB evidence only to proven restricted SVG material without changing IDAT bytes. |
| Independent PNG pixel decoding | Implemented | Restricted 8-bit non-interlaced RGB/RGBA profile with independent zlib and filter reconstruction. |
| Rendered contrast validation | Implemented | Validates a declared text region using independently decoded pixels. |
| Rendered logo geometry and clear space | Implemented | Validates a declared placement against a transparent approved PNG mask. |
| Rendered text bounds, safe area and clipping guard | Implemented | Validates visible foreground inside a declared text-only analysis region. |
| Editable SVG approved-copy identity | Implemented | Independently parses one direct-text SVG element and compares exact approved UTF-8 copy. |
| Cross-validator final artifact binding | Implemented | Requires all raster validators to share the exact normalized PNG and pixel decode. |
| Static Social Media Post final certificate | Certified path | Synthetic end-to-end material reaches a certificate over signed execution, normalization and independent artifact proofs. Permanent real-Inkscape regressions cover bounded execution and final artifact certification. |
| Desktop product shell | Implemented | Tauri/React review shell displays immutable inputs, resolution state, contract, permissions, sealed plan, execution, validators, evidence and certificate state. Renderer mutation cannot forge acceptance. Writable approval and execution commands are not yet enabled. |
| General application learning | Planned | No live-learning or self-modifying production capability is allowed. |
| Background cleanup job | Planned | No certified job-specific contract and validator chain exists. |
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

**Status: demonstrated, not closed.** A genuine WPF UI Automation action is signed and independently verified. The phase remains open because production application coverage, broader UI patterns, recovery, code signing and real-user environment hardening are incomplete.

### Phase 4 — Graphic Designer Alpha

**Status: one certified job and an expanded proof-bound Inkscape surface; phase not closed.** Static Social Media Post has a complete certified path. The adapter now provides version-pinned, attack-tested operators for canvas, layer, assets, text, colors, geometry and PNG/SVG/PDF delivery. The phase remains open until the background-cleanup, brand-compliant-export and print-ready-poster jobs each receive their own contracts, planners, independent validators, actionable failure maps and permanent certificate regressions.

### Phase 5 — Profession learning laboratory

**Status: not started.** Candidate operator learning, demonstration capture, synthetic-task generation, certification and capsule signing remain future work.

### Phase 6 — Cross-platform and additional professions

**Status: not started.** Additional platform bridges and profession capsules remain future work.

## Release labels

- **Experimental:** code or execution may be demonstrated but cannot issue a verified-work certificate for the unsupported claim.
- **Certified path:** the exact bounded claim set can reach an independently verifiable certificate through automated evidence.
- **Profession alpha:** every mandatory technical claim for the declared job types is covered by certified paths and failure maps.
- **Product alpha:** the desktop application can safely compile, review, authorize, execute and inspect those certified profession paths.

## Completed immediate gates

1. Deterministic intent-to-contract compiler for Static Social Media Post.
2. Typed planner synthesis using certified Graphic Designer operators.
3. Permanent real-Inkscape final-artifact validation and final-certificate CI.
4. Tauri/React contract, permission, plan, execution, validator, evidence and certificate views.
5. Renderer-side acceptance forgery prevention and actionable validator/failure display.
6. Expanded proof-bound Inkscape operator set with per-operator attack coverage and real regression.

## Next gates

1. Certify background cleanup, brand-compliant export and print-ready poster preflight.
2. Add digest-bound writable approval and execution commands to the desktop application without moving authority into the renderer.
3. Harden local key storage, revocation, release signing, SBOM and Windows installer provenance.
4. Expand the Windows Bridge across real application patterns and recovery cases.
5. Build the Profession Learning Laboratory in a cryptographically separate environment.
6. Add cross-platform bridges and additional profession capsules only after the Windows Product Alpha gates hold.

## Non-negotiable rule

A passing model response, application return code, screenshot, click, keystroke, declared success field or executor-generated digest is never sufficient proof by itself. Unsupported claims remain `UNKNOWN` and cannot be promoted by product messaging, UI state or certificate wording.
