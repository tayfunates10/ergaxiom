# Ergaxiom Roadmap

This roadmap is capability-gated. A phase is complete only when its exit criteria are demonstrated by automated evidence; elapsed time or file count does not complete a phase.

For the exact implemented claim boundary, see [Current capability status](status.md).

## Current gate summary

| Phase | Gate status |
|---|---|
| Phase 0 — Verifiable foundation | Satisfied for v1 |
| Phase 1 — Proof kernel | Satisfied for v1 |
| Phase 2 — Occupational digital twin | Satisfied for v1 |
| Phase 3 — Windows execution bridge | Demonstrated; production gate open |
| Phase 4 — Graphic Designer Alpha | Satisfied for v1; four certified job paths |
| Windows Product Alpha | Digest-bound control implemented for one bounded fixture; release and multi-job gates open |
| Phase 5 — Profession learning laboratory | Not started |
| Phase 6 — Cross-platform and additional professions | Not started |

A satisfied v1 gate means the listed invariants are implemented and exercised by automated tests. It does not mean interfaces are stable or the product is ready for unrestricted use.

## Phase 0 — Verifiable foundation

**Goal:** define the contracts that prevent the system from treating model confidence as truth.

Deliverables:

- Work Contract schema
- Profession Capsule schema
- Evidence Bundle schema
- Trust and verification model
- Cross-document foundation validator
- Graphic Designer draft capsule
- One complete example contract

Exit criteria:

- Every schema is valid JSON Schema 2020-12.
- Every mandatory example constraint is linked to a declared validator.
- Unknown mandatory requirements block acceptance.
- Contract assurance cannot be lower than the profession capsule minimum.
- CI rejects broken references and duplicate identifiers.

## Phase 1 — Proof kernel

**Goal:** implement the authoritative acceptance engine without desktop control.

Planned components:

- Canonical serialization and content hashing
- Contract compiler intermediate representation
- Three-valued claim engine: `TRUE`, `FALSE`, `UNKNOWN`
- Capability and permission tokens bound to contract hashes
- Proof-obligation state machine
- Validator registry
- Evidence sealing and signature interface
- Deterministic replay manifest

Exit criteria:

- The kernel accepts only runs whose mandatory obligations are sealed as passed.
- Mutating a contract, plan, artifact or evidence record invalidates acceptance.
- Validator disagreement produces `UNRESOLVED`.
- Property-based tests cannot produce an accepted run with a missing mandatory proof.

## Phase 2 — Occupational digital twin

**Goal:** execute typed plans against isolated state before touching a user's real workspace.

Planned components:

- Workspace snapshot and immutable input staging
- Typed operator plan graph
- Precondition and postcondition evaluation
- Checkpoints and rollback journal
- Plan/trace conformance checker
- Environment and application identity capture

Exit criteria:

- Failed operations cannot modify immutable inputs.
- A simulated or isolated run produces a complete trace.
- Undeclared deviations block acceptance.
- Final artifacts can be reproduced from a sealed run manifest.

## Phase 3 — Windows execution bridge

**Goal:** provide constrained Windows execution without making screen coordinates the source of truth.

Priority order:

1. Native document or application model
2. Application API
3. Signed application plugin
4. CLI
5. Windows UI Automation
6. Accessibility state
7. Visually confirmed interaction
8. Constrained coordinate fallback

Exit criteria:

- Every operation reports observed pre-state and post-state.
- The bridge refuses actions outside its capability token.
- A click or keystroke is never treated as proof of success.
- Time-of-check/time-of-use changes are detected at critical boundaries.
- Production application identity, recovery, selector and code-signing policies are exercised outside a controlled test target.

## Phase 4 — Graphic Designer Alpha

**Goal:** deliver the first narrow profession that can execute and verify real work.

Initial certified job types:

- Static social-media post
- Image background cleanup
- Brand-compliant image export
- Print-ready poster preflight

Initial application strategy:

- Start with an Ergaxiom-owned deterministic document model.
- Add one application bridge at a time.
- Keep artifact verification independent of the application used to create it.

Exit criteria:

- Technical output claims are independently verified.
- Brand invariants such as logo geometry and approved copy are preserved.
- Subjective preferences are reported separately from hard acceptance claims.
- A failed proof returns an actionable error map instead of a success message.
- Every initial job type has a permanent certified-path regression suite.

Current bounded achievement:

- Static Social Media Post reaches a final certificate over authorized execution, signed Inkscape material, signed sRGB normalization, independent PNG decoding, approved-copy identity, logo geometry, text safe area and rendered contrast.
- Image Background Cleanup reaches a certificate over an explicitly approved binary alpha mask, exact foreground preservation, independent PNG proofs and pinned Inkscape integration.
- Brand-Compliant Image Export reaches a certificate over restricted SVG brand rules, approved identity, pinned Inkscape export and IDAT-preserving sRGB normalization.
- Print-Ready Poster Preflight reaches a certificate over restricted outlined-vector input, exact print geometry, independent PDF resources and security inspection, and pinned Inkscape PDF export.

## Windows Product Alpha

**Goal:** let a user safely review, authorize, execute and inspect certified profession work without moving authority into the renderer.

Completed control gate:

- Tauri and React inspection shell with backend-verified snapshots;
- exact snapshot, Work Contract, Operator Plan and permission digest review;
- Rust-generated expiring approval record;
- stale snapshot, altered tuple, expired approval and replay rejection;
- backend-owned execution, cancellation and rollback lifecycle;
- canonical command receipts binding pre-state and post-state snapshots;
- validator and replay evidence hidden until authorized execution;
- renderer remains without filesystem, shell, unrestricted network, arbitrary process or signing-key access.

Remaining product gates:

- DPAPI, TPM-backed or equivalent local private-key protection;
- issuer-role separation, key rotation and revocation;
- signed desktop, bridge, adapter and installer releases;
- SBOM, dependency provenance, reproducible release manifests and checksums;
- user-selected immutable inputs instead of the bounded fixture;
- all four certified Graphic Designer jobs routed through the same user-driven desktop lifecycle;
- persistent job and receipt storage with upgrade and rollback attack tests.

The current approval and command receipts are canonical hashes owned by the Rust process, not production digital signatures. A completed desktop execution still cannot display certified acceptance without a separately verified Evidence Bundle and Acceptance Certificate.

## Phase 5 — Profession learning laboratory

**Goal:** convert expert demonstrations and application documentation into candidate operators without learning unsafely in production.

Planned components:

- Expert demonstration capture
- Decision-point annotation
- Candidate operator synthesis
- Synthetic task generation
- Adversarial and regression testing
- Skill certification and signing

Exit criteria:

- New operators cannot enter a production capsule without passing its certification suite.
- Live user work is never used for immediate unreviewed capability mutation.
- Capsule upgrades are versioned and can be rolled back.

## Phase 6 — Cross-platform and additional professions

**Goal:** preserve the proof kernel while replacing platform bridges and adding profession capsules.

Candidate capsules:

- Video Editor
- Software Developer
- Web Designer
- CAD Operator
- Office Specialist
- SEO Specialist

Exit criteria:

- Profession contracts and evidence bundles remain platform-neutral.
- Platform-specific claims are isolated behind bridge attestations.
- The same bounded job can be verified consistently across supported platforms.

## Non-negotiable release rule

A capability may be demonstrated experimentally before it is certified, but the product must label it as experimental and must not issue a verified-work certificate for unsupported claims.
