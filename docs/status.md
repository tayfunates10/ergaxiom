# Ergaxiom Current Capability Status

This document records what the repository can currently prove. It is deliberately narrower than the long-term product vision.

A capability is marked **certified path** only when the repository has an automated evidence chain that reaches an independently verified Acceptance Certificate. **Demonstrated** means real execution exists but the complete profession-level claim set is not yet certified. **Implemented** means the deterministic component and attack tests exist. **Planned** means the capability is not present as a production runtime.

## Capability matrix

| Area | Status | Current boundary |
|---|---|---|
| Normative Work Contract, Profession Capsule and Evidence Bundle schemas | Implemented | Draft schemas remain versioned and subject to pre-alpha change. |
| Canonical JSON and SHA-256 sealing | Implemented | Used by contracts, plans, approvals, command receipts, evidence and certificates. |
| Three-valued proof kernel | Implemented | Mandatory `FALSE`, `UNKNOWN`, missing and contradictory proof states fail closed. |
| Property-based impossible-acceptance tests | Implemented | Generated states cannot accept missing mandatory proof. |
| Work Contract and capsule runtime compilation | Implemented | Compiles typed contracts and version-pinned profession capsules. |
| Deterministic intent-to-contract compilation | Implemented | Static Social Media Post, Image Background Cleanup, Brand-Compliant Image Export and Print-Ready Poster Preflight compile structured resolved intents. Unrestricted natural-language interpretation is not claimed. |
| Typed planner synthesis | Implemented | All four initial Graphic Designer jobs synthesize deterministic plans using capsule-approved operators. General planning is not claimed. |
| Operator Plan compilation and trace conformance | Implemented | Plans may use only capsule-approved, version-pinned operators. |
| Signed capability tokens and authorization receipts | Implemented | Direct-Ed25519, DPAPI signer-bound and separate P-256 production-bound tokens are contract, capsule, plan, step, operator, executor and optional-device bound. The permanent Linux and Windows production-signer matrix passed formatting, warnings-deny Clippy and attack tests. |
| Purpose-locked Capability Token issuance | Implemented | DPAPI and P-256 authorities compute the canonical payload digest and fix the Capability role, issuer, key ID and signer request ID. The P-256 authority additionally verifies the public trust snapshot and sealed caller-authorization receipt before returning the token. |
| Authorized execution trace | Implemented | Receipt use and plan state are independently recomputed. |
| Occupational Twin | Implemented | Isolated deterministic workspace, immutable inputs, rollback, checkpoints and replay packages. |
| Evidence Runtime | Implemented | Evidence Bundles cannot self-assert acceptance. |
| Ed25519 Acceptance Certificates | Implemented | Direct and signer-bound issuance independently reassess the exact Evidence Bundle before signing. Existing direct-Ed25519 packages remain backward compatible. |
| Purpose-locked Acceptance Certificate issuance | Implemented | DPAPI and P-256 authorities require Evidence Runtime `ACCEPTED` with zero failed or unknown mandatory obligations before signing. The P-256 package has a separate public-trust verifier and independently recomputes the Replay Manifest from the Evidence Bundle. |
| Backend-authorized purpose-locked issuance | Implemented | Capability issuance requires an exact `Approved` snapshot, non-expired approval, applied approve receipt, compiled step/operator and contract permission. Attestation issuance requires an exact `Executed` snapshot, applied execute receipt, accepted Evidence Bundle and independently rebuilt Replay Manifest. Authorizations are one-shot and consumed before signer invocation. No renderer issuance command exists. |
| Role-separated public-key governance | Implemented | Capability, execution, normalization, attestation and release Ed25519 verification keys are role, issuer, key ID, validity-window, revision and registry-digest bound. Public-key reuse, stale updates and role confusion fail closed. P-256 governed rotation and revocation are not yet integrated. |
| Governed capability and attestation verification | Implemented | Direct and DPAPI signer-bound Capability Tokens plus Acceptance Certificates pass through the current Ed25519 governed registry. Production P-256 packages use fixed public trust snapshots but are not yet routed through an algorithm-agile governed registry. |
| Deterministic release evidence | Implemented | SPDX 2.3 dependency inventory, source/toolchain/artifact manifest and sorted SHA-256 checksums reproduce from identical inputs. Permanent Windows CI compiles an unsigned candidate and proves it remains explicitly ineligible without signing and installer-provenance evidence. |
| Windows DPAPI isolated signer | Implemented | A separate one-request signer process protects persisted Ed25519 seeds with DPAPI CurrentUser and identity-specific entropy, accepts only role-bound lowercase SHA-256 digests, persists replay markers and returns public material only. This is a development/backward-compatibility signer, not TPM non-exportability or protection from arbitrary malicious same-user code. |
| Windows TPM/CNG issuer signer foundation | Implemented | Fixed Capability and Attestation identities use a Microsoft Platform Crypto Provider, ECDSA P-256/SHA-256, non-exportable signing-only key policy, public-only descriptors and handle-only signing contracts. Hosted runners keep assurance `UNPROVEN`; no software-provider or DPAPI fallback can claim production eligibility. |
| Authenticated local production signer service | Implemented | A revisioned caller allowlist, PID creation-time guard, SID/session/path/image-digest binding, service-instance binding, replay-before-backend ordering, sealed public trust snapshot and explicit local message-mode named-pipe ACL are implemented and Windows-tested. Purpose-locked Capability and Attestation runtimes are wired to the transport. Hardened Windows-service deployment and persisted trust rotation remain open. |
| Windows production release signing | Planned | Authenticode, trusted timestamps, certificate-chain verification and signed installer upgrade/rollback provenance are not implemented. The CNG issuer-signer foundation does not make unsigned Windows artifacts release-eligible. |
| Windows Bridge protocol | Implemented | Signed pre-state, action-boundary state, post-state and TOCTOU checks. |
| Windows UI Automation host and Rust client | Demonstrated | Real bounded action against a controlled WPF target; not arbitrary Windows application control. |
| Inkscape adapter | Demonstrated | Exact binary binding, source immutability, action-boundary checks and a restricted proof-bound operator set with real Inkscape regression. |
| Proof-bound Inkscape canvas, layer, asset, text, color and geometry operators | Implemented | Ten version-pinned capabilities support canvas resize, layer creation, digest-bound asset placement, explicit text, fill, transform, align, distribute, editable SVG save and profiled PNG/SVG/PDF export. Unsupported SVG structures fail closed. |
| Signed Inkscape execution evidence | Implemented | Source, editable SVG, rendered output, semantic snapshots, application identity and signature are bound. |
| Independent PNG container validation | Implemented | Chunk ordering, CRC, dimensions, media type and color-profile evidence. |
| Restricted sRGB normalization | Implemented | Adds sRGB evidence only to proven restricted SVG material without changing IDAT bytes. |
| Independent PNG pixel decoding | Implemented | Restricted 8-bit non-interlaced RGB/RGBA profile with independent zlib and filter reconstruction. |
| Rendered contrast validation | Implemented | Validates a declared text region using independently decoded pixels. |
| Rendered logo geometry and clear space | Implemented | Validates a declared placement against a transparent approved PNG mask. |
| Rendered text bounds, safe area and clipping guard | Implemented | Validates visible foreground inside a declared text-only analysis region. |
| Editable SVG approved-copy identity | Implemented | Independently parses one direct-text SVG element and compares exact approved UTF-8 copy. |
| Cross-validator final artifact binding | Implemented | Requires all raster validators to share the exact normalized PNG and pixel decode. |
| Independent restricted PDF preflight | Implemented | Recomputes one-page PDF boxes, resources, vector-only state, outlined-font state, allowed color spaces, transparency and security boundaries. |
| Static Social Media Post final certificate | Certified path | Synthetic end-to-end material reaches a certificate over signed execution, normalization and independent artifact proofs. Permanent real-Inkscape regressions cover bounded execution and final artifact certification. |
| Image Background Cleanup final certificate | Certified path | Applies an explicitly approved digest-bound binary alpha mask without guessing segmentation, independently proves exact foreground preservation and transparent background samples, runs a pinned Inkscape integration probe and verifies an Ed25519 Acceptance Certificate. |
| Brand-Compliant Image Export final certificate | Certified path | Independently proves exact restricted-SVG brand rules, exports through pinned Inkscape, preserves IDAT during sRGB normalization and verifies a signed Acceptance Certificate. |
| Print-Ready Poster Preflight final certificate | Certified path | Independently proves bounded flat-vector source geometry, bleed, safe area, palette, PDF page boxes, vector-only resources, outlined fonts, approved color spaces, transparency absence, security boundaries and pinned Inkscape export before issuing a certificate. |
| Desktop product shell | Implemented | Tauri/React shell displays immutable inputs, resolution state, contract, permissions, sealed plan, execution, validators, evidence, certificate state and backend command receipts. Renderer mutation cannot forge acceptance. |
| Digest-bound desktop control authority | Implemented | Rust owns an in-memory approval, execution, cancellation and rollback lifecycle for the bounded static-post fixture. Stale snapshots, altered tuples, expired approvals, replayed transitions and modified receipts fail closed. Approval hashes are not production signatures. |
| General application learning | Planned | No live-learning or self-modifying production capability is allowed. |
| Cross-platform bridges | Planned | The proof kernel is platform-neutral; bounded Windows UI Automation and platform-bound Inkscape paths exist. |

## Phase assessment

### Phase 0 — Verifiable foundation

**Exit gate: satisfied.** Normative schemas, cross-document validation, first capsule and complete example contracts are present and exercised by CI.

### Phase 1 — Proof kernel

**Exit gate: satisfied for v1.** Canonical sealing, three-valued acceptance, validator independence, capability authorization, evidence reassessment, replay manifests, signatures and property-based fail-closed tests are implemented.

### Phase 2 — Occupational digital twin

**Exit gate: satisfied for v1.** Immutable input staging, typed operations, atomic postconditions, rollback, trace conformance and replay material are implemented and attack-tested.

### Phase 3 — Windows execution bridge

**Status: demonstrated, not closed.** A genuine WPF UI Automation action is signed and independently verified. A bounded DPAPI signer, purpose-locked Ed25519 issuance, backend issuance authorization, a CNG/P-256 issuer-signer foundation, authenticated local signer-service boundary and production Capability/Attestation issuance runtimes now exist and pass the permanent Linux/Windows matrix. The phase remains open because physical-TPM assurance is unproven, hardened service deployment, persistent trust lifecycle, broader UI patterns, recovery, code signing and real-user deployment hardening are incomplete.

### Phase 4 — Graphic Designer Alpha

**Exit gate: satisfied for v1.** Static Social Media Post, bounded binary-mask Image Background Cleanup, Brand-Compliant Image Export and bounded flat-vector Print-Ready Poster Preflight each have normative contracts, deterministic intent compilers, typed plans, independent validators, actionable failure maps, real Inkscape integration, Evidence Bundle reassessment, verified Acceptance Certificates and permanent CI.

This does not claim unrestricted design automation, general commercial-print certification, CMYK conversion, spot-color validation, overprint simulation, PDF/X compliance or unrestricted raster-image DPI analysis.

### Windows Product Alpha control gate

**Status: implemented for one bounded fixture, product gate remains open.** The desktop application can review and submit the exact snapshot, contract, plan and permission tuple; Rust issues an expiring approval and owns execution, cancellation, rollback and audit receipts. Public Ed25519 verification-key roles, rotation, revocation, deterministic unsigned release evidence, a separate DPAPI signer, purpose-locked issuance, one-shot backend authorization, a CNG/P-256 key-provider contract, authenticated local signer-service boundary and P-256 Capability/Attestation issuance runtimes are implemented and CI-verified. The renderer exposes no issuance command. Persistent user-selected jobs, real Evidence Bundle loading, deployed internal CNG service orchestration, independently proven physical-TPM keys, P-256 governance, Authenticode, signed installer provenance and all four profession paths in one user-driven desktop flow remain open.

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
7. Binary-mask Image Background Cleanup with authorized trace reassessment, independent PNG proofs, real Inkscape integration and a verified Acceptance Certificate.
8. Brand-Compliant Image Export with restricted SVG rules, signed execution, IDAT-preserving sRGB normalization, real Inkscape export and a verified Acceptance Certificate.
9. Print-Ready Poster Preflight with restricted outlined-vector SVG validation, deterministic PDF boxes, independent PDF resource/security proofs, real Inkscape export and a verified Acceptance Certificate.
10. Digest-bound desktop approval and execution lifecycle with stale-state rejection, expiry, cancellation, rollback and canonical command receipts.
11. Role-separated Ed25519 public-key governance with rotation, revocation, stale-registry rejection, governed Capability Token and Acceptance Certificate verification, reproducible SPDX/manifest/checksum evidence and fail-closed unsigned Windows candidates.
12. Separate Windows signer executable with DPAPI CurrentUser at-rest protection, role-bound digest-only signatures, persistent replay rejection, generic error responses and real Windows process-isolation tests.
13. Purpose-locked signer-bound Capability Token issuance with fixed role, issuer and key identity, backend-computed payload digests, trusted-public-key matching, governed revocation and real Windows child-process verification.
14. Purpose-locked signer-bound Acceptance Certificate issuance with Evidence Runtime reassessment before signing, deterministic Replay Manifest binding, fixed Attestation identity, governed revocation and real Windows DPAPI child-process verification.
15. One-shot backend authorization for purpose-locked Capability Token and Acceptance Certificate issuance, bound to exact approval, command receipt, snapshot, contract, plan, permission, Evidence Bundle and Replay Manifest material.
16. TPM/CNG issuer-signer foundation with fixed Capability and Attestation identities, non-exportable signing-only P-256 key policy, handle-only CNG signing, P-256 protocol verification, authenticated caller and service-instance binding, replay-before-backend ordering and explicit local named-pipe security.
17. Purpose-locked P-256 Capability Token and Acceptance Certificate issuance with sealed public trust snapshots, independent receipt sealing, backward-compatible artifact types, Evidence Bundle/Replay Manifest reassessment and permanent Linux/Windows CI.

## Next gates

1. Add an independently trusted physical-TPM evidence gate, separate administrator provisioning executable and algorithm-agile P-256 key governance.
2. Deploy the authenticated signer as a hardened Windows service and persist/rotate signed trust snapshots.
3. Add Authenticode, trusted timestamps, certificate-chain verification and signed installer upgrade/rollback provenance.
4. Replace the bounded desktop fixture with persistent user-selected immutable inputs, load real Evidence Bundles and internally route all four certified Graphic Designer job types through the deployed backend issuance policy.
5. Expand the Windows Bridge across real application patterns and recovery cases.
6. Build the Profession Learning Laboratory in a cryptographically separate environment.
7. Add cross-platform bridges and additional profession capsules only after the Windows Product Alpha gates hold.

## Non-negotiable rule

A passing model response, application return code, screenshot, click, keystroke, declared success field or executor-generated digest is never sufficient proof by itself. Unsupported claims remain `UNKNOWN` and cannot be promoted by product messaging, UI state or certificate wording.
