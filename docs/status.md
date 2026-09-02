# Ergaxiom Current Capability Status

This document is the canonical claim boundary for the current repository. It records only capabilities supported by the checked-in implementation and mandatory validation gates. Unsupported claims remain `UNKNOWN`.

## Foundation

| Area | Status | Current boundary |
|---|---|---|
| Schemas and proof kernel | Implemented | Mandatory false, unknown, missing and contradictory evidence fail closed. |
| Contract compilation and typed planning | Implemented | The four bounded Graphic Designer jobs compile resolved structured intent into capsule-approved deterministic plans. General natural-language compilation is not claimed. |
| Profession catalog | Implemented | Every installed capsule is bound by confined path, ID, version, canonical digest, lifecycle state and exact job inventory. Example contracts must reference registered capsule versions and job types. |
| Profession scaffold | Implemented | Existing catalog/capsule integrity is checked before mutation; conflicting IDs/paths and unsafe filesystem boundaries are rejected. New capsules are draft, planned, production-disabled, E0, network-denied and live-learning-disabled. |
| Profession Learning Laboratory | Implemented, isolated | Provenance-bound demonstrations can synthesize proposal-only candidates only for Occupational Twin / isolated test. Zero failures and zero `UNKNOWN`, independent human review, canary, revocation and rollback evidence are required; the laboratory has no production-signing or automatic-production authority. |
| Evidence and replay | Implemented | Executor self-assertion cannot complete acceptance; mandatory evidence is independently reassessed. |
| Desktop control shell | Implemented for one bounded fixture | Rust owns approval/execution state; renderer state cannot forge acceptance. |
| Windows UI Automation and Inkscape bridges | Demonstrated | Real bounded paths exist; arbitrary desktop control is not claimed. |

## Profession baseline

The installed Graphic Designer profession is `ergaxiom.profession.graphic-designer` capsule **v0.6.0**. The catalog defines exactly four certified job identities:

1. `social_media_static_post`
2. `image_background_cleanup`
3. `brand_compliant_image_export`
4. `print_ready_poster_preflight`

The Graphic Designer catalog entry remains production-disabled. Certification applies only to the exact bounded operators, validators, artifacts and evidence chains covered by the permanent tests.

A second demonstration profession, `ergaxiom.profession.technical-writer`, proves the extension pipeline with the single `plain_text_revision` job. It remains `draft`, `planned`, `production_enabled: false` and `live_learning_allowed: false`; it is not claimed as a production-certified profession.

## Release and security baseline

Deterministic release evidence remains `schema_version: 0.2.0`. It binds the exact checked-out source commit, `Cargo.lock`, desktop `package-lock.json`, the profession catalog, every registered Profession Capsule, every example Work Contract and every foundation schema. Foundation inventory and digests are deterministic; invalid or mismatched catalog/capsule/contract references fail closed.

Unsigned candidates remain `release_eligible: false` until all mandatory production signing and installer-provenance blockers are independently satisfied.

Dependency security is blocking:

- desktop candidates run `npm ci` and `npm audit --audit-level=high`;
- Rust release/security paths reject stale lockfiles with `cargo metadata --locked`;
- the pinned RustSec audit evaluates the checked-in lock graph; and
- no advisory ignore or gate weakening is permitted.

## Phase assessment

| Phase | Gate |
|---|---|
| Verifiable foundation | Satisfied for v1 |
| Proof kernel | Satisfied for v1 |
| Occupational Twin | Satisfied for v1 |
| Windows execution bridge | Demonstrated; production deployment gates remain open |
| Graphic Designer Alpha | Satisfied for the four bounded certified jobs |
| Windows Product Alpha | Control and trust foundations implemented; persistent installed-backend and signed-release gates remain open |
| Profession Learning Laboratory | Source-complete for the isolated proposal/certification/canary lifecycle; production promotion remains outside laboratory authority |
| Additional professions/platforms | Technical Writer demonstration capsule proves the extension path but remains draft/planned/production-disabled |

## Open production gates

The repository does not yet claim unrestricted desktop work, completed production installer provenance, general application learning or a second production-certified profession. The detailed remaining product gates are maintained in [release-readiness.md](release-readiness.md) and [roadmap.md](roadmap.md).

## Mandatory validation

A canonical baseline is not ready while any required check is failing or pending:

```bash
python tools/validate_schema_catalog.py
python tools/validate_foundation.py
python -m unittest tools.test_validate_foundation tools.test_scaffold_profession tools.test_profession_lab tools.release.test_generate_release_evidence
python -m compileall -q tools

cd apps/desktop
npm ci
npm audit --audit-level=high
npm test
npm run build

cd ../..
cargo metadata --locked --format-version 1 --no-deps > /dev/null
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
git diff --check
```

Windows-specific signer/service/Tauri, the four Graphic Designer certified-path regressions and real-Inkscape regressions must pass on the final canonical-base PR HEAD. No security, provenance, assurance, validator or evidence gate may be weakened to obtain a green result.
