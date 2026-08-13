# Ergaxiom release readiness

## Current decision

The repository can produce an **unsigned pre-alpha validation candidate**, but it must not be presented as a production-ready Windows release. The deterministic release manifest keeps `schema_version` at `0.2.0` and derives `release_eligible` from mandatory blockers; the current unsigned path remains `false` until signing, hardware, installation and recovery evidence is proven.

## Automated software gates

| Gate | Current state | Evidence |
|---|---|---|
| Schema catalog | Implemented | Every JSON Schema is Draft 2020-12 validated. |
| Profession inventory | Implemented | Catalog ID/version/path/digest/job inventory is fail-closed; unregistered capsule files are rejected. |
| Work Contract coverage | Implemented | Every example contract is discovered and bound to a registered capsule version and job type; certified jobs require coverage. |
| Profession extension attacks | Implemented | Substitution, traversal, duplicate identity/path, downgrade and missing-reference classes fail closed. |
| Profession scaffold | Implemented | Existing catalog/capsule integrity is verified before writes; scaffold paths are confined and new capsules remain draft, planned, production-disabled, E0, network-denied and live-learning-disabled. |
| Desktop renderer | Implemented | TypeScript check, trust-boundary tests and production Vite build. |
| JavaScript dependency audit | Implemented | Both desktop CI and the Windows release-candidate path reject high-severity `npm audit` findings after `npm ci`. |
| Rust dependency audit | Implemented in CI | The pinned RustSec action audits `Cargo.lock`; release/security CI first rejects a stale lock with `cargo metadata --locked`. |
| Rust formatting, Clippy and tests | Implemented in CI | Linux and Windows workflows remain mandatory for changed Rust paths. |
| Deterministic SBOM, manifest and checksums | Implemented | Identical inputs reproduce SPDX 2.3 inventory and release evidence. The manifest binds the exact source commit, both lockfiles, profession catalog and a deterministic inventory of every registered capsule, example Work Contract and foundation schema. |
| Source identity binding | Implemented | Release-evidence jobs check out the exact PR head/source SHA and reject a checkout/evidence SHA mismatch instead of labeling a synthetic PR merge tree as the source commit. |
| Unsigned-candidate rejection | Implemented | Current signing/provenance blockers deterministically keep `release_eligible: false`. |

## Production release blockers

These gates cannot be satisfied by source changes or hosted CI alone:

1. Provision the Capability and Attestation keys on controlled Windows hardware and retain independently reviewed physical-TPM evidence.
2. Establish governance-key custody, rotation, backup, revocation and recovery procedures.
3. Install the fixed LocalSystem signer service and protected policy stores through an elevated, recorded ceremony; test restart and recovery.
4. Complete Issue #62: persist and recover the full approved Capability → execution receipts → Evidence Bundle → Replay Manifest → Acceptance Certificate chain through the installed signer.
5. Replace the bounded desktop fixture with immutable user-selected inputs and route all four certified Graphic Designer jobs through the same lifecycle.
6. Sign the desktop, Windows host, adapters and MSI/NSIS installer with Authenticode and a trusted timestamp; independently verify the certificate chain and exact binary identities.
7. Attack-test signed installer install, upgrade, downgrade prevention, rollback and uninstall recovery.
8. Choose and add the project's distribution license before presenting the public repository as reusable open-source software.

## Required validation before a release candidate

```bash
python tools/validate_schema_catalog.py
python tools/validate_foundation.py
python -m unittest \
  tools.test_validate_foundation \
  tools.test_scaffold_profession \
  tools.release.test_generate_release_evidence
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

Windows-only signer, service, Tauri and real-Inkscape gates must also pass on the exact release commit. A release candidate must be rebuilt from that exact commit and compared with its recorded toolchain, lockfiles, SBOM, foundation inventory, checksums and signed provenance.

## Profession extension rule

New professions start with `tools/scaffold_profession.py`. Catalog membership never grants execution or certification. Before any mutation, the scaffold verifies the current catalog structure and every registered capsule identity/version/digest, rejects conflicting paths and identities, and uses an atomic catalog replacement boundary. A generated capsule is always draft, planned and production-disabled with E0 assurance, network denied, self-verification denied, irreversible approval required and live learning disabled.

A job becomes certifiable only after its typed runtime, independent validators, evidence chain, attack suite and real bounded application path reach an independently verified Acceptance Certificate.
