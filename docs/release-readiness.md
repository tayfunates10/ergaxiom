# Ergaxiom release readiness

## Current decision

The repository can produce an **unsigned pre-alpha validation candidate**, but it must not be presented as a production-ready Windows release. The deterministic release manifest intentionally sets `release_eligible` to `false` until every mandatory signing, hardware, installation, recovery and licensing gate is proven.

Issue #78 now has a repository-controlled Windows release policy, exact shipping inventory, Authenticode evidence verifier, NSIS packaging configuration and final fail-closed release-evidence decision. Those mechanisms do **not** replace the missing real code-signing identity, controlled installer lifecycle evidence, physical-hardware evidence or owner license decision. See [Signed Windows release boundary](windows-signed-release.md).

## Automated software gates

| Gate | Current state | Evidence |
|---|---|---|
| Schema catalog | Implemented | Every JSON Schema is Draft 2020-12 validated. |
| Profession inventory | Implemented | Catalog ID/version/path/digest/job inventory is fail-closed. |
| Work Contract coverage | Implemented | Every example contract is discovered; every certified job requires coverage. |
| Profession extension attacks | Implemented | Substitution, traversal, duplicate identity, downgrade and missing-reference tests. |
| Desktop renderer | Implemented | TypeScript check, trust-boundary tests and production Vite build. |
| JavaScript dependency audit | Implemented | CI rejects high-severity `npm audit` findings. |
| Rust dependency audit | Implemented in CI | The pinned official RustSec action checks `Cargo.lock`. |
| Rust formatting, Clippy and tests | Implemented in CI | Linux and Windows workflows remain mandatory for changed Rust paths. |
| Deterministic SBOM, manifest and checksums | Implemented | Identical inputs reproduce SPDX 2.3 inventory and release evidence; the manifest explicitly binds the canonical profession catalog digest. |
| Windows shipping inventory | Implemented | Desktop EXE, production signer-service EXE and exactly one NSIS setup EXE are required; partial or substituted inventories fail closed. |
| Windows Authenticode evidence contract | Implemented | Exact post-sign SHA-256, signer identity, chain, revocation and RFC 3161 timestamp evidence are required by the finalizer. |
| Windows installer policy | Implemented | Canonical production packaging is NSIS, per-machine and downgrade-disabled; the signer-service binary is included as a fixed resource. |
| Final Windows release decision | Implemented | Test identities, wrong chain/timestamp/subject, post-sign mutation, test-mode lifecycle evidence and missing external gates keep `release_eligible: false`. |
| Unsigned-candidate rejection | Implemented | Windows CI builds the current unsigned desktop/service/installer candidate and must prove that it cannot self-promote to production eligibility. |

## Production release blockers

These gates cannot be satisfied by source changes or hosted CI alone:

1. Provision the Capability and Attestation keys on controlled Windows hardware and retain independently reviewed physical-TPM evidence.
2. Establish governance-key custody, rotation, backup, revocation and recovery procedures.
3. Install the fixed LocalSystem signer service and protected policy stores through an elevated, recorded ceremony; test restart and recovery.
4. Complete the full approved Capability → execution receipts → Evidence Bundle → Replay Manifest → Acceptance Certificate production chain through the installed signer and bind its exact final evidence to the release commit.
5. Replace the bounded desktop fixture with immutable user-selected inputs and route all four certified Graphic Designer jobs through the same lifecycle.
6. Supply the real owner-approved code-signing certificate identity and private-key operation outside Git, Authenticode-sign the exact desktop/service/installer artifacts, obtain the trusted RFC 3161 timestamp and independently verify the chain and post-sign identities.
7. Produce controlled-machine `test_mode: false` install, upgrade, downgrade-rejection, interrupted-upgrade/rollback-recovery and uninstall evidence bound to the exact signed installer SHA-256. Hosted CI evidence cannot satisfy this gate.
8. Choose and record the project's distribution license before presenting the public repository as reusable open-source software.

## Required validation before a release candidate

```bash
python tools/validate_schema_catalog.py
python tools/validate_foundation.py
python -m unittest \
  tools.test_validate_foundation \
  tools.test_scaffold_profession \
  tools.release.test_generate_release_evidence \
  tools.release.test_finalize_windows_release_evidence

cd apps/desktop
npm ci
npm audit --audit-level=high
npm test
npm run build

cd ../..
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

Windows-only signer, service, Tauri, installer and physical-hardware gates must also pass on the exact release commit. A release candidate must be rebuilt from that commit and compared with its recorded toolchain, lockfiles, SBOM, checksums and signed provenance. `tools/release/finalize_windows_release_evidence.py` is the last release decision and may return `release_eligible: true` only after all exact-commit evidence inputs are independently accepted.

## Profession extension rule

New professions start with `tools/scaffold_profession.py`. The generated capsule is always draft, planned and production-disabled. Catalog membership never grants execution or certification. A job becomes certifiable only after its typed runtime, independent validators, evidence chain, attack suite and real bounded application path reach an independently verified Acceptance Certificate.
