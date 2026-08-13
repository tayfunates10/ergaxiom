# Ergaxiom release readiness

## Current decision

The repository can produce an **unsigned pre-alpha validation candidate**, but it must not be presented as a production-ready Windows release. The deterministic release manifest intentionally sets `release_eligible` to `false` until every mandatory signing, hardware, installation and recovery gate is proven.

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
| Unsigned-candidate rejection | Implemented | Release evidence fails closed with `release_eligible: false`. |

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

Windows-only signer, service, Tauri, installer and physical-hardware gates must also pass on the exact release commit. A release candidate must be rebuilt from that commit and compared with its recorded toolchain, lockfiles, SBOM, checksums and signed provenance.

## Profession extension rule

New professions start with `tools/scaffold_profession.py`. The generated capsule is always draft, planned and production-disabled. Catalog membership never grants execution or certification. A job becomes certifiable only after its typed runtime, independent validators, evidence chain, attack suite and real bounded application path reach an independently verified Acceptance Certificate.
