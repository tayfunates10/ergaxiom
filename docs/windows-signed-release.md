# Signed Windows release boundary

Issue #78 makes Windows release eligibility fail closed. The canonical installer is NSIS with per-machine scope, `%ProgramFiles%\Ergaxiom` as the application root and downgrades disabled. The shipped inventory is fixed to `ergaxiom-desktop.exe`, `ergaxiom-windows-production-signer-service.exe` and exactly one `*-setup.exe` installer. UIA, Windows bridge and Inkscape adapter code are recorded as linked runtime inputs rather than separate shipped executables.

## Authenticode policy

`tools/release/windows_release_policy.json` is the source-controlled signing policy. Production evidence requires an owner-approved exact certificate subject and DER SHA-256 pin, the fixed Windows certificate store, code-signing EKU, SHA-256 Authenticode, SHA-256 RFC3161 timestamping through the fixed HTTPS endpoint, a valid non-self-signed chain and online revocation checking. Workflow arguments cannot replace those identities.

The repository intentionally contains no real private key or production certificate. The current policy remains `OWNER_CERTIFICATE_PIN_REQUIRED`, so signing fails before an artifact is touched. After the owner selects the real certificate the policy must be changed to `OWNER_APPROVED_PINNED` with its exact subject and DER SHA-256. Private-key material remains external to Git and is never exported by these scripts.

`sign_windows_release.ps1` resolves exactly one pinned certificate and signs through SignTool. `verify_windows_signatures.ps1` independently recomputes artifact hashes, verifies Authenticode, signer/timestamp certificates, code-signing EKU, chain and online revocation.

## Installer and production signer-service boundary

`apps/desktop/src-tauri/tauri.release.conf.json` selects NSIS, `perMachine`, `allowDowngrades: false`, and packages the already-signed production signer-service executable. The installer does not manufacture production trust state. Installing/validating `ErgaxiomProductionSigner` as LocalSystem remains the controlled Issue #77 ceremony because the manifest binds the exact service executable digest, trust state, caller allowlist, deployment policy and active TPM/CNG generations.

A copied service executable never enables production issuance. Production acceptance requires the canonical `tools/windows/controlled_trust_gate.py` verifier to re-read all six raw Issue #77 evidence files. A pre-computed `verified: true` hardware summary is deliberately insufficient.

The six mandatory raw files are Capability provisioning evidence, Attestation provisioning evidence, physical TPM promotion evidence, governance recovery receipt, LocalSystem installation receipt, and restart/recovery receipt. The finalizer additionally requires the installation and both restart snapshots to contain the same signer-service SHA-256 as the signed release artifact.

## Installer lifecycle coverage

Hosted Windows CI creates real version `0.0.9` and `0.1.0` NSIS installers and tests clean install, normal upgrade, downgrade rejection, deterministic interrupted upgrade, recovery, uninstall and `%ProgramData%\Ergaxiom` state preservation. This record always says `test_mode: true` and can never satisfy production eligibility.

Controlled production lifecycle evidence must be bound to the exact source commit and signed installer SHA-256 with `test_mode: false`. It must prove all of: clean install, LocalSystem service installation, running-service validation, protected-state ACL verification, upgrade, downgrade rejection, interrupted-upgrade state preservation, rollback/recovery, recovery install, uninstall, and production-state preservation.

## Two-stage signed release protocol

A real Issue #77 ceremony cannot precede Authenticode signing because its installation receipt must bind the **exact signed signer-service hash**. RFC3161 timestamping changes the signed PE bytes, so rebuilding/re-signing after the ceremony would invalidate the hardware binding. For that reason the production flow is deliberately split into two immutable stages.

### Stage A — prepare the exact signed candidate

Run on the exact clean release commit with the owner-pinned real certificate available:

```powershell
./tools/release/build_signed_windows_release.ps1 `
  -Mode Prepare `
  -OutputDirectory C:\ergaxiom-release\candidate
```

This delegates to `prepare_signed_windows_release.ps1`, builds the locked desktop and signer service, Authenticode-signs both, bundles the canonical NSIS installer, signs it, independently re-verifies all three signatures, writes deterministic base release evidence, and emits `signed-candidate-handoff.json`. The handoff is explicitly `SIGNED_CANDIDATE_NOT_RELEASED` / `release_eligible: false`.

The physical Issue #77 ceremony must then install and recover **that exact** `candidate\artifacts\ergaxiom-windows-production-signer-service.exe`. Do not rebuild or re-sign the candidate after the ceremony.

### Stage B — finalize the same immutable candidate

After the controlled lifecycle, #75 production-chain evidence, six #77 raw evidence files and owner license decision exist:

```powershell
./tools/release/build_signed_windows_release.ps1 `
  -Mode Finalize `
  -PreparedReleaseDirectory C:\ergaxiom-release\candidate `
  -LifecycleEvidence C:\evidence\controlled-installer-lifecycle.json `
  -ProductionChainEvidence C:\evidence\issue-75-production-chain.json `
  -CapabilityProvisioningEvidence C:\evidence\capability-provisioning.json `
  -AttestationProvisioningEvidence C:\evidence\attestation-provisioning.json `
  -PhysicalTpmPromotionEvidence C:\evidence\physical-tpm-promotion.json `
  -GovernanceRecoveryReceipt C:\evidence\governance-recovery.json `
  -SignerInstallationReceipt C:\evidence\signer-installation.json `
  -SignerRestartRecoveryReceipt C:\evidence\signer-restart-recovery.json `
  -LicenseDecision C:\evidence\owner-license-decision.json `
  -OutputDirectory C:\ergaxiom-release\final
```

`finalize_prepared_windows_release.ps1` refuses source-commit drift, dirty tracked source, artifact cardinality/name substitution or any post-prepare SHA-256 mutation. It re-verifies Authenticode on the prepared files, reruns the canonical #77 controlled-trust verifier over all raw ceremony files, and only then invokes the final release decision.

## Production-chain fail-closed boundary

Issue #75 currently has no standalone canonical production-chain verifier in its branch. Therefore `finalize_windows_release_evidence.py` deliberately **does not trust** a caller-authored `production_chain` JSON even when it contains `verified: true`. Until a canonical #75 verifier/export contract is available and integrated, the explicit blocker `PRODUCTION_CHAIN_CANONICAL_VERIFIER_NOT_INTEGRATED` remains present. This avoids turning a summary file into production authority.

Once #75 supplies that verifier, it must independently bind the persisted production Capability Token, authorization/command/execution receipts, Evidence Bundle, Replay Manifest, Acceptance Certificate, recovery state and exact source/artifact identities. The #78 gate will consume that canonical proof; it will not weaken to a boolean summary.

## Final release evidence and attacks

`tools/release/finalize_windows_release_evidence.py` rejects partial/substituted inventories, post-sign mutation, test identities, failed SignTool verification, missing code-signing EKU, wrong subject/certificate pin, invalid/revoked/untrusted chain, missing/untrusted timestamp, incomplete production lifecycle, generic hardware summaries, missing raw controlled-trust evidence, signer-service hash substitution, missing canonical #75 verification and unresolved license evidence.

A signed artifact by itself is not a production release. Final `release_eligible: true` requires every independent gate to be proven for the exact candidate.

## CI and review

`.github/workflows/windows-signed-release.yml` runs release attack tests, the canonical controlled-trust verifier tests, unsigned-candidate rejection and the real hosted NSIS lifecycle matrix. Hosted artifacts are explicitly test-only/not-production. Workflow checkouts are pinned to the exact PR head source commit.

Before publication an independent controlled Windows reviewer must reproduce the prepared artifact hashes, inspect the exact #77 installation/recovery evidence, verify #75 production evidence through its canonical verifier, rerun signature/chain/timestamp checks, validate the signed installer lifecycle, and confirm the final manifest says exactly `release_eligible: true`.

## Current blockers

Production remains intentionally blocked. There is no owner-pinned real code-signing certificate, no owner-selected SPDX license, no controlled production installer lifecycle evidence, no final canonical Issue #75 production-chain verifier/evidence, and no physical Issue #77 ceremony against this exact signed candidate. Hosted CI cannot replace any of those gates.
