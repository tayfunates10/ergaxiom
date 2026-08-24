# Signed Windows release boundary

Issue #78 makes Windows release eligibility fail closed. The canonical installer is NSIS with per-machine scope, `%ProgramFiles%\Ergaxiom` as the application root and downgrades disabled. Windows update execution is pinned to Tauri's **quiet** NSIS updater contract (`/S /UPDATE`) instead of inheriting an implicit updater UI default. The shipped inventory is fixed to `ergaxiom-desktop.exe`, `ergaxiom-windows-production-signer-service.exe` and exactly one `*-setup.exe` installer. UIA, Windows bridge and Inkscape adapter code are recorded as linked runtime inputs rather than separate shipped executables.

## Authenticode policy

`tools/release/windows_release_policy.json` is the source-controlled signing policy. Production evidence requires an owner-approved exact certificate subject and DER SHA-256 pin, the fixed Windows certificate store, code-signing EKU, SHA-256 Authenticode, SHA-256 RFC3161 timestamping through the fixed HTTPS endpoint, a valid non-self-signed chain and online revocation checking. Workflow arguments cannot replace those identities.

The repository intentionally contains no real private key or production certificate. The current policy remains `OWNER_CERTIFICATE_PIN_REQUIRED`, so signing fails before an artifact is touched. After the owner selects the real certificate the policy must be changed to `OWNER_APPROVED_PINNED` with its exact subject and DER SHA-256. Private-key material remains external to Git and is never exported by these scripts.

`sign_windows_release.ps1` resolves exactly one pinned certificate and signs through SignTool. `verify_windows_signatures.ps1` independently recomputes artifact hashes, verifies Authenticode, signer/timestamp certificates, code-signing EKU, chain and online revocation.

## Controlled production host preflight

Before changing the signing policy or running a ceremony, use the read-only host inventory on the intended physical Windows machine:

```powershell
./tools/release/check_production_windows_host.ps1 `
  -PolicyPath tools/release/windows_release_policy.json `
  -OutputPath C:\evidence\production-host-preflight.json
```

The report checks the clean source commit, Administrator context, Git/Rust/Node/Python/SignTool availability, TPM present/ready/enabled/activated state, `Microsoft Platform Crypto Provider`, and all code-signing certificate candidates in the configured Windows certificate store.

### Locale-independent CNG provider detection

`Microsoft Platform Crypto Provider` presence is resolved by `tools/release/detect_platform_crypto_provider.ps1`, which the preflight invokes and embeds under `microsoft_platform_crypto_provider` next to the `microsoft_platform_crypto_provider_present` summary flag. Detection is ordered and each step is a real probe:

1. `NCryptOpenStorageProvider` — the provider is registered and can actually be opened. Authoritative.
2. `NCryptEnumStorageProviders` — the exact provider name appears in the live CNG registration list. Authoritative.
3. `certutil -csplist` — corroborating only.

Both native probes are locale independent. `certutil -csplist` renders localized labels on non-English Windows and can exit non-zero because of an unrelated provider, so the previous exit-code-plus-string match could report a false negative on a localized host with a working TPM KSP. It is now a tertiary probe and is no longer able to veto a successful native probe.

Detection is still fail closed in both directions. A failed or unavailable probe never becomes `true`: the recorded status code and error are kept, `present` stays `false` and `detection_method` stays `null`. Presence is only reported when a probe genuinely succeeded, and the reported `detection_method` names which one. Opening the provider proves the KSP is loadable, not that a TPM key exists, so `ready_for_controlled_hardware_ceremony` still additionally requires elevation and TPM present/ready/enabled/activated, and `physical_tpm_evidence_proven` remains permanently `false` in this report.

`host-preflight-selftest` in the `Windows release evidence` workflow is the repository-controlled regression test for this. On hosted Windows it asserts that the native probes really ran, that a genuinely registered provider (`Microsoft Software Key Storage Provider`) is detected through `NCryptOpenStorageProvider`, that a fabricated provider name is rejected by every probe, that the summary flag matches the detail record, and that `-RequireReady` still fails closed. Hosted CI is never physical TPM evidence. Certificate output is public metadata only: subject, DER SHA-256, thumbprint, validity and whether a private key is available. It never exports a private key, PIN or token secret and it always records `physical_tpm_evidence_proven: false` and `release_eligible: false` because preflight is not ceremony evidence.

Before Stage A, the owner-approved certificate must be pinned in `windows_release_policy.json`. Re-run the same preflight with `-RequireReady`; it fails unless the exact pinned certificate is uniquely available and the controlled hardware prerequisites are ready.

## Installer and production signer-service boundary

`apps/desktop/src-tauri/tauri.release.conf.json` selects NSIS, `perMachine`, `allowDowngrades: false`, and packages the already-signed production signer-service executable. `tools/release/windows_release_policy.json` additionally pins `updater_install_mode: quiet`; lifecycle verification rejects any other updater mode. The installer does not manufacture production trust state. Installing/validating `ErgaxiomProductionSigner` as LocalSystem remains the controlled Issue #77 ceremony because the manifest binds the exact service executable digest, trust state, caller allowlist, deployment policy and active TPM/CNG generations.

A copied service executable never enables production issuance. Production acceptance requires the canonical `tools/windows/controlled_trust_gate.py` verifier to re-read all six raw Issue #77 evidence files. A pre-computed `verified: true` hardware summary is deliberately insufficient.

The six mandatory raw files are Capability provisioning evidence, Attestation provisioning evidence, physical TPM promotion evidence, governance recovery receipt, LocalSystem installation receipt, and restart/recovery receipt. The finalizer additionally requires the installation and both restart snapshots to contain the same signer-service SHA-256 as the signed release artifact.

## Installer lifecycle coverage

Hosted Windows CI creates real version `0.0.9` and `0.1.0` NSIS installers and tests clean install, quiet updater upgrade (`/S /UPDATE`), downgrade rejection, deterministic interrupted upgrade, recovery, uninstall and `%ProgramData%\Ergaxiom` state preservation. Registry state must converge to the exact expected version and remain stable before a phase is accepted. This record always says `test_mode: true` and can never satisfy production eligibility.

Controlled production lifecycle evidence must be bound to the exact source commit and signed installer SHA-256 with `test_mode: false`. It must prove all of: clean install, LocalSystem service installation, running-service validation, protected-state ACL verification, upgrade, downgrade rejection, interrupted-upgrade state preservation, rollback/recovery, recovery install, uninstall, and production-state preservation.

## Two-stage signed release protocol

A real Issue #77 ceremony cannot precede Authenticode signing because its installation receipt must bind the **exact signed signer-service hash**. RFC3161 timestamping changes the signed PE bytes, so rebuilding/re-signing after the ceremony would invalidate the hardware binding. For that reason the production flow is deliberately split into two immutable stages.

### Stage A — prepare the exact signed candidate

Run on the exact clean release commit with the owner-pinned real certificate available:

```powershell
./tools/release/check_production_windows_host.ps1 `
  -PolicyPath tools/release/windows_release_policy.json `
  -OutputPath C:\evidence\production-host-preflight.json `
  -RequireReady

./tools/release/build_signed_windows_release.ps1 `
  -Mode Prepare `
  -OutputDirectory C:\ergaxiom-release\candidate
```

This delegates to `prepare_signed_windows_release.ps1`, builds the locked desktop and signer service, Authenticode-signs both, bundles the canonical NSIS installer, signs it, independently re-verifies all three signatures, writes deterministic base release evidence, and emits `signed-candidate-handoff.json`. The handoff is explicitly `SIGNED_CANDIDATE_NOT_RELEASED` / `release_eligible: false`.

The physical Issue #77 ceremony must then install and recover **that exact** `candidate\artifacts\ergaxiom-windows-production-signer-service.exe`. Do not rebuild or re-sign the candidate after the ceremony.

### Owner license evidence for the immutable commit

The owner decision is already approved in repository policy. Generate its exact source-commit-bound evidence from the same clean checkout and write it outside the repository worktree:

```powershell
python tools/release/generate_owner_license_decision.py `
  --repo-root . `
  --output C:\evidence\owner-license-decision.json
```

The generator refuses a dirty tracked worktree, a non-approved policy, a mismatched proprietary SPDX expression or a mismatched root `LICENSE`. It binds the decision to `git rev-parse HEAD`, the canonical policy digest and the `LICENSE` digest.

### Stage B — finalize the same immutable candidate

After controlled lifecycle evidence, the six Issue #77 raw evidence files, the persisted production-chain directory and all raw production verifier inputs exist, finalize the same immutable candidate. The argument names below intentionally mirror the current `build_signed_windows_release.ps1` interface; do not replace them with a precomputed `verified: true` summary.

```powershell
./tools/release/build_signed_windows_release.ps1 `
  -Mode Finalize `
  -PreparedReleaseDirectory C:\ergaxiom-release\candidate `
  -LifecycleEvidence C:\evidence\controlled-installer-lifecycle.json `
  -ProductionChainRoot C:\evidence\production-chain `
  -ProductionJobId <certified-job-id> `
  -ProductionGovernancePolicy C:\evidence\production-governance-policy.json `
  -ProductionTrustStateEnvelope C:\evidence\production-trust-state-envelope.json `
  -ProductionDeploymentPolicy C:\evidence\production-deployment-policy.json `
  -ProductionIdentityChallenge C:\evidence\production-identity-challenge.json `
  -ProductionIdentityProof C:\evidence\production-identity-proof.json `
  -ProductionCompiledContract C:\evidence\production-compiled-contract.json `
  -ProductionCompiledPlan C:\evidence\production-compiled-plan.json `
  -ProductionAssuranceLevel <E0-through-E5> `
  -ProductionExpectedExecutorId <expected-executor-id> `
  -CapabilityProvisioningEvidence C:\evidence\capability-provisioning.json `
  -AttestationProvisioningEvidence C:\evidence\attestation-provisioning.json `
  -PhysicalTpmPromotionEvidence C:\evidence\physical-tpm-evidence.json `
  -GovernanceRecoveryReceipt C:\evidence\governance-recovery.json `
  -SignerInstallationReceipt C:\evidence\installation.json `
  -SignerRestartRecoveryReceipt C:\evidence\recovery.json `
  -LicenseDecision C:\evidence\owner-license-decision.json `
  -OutputDirectory C:\ergaxiom-release\final
```

If the production verifier is device-bound, also pass `-ProductionExpectedDeviceId <expected-device-id>`.

`finalize_prepared_windows_release.ps1` refuses source-commit drift, dirty tracked source, artifact cardinality/name substitution or any post-prepare SHA-256 mutation. It re-verifies Authenticode on the prepared files, reruns the canonical #77 controlled-trust verifier over all raw ceremony files, independently verifies the persisted production execution chain from the raw production inputs, and only then invokes the final release decision.

## Physical TPM / LocalSystem ceremony

The protected `Controlled Windows trust` workflow must be manually dispatched with `run_controlled_hardware=true` on a runner carrying all four labels: `self-hosted`, `windows`, `x64`, `ergaxiom-controlled-tpm`. The job is bound to the `controlled-windows-production` GitHub Environment and fails closed unless it is elevated, TPM state is ready, the Microsoft Platform Crypto Provider policy is satisfied, both production CNG roles are provisioned, the signer service is installed/validated as LocalSystem and restart/recovery evidence verifies.

The Environment must provide these reviewed variables before dispatch:

- `ERGAXIOM_SIGNER_MANIFEST_PATH`
- `ERGAXIOM_GOVERNANCE_RECOVERY_RECEIPT_PATH`
- `ERGAXIOM_MACHINE_INVENTORY_DIGEST`
- `ERGAXIOM_PHYSICAL_HARDWARE_ATTESTATION_DIGEST`
- `ERGAXIOM_OPERATOR_QUORUM_DIGEST`
- `ERGAXIOM_CAPABILITY_GENERATION`
- `ERGAXIOM_ATTESTATION_GENERATION`

The three reviewed digest variables must each be lowercase 64-character SHA-256 values. The workflow emits public evidence only; it must never export CNG private-key material.

## Production-chain fail-closed boundary

`crates/production-execution-runtime/src/bin/verify_production_release_chain.rs` is the release-specific canonical production-chain verifier integrated by this layer. It does not trust a caller-authored `production_chain: { verified: true }` summary. It independently consumes the persisted production-chain state together with the raw Work Contract and Operator Plan, checked-out profession catalog/capsule, governance/trust state, a fresh deployed signer identity challenge/proof, deployment policy and the exact signed signer-service SHA-256.

Release eligibility requires a recovered `Certified` production chain and independent verification of Capability consumption, Evidence Bundle, Replay Manifest and Acceptance Certificate for the same source and artifact identities. Missing, stale, substituted or unverifiable production-chain material remains fail closed.

## Final release evidence and attacks

`tools/release/finalize_windows_release_evidence.py` rejects partial/substituted inventories, post-sign mutation, test identities, failed SignTool verification, missing code-signing EKU, wrong subject/certificate pin, invalid/revoked/untrusted chain, missing/untrusted timestamp, incomplete production lifecycle, generic hardware summaries, missing raw controlled-trust evidence, signer-service hash substitution, unverifiable production-chain evidence and unresolved license evidence.

A signed artifact by itself is not a production release. Final `release_eligible: true` requires every independent gate to be proven for the exact candidate.

## Distribution license decision

The owner selected a proprietary distribution model with all rights reserved. The release policy is `owner_decision_status: APPROVED` with SPDX expression `LicenseRef-Ergaxiom-Proprietary`, and the repository root `LICENSE` contains the corresponding Ergaxiom Proprietary License. Finalization requires the generated source-commit-bound `owner-license-decision.json` whose `spdx_expression` exactly matches that approved policy; this is release evidence for the immutable candidate, not an unresolved owner decision.

## CI and review

`.github/workflows/windows-signed-release.yml` runs release attack tests, owner-license evidence tests, the canonical controlled-trust verifier tests, unsigned-candidate rejection and the real hosted NSIS lifecycle matrix. Every PowerShell release runner is parsed on hosted Windows. Hosted artifacts are explicitly test-only/not-production. Workflow checkouts are pinned to the exact PR head source commit.

Before publication an independent controlled Windows reviewer must reproduce the prepared artifact hashes, inspect the exact #77 installation/recovery evidence, verify #75 production evidence through the canonical release verifier, rerun signature/chain/timestamp checks, validate the signed installer lifecycle, and confirm the final manifest says exactly `release_eligible: true`.

## Current blockers

Production remains intentionally blocked. The owner distribution-license decision is resolved and its exact-commit evidence now has a canonical generator. Remaining external gates are an owner-pinned real code-signing certificate with usable private key, controlled production installer lifecycle evidence for the exact signed candidate, a real persisted `Certified` production job with fresh deployed signer proof for that candidate, and the physical Issue #77 TPM/LocalSystem ceremony against the exact signed signer-service bytes. Hosted CI cannot replace any of those gates.
