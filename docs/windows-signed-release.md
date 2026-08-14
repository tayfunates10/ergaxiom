# Signed Windows release boundary

Issue #78 makes Windows release eligibility fail closed. The canonical installer is NSIS with per-machine scope, `%ProgramFiles%\Ergaxiom` as the application root and downgrades disabled. The release artifact inventory is fixed to `ergaxiom-desktop.exe`, `ergaxiom-windows-production-signer-service.exe` and exactly one `*-setup.exe` installer. UIA, Windows bridge and Inkscape adapter code are recorded as linked runtime inputs rather than misrepresented as separately shipped executables.

## Authenticode policy and signing

`tools/release/windows_release_policy.json` is the source-controlled signing policy. Production evidence must match an owner-approved exact certificate subject and DER SHA-256 pin, the fixed Windows certificate store, the code-signing EKU, SHA-256 Authenticode, SHA-256 RFC 3161 timestamping through the fixed HTTPS timestamp endpoint, a valid certificate chain, online revocation checking and a non-self-signed signer. Workflow arguments cannot replace those identities.

The repository intentionally contains no real private key or production certificate. The current policy has `identity_status: OWNER_CERTIFICATE_PIN_REQUIRED`, so `tools/release/sign_windows_release.ps1` refuses to sign before touching an artifact. After the owner selects the real certificate, the policy must be changed to `OWNER_APPROVED_PINNED` with its exact subject and DER SHA-256. The private key remains external to Git and may be hardware/provider backed behind the pinned Windows certificate-store identity; the scripts never export it.

`sign_windows_release.ps1` resolves exactly one matching certificate, requires an available private key and code-signing EKU, rejects self-signed or out-of-validity identities, invokes SignTool with SHA-256 plus RFC 3161/SHA-256 timestamping and immediately verifies every resulting signature.

`tools/release/verify_windows_signatures.ps1` independently recomputes every artifact SHA-256, reads Authenticode signer/timestamp certificates, performs certificate-chain verification, uses online revocation checking in production mode, verifies the code-signing EKU and executes SignTool verification. Its timestamp URL field records the policy endpoint used by the controlled signing procedure; trust in the embedded timestamp is independently established from the signed timestamp certificate and chain rather than from that string alone.

## Installer packaging and signer-service handoff

`apps/desktop/src-tauri/tauri.release.conf.json` selects NSIS, `perMachine`, `allowDowngrades: false`, and packages the already-signed production signer-service executable as an installer resource. The service executable is therefore part of the exact signed release inventory before bundling.

The NSIS package does **not** manufacture production trust state or silently invent a signer manifest. Installing or upgrading the `ErgaxiomProductionSigner` SCM service remains the elevated Issue #77 controlled ceremony because its manifest binds the exact service executable digest, accepted trust state, caller allowlist, deployment policy and active TPM/CNG key generations. Release acceptance requires the Issue #77 installation/recovery evidence for the exact packaged signer binary. Hosted installer tests deliberately do not install the LocalSystem production service.

This split is intentional: the installer owns signed application-file provenance; the controlled trust ceremony owns production service/trust activation. A copied signer executable alone never enables production issuance.

## Real installer lifecycle attack coverage

The CI-only configs create version `0.0.9` and `0.1.0` NSIS installers from the same release source boundary. `tools/release/test_windows_installer_lifecycle.ps1` runs the actual installers elevated on a disposable Windows runner and verifies:

- clean per-machine install and exact desktop/signer-service file inventory;
- normal upgrade from `0.0.9` to `0.1.0` through the Windows uninstall registry;
- attempted downgrade cannot replace the installed `0.1.0` state;
- deterministic interruption before upgrade file replacement exits non-zero;
- the previous installation and a `%ProgramData%\Ergaxiom` state sentinel survive the interruption;
- rerunning the current installer recovers successfully;
- uninstall removes application registration while preserving the state sentinel.

A timeout kills hung installer/uninstaller processes so a dialog or malformed downgrade path cannot silently stall the gate. The generated lifecycle record always has `test_mode: true`; it proves repository-controlled installer mechanics but can never satisfy the production lifecycle gate.

A production lifecycle evidence record is accepted only when it is bound to the exact source commit and exact signed installer SHA-256 and has `test_mode: false` with all phases proven on the controlled Windows machine. The controlled run must additionally be reviewed together with the Issue #77 installation/recovery receipts so production trust state is not confused with the hosted-CI sentinel.

## Controlled final release runner

Once the external gates exist, `tools/release/build_signed_windows_release.ps1` executes the repository-controlled production sequence without further source redesign:

1. require an exact clean Git HEAD and a current locked Cargo graph;
2. run `npm ci`, build the desktop and production signer-service release binaries;
3. sign and verify both PE inputs using only the owner-pinned certificate policy;
4. copy the signed signer service into the release resources and create the canonical NSIS package;
5. sign and verify the installer;
6. recompute deterministic SPDX/SBOM, signed artifact SHA-256 values and base release evidence;
7. independently create signature evidence for the exact three signed artifacts;
8. combine controlled installer lifecycle evidence, Issue #75 production-chain evidence, Issue #77 hardware/operational evidence and the owner license decision;
9. fail the command unless final `release_eligible` is exactly `true`.

Example final controlled invocation:

```powershell
./tools/release/build_signed_windows_release.ps1 `
  -LifecycleEvidence C:\evidence\controlled-installer-lifecycle.json `
  -ProductionChainEvidence C:\evidence\issue-75-production-chain.json `
  -HardwareOperationalEvidence C:\evidence\issue-77-hardware-operations.json `
  -LicenseDecision C:\evidence\owner-license-decision.json `
  -OutputDirectory C:\evidence\final-release
```

The command cannot be used as a development fallback: unresolved certificate policy, unavailable pinned private key, invalid timestamp/signature/chain, dirty source, stale lockfile, missing external evidence or any final blocker terminates the run.

## Final release evidence

`tools/release/finalize_windows_release_evidence.py` combines the deterministic SBOM/manifest/checksums with independently produced Windows evidence. It rejects partial artifact inventories, post-sign hash mutation, test identities, unavailable/failed SignTool verification, missing code-signing EKU, wrong signer subject/pin, invalid chain, missing timestamp, test-mode lifecycle evidence, missing production-chain evidence, missing hardware/operational evidence and unresolved license evidence.

A final manifest can become `release_eligible: true` only when every blocker is cleared for the same 40-character source commit and exact signed installer hash. A signed artifact by itself is not a production release.

The lower-level finalizer inputs are:

```text
python tools/release/finalize_windows_release_evidence.py \
  --base-manifest <ergaxiom-release-manifest.json> \
  --policy tools/release/windows_release_policy.json \
  --signature-evidence <signature-evidence.json> \
  --lifecycle-evidence <controlled-windows-lifecycle.json> \
  --production-chain-evidence <issue-75-production-chain.json> \
  --hardware-operational-evidence <issue-77-hardware-operations.json> \
  --license-decision <owner-license-decision.json> \
  --output <ergaxiom-final-windows-release-evidence.json>
```

The owner-license record is never fabricated. Until an owner-approved SPDX expression is committed to the release policy and supplied in a matching evidence record, `DISTRIBUTION_LICENSE_NOT_APPROVED` remains a production blocker.

## CI and independent review

`.github/workflows/windows-signed-release.yml` now has separate fail-closed jobs for release-policy attacks, unsigned-candidate rejection and the real hosted Windows NSIS lifecycle matrix. Evidence artifacts are explicitly named `NOT-PRODUCTION` or `TEST-ONLY`. A manual production preflight still rejects the current branch before any certificate-backed production claim because the owner identity and license decision are unresolved.

Before publication, an independent controlled Windows reviewer must verify the exact signed desktop, signer-service and installer; inspect the real Issue #77 signer installation/recovery receipts and Issue #75 production package; reproduce checksums; run the controlled lifecycle procedure against the signed installer; and confirm the final manifest says exactly `release_eligible: true` for that source commit.

## Current blockers

At this branch the expected production decision is **blocked**. There is no owner-pinned real code-signing certificate, no owner-selected distribution license, no controlled production installer lifecycle evidence, Issue #75 has not yet supplied the final production execution/evidence/recovery package, and Issue #77 has not yet supplied a hardware-executed physical-TPM/LocalSystem installation/recovery artifact for this signed installer candidate. None of these blockers is replaced by hosted-CI fixtures.
