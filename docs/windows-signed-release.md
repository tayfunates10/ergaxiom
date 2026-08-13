# Signed Windows release boundary

Issue #78 makes Windows release eligibility fail closed. The canonical installer is NSIS with per-machine scope and downgrades disabled. The release artifact inventory is fixed to `ergaxiom-desktop.exe`, `ergaxiom-windows-production-signer-service.exe` and exactly one `*-setup.exe` installer. UIA, Windows bridge and Inkscape adapter code are recorded as linked runtime inputs rather than misrepresented as separately shipped executables.

## Authenticode policy

`tools/release/windows_release_policy.json` is the source-controlled signing policy. Production evidence must match an owner-approved exact certificate subject and DER SHA-256 pin, SHA-256 Authenticode, RFC 3161 timestamping through the fixed HTTPS timestamp endpoint, a valid certificate chain, online revocation checking and a non-self-signed signer. Workflow inputs cannot replace those identities.

The repository intentionally contains no real private key or production certificate. The current policy has `identity_status: OWNER_CERTIFICATE_PIN_REQUIRED`, so production preflight fails. After the owner supplies a real certificate, the policy must be changed to `OWNER_APPROVED_PINNED` with its exact subject and DER SHA-256. The real private key remains external to Git.

`tools/release/verify_windows_signatures.ps1` independently reads Authenticode metadata from exact artifacts and emits machine-readable signature, signer, chain, timestamp and post-sign SHA-256 evidence. It never creates a signature and therefore cannot turn an unsigned build into a production release.

## Installer provenance

`apps/desktop/src-tauri/tauri.release.conf.json` and the CI variant select NSIS, `perMachine`, `allowDowngrades: false`, and package the production signer-service executable as an installer resource. The LocalSystem service and protected `%ProgramData%\Ergaxiom` trust state remain under the controlled provisioning ceremony from Issue #77; hosted CI is not allowed to fabricate that installation ceremony.

A production lifecycle evidence record is accepted only when it is bound to the exact source commit and exact installer SHA-256 and has `test_mode: false` with all of these phases true: clean install, upgrade, downgrade rejection, interrupted-upgrade state preservation, recovery install, uninstall, and production-state preservation. Missing or test-mode lifecycle evidence produces `INSTALLER_LIFECYCLE_NOT_VERIFIED`.

## Final release evidence

`tools/release/finalize_windows_release_evidence.py` combines the PR #73 deterministic SBOM/manifest/checksums with independently produced Windows evidence. It rejects partial artifact inventories, post-sign hash mutation, test identities, wrong signer subject/pin, invalid chain, missing timestamp, test-mode lifecycle evidence, missing production-chain evidence, missing hardware/operational evidence and unresolved license evidence.

A final manifest can become `release_eligible: true` only when every blocker is cleared for the same 40-character source commit and exact signed installer hash. A signed artifact by itself is not a production release.

Required finalizer inputs are:

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

The owner-license record is not fabricated. Until an owner-approved SPDX expression is committed to the release policy and supplied in a matching evidence record, `DISTRIBUTION_LICENSE_NOT_APPROVED` remains a production blocker.

## CI and independent review

`.github/workflows/windows-signed-release.yml` builds the exact desktop PE, signer-service PE and NSIS installer on Windows, creates baseline release evidence, verifies that the unsigned/test candidate has no acceptable production Authenticode evidence, runs the fail-closed finalizer and uploads evidence explicitly named `NOT-PRODUCTION`. A manual production preflight also fails until the owner certificate pin and license decision are resolved.

Repository-controlled tests cover the positive all-evidence path plus rejection of test identity, wrong chain, missing timestamp, wrong subject, post-sign mutation, partial artifact inventory and test-mode lifecycle evidence. The Windows workflow additionally proves that the real current unsigned candidate cannot self-promote.

Before any release publication, an independent controlled Windows reviewer must verify the exact signed desktop, signer-service and installer with `verify_windows_signatures.ps1`, capture the real install/upgrade/downgrade/interruption/recovery/uninstall evidence from the controlled machine, bind Issue #75 and #77 evidence, recompute checksums, and confirm the final manifest says exactly `release_eligible: true`.

## Current blockers

At this branch the expected production decision is **blocked**. There is no owner-pinned real code-signing certificate, no owner-selected distribution license, no controlled production installer lifecycle evidence, and the dependent Issue #75/#77 production-chain and hardware/operational evidence branches are not yet available on this baseline. None of these blockers is replaced by hosted-CI fixtures.
