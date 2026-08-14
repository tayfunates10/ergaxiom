[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$LifecycleEvidence,
  [Parameter(Mandatory)][string]$ProductionChainEvidence,
  [Parameter(Mandatory)][string]$HardwareOperationalEvidence,
  [Parameter(Mandatory)][string]$LicenseDecision,
  [Parameter(Mandatory)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
Push-Location $repoRoot
try {
  $sourceCommit = (& git rev-parse HEAD).Trim()
  if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') { throw 'SOURCE_COMMIT_UNRESOLVED' }
  $dirty = (& git status --porcelain --untracked-files=no)
  if ($LASTEXITCODE -ne 0 -or $dirty) { throw 'TRACKED_WORKTREE_NOT_CLEAN' }

  $policyPath = Join-Path $repoRoot 'tools\release\windows_release_policy.json'
  $policy = Get-Content $policyPath -Raw | ConvertFrom-Json -Depth 32
  if ($policy.signing.identity_status -ne 'OWNER_APPROVED_PINNED') { throw 'SIGNING_IDENTITY_POLICY_UNRESOLVED' }
  if ($policy.license.owner_decision_status -ne 'APPROVED') { throw 'DISTRIBUTION_LICENSE_NOT_APPROVED' }

  foreach ($path in @($LifecycleEvidence, $ProductionChainEvidence, $HardwareOperationalEvidence, $LicenseDecision)) {
    if (-not (Test-Path (Resolve-Path $path).Path -PathType Leaf)) { throw "MANDATORY_EVIDENCE_MISSING: $path" }
  }

  & cargo metadata --locked --no-deps --format-version 1 *> $null
  if ($LASTEXITCODE -ne 0) { throw 'CARGO_LOCK_REJECTED' }
  & npm --prefix apps/desktop ci
  if ($LASTEXITCODE -ne 0) { throw 'NPM_CI_FAILED' }
  & npm --prefix apps/desktop run tauri -- build --no-bundle
  if ($LASTEXITCODE -ne 0) { throw 'DESKTOP_BUILD_FAILED' }
  & cargo build --release --locked -p ergaxiom-windows-production-signer-service
  if ($LASTEXITCODE -ne 0) { throw 'PRODUCTION_SIGNER_SERVICE_BUILD_FAILED' }

  $desktop = Join-Path $repoRoot 'apps\desktop\src-tauri\target\release\ergaxiom-desktop.exe'
  $service = Join-Path $repoRoot 'target\release\ergaxiom-windows-production-signer-service.exe'
  if (-not (Test-Path $desktop -PathType Leaf) -or -not (Test-Path $service -PathType Leaf)) { throw 'RELEASE_PE_INPUT_MISSING' }

  & (Join-Path $PSScriptRoot 'sign_windows_release.ps1') -PolicyPath $policyPath -Artifact @($desktop, $service)
  if ($LASTEXITCODE -ne 0) { throw 'PE_SIGNING_FAILED' }

  $resourceDir = Join-Path $repoRoot 'apps\desktop\src-tauri\release-resources'
  New-Item -ItemType Directory -Force $resourceDir | Out-Null
  $resourceService = Join-Path $resourceDir 'ergaxiom-windows-production-signer-service.exe'
  Copy-Item $service $resourceService -Force

  & npm --prefix apps/desktop run tauri -- bundle --config src-tauri/tauri.release.conf.json
  if ($LASTEXITCODE -ne 0) { throw 'NSIS_BUNDLE_FAILED' }
  $installerCandidates = @(Get-ChildItem (Join-Path $repoRoot 'apps\desktop\src-tauri\target\release\bundle\nsis') -Filter '*-setup.exe' -File)
  if ($installerCandidates.Count -ne 1) { throw "INSTALLER_CARDINALITY_REJECTED: $($installerCandidates.Count)" }
  $installer = $installerCandidates[0].FullName

  & (Join-Path $PSScriptRoot 'sign_windows_release.ps1') -PolicyPath $policyPath -Artifact @($installer)
  if ($LASTEXITCODE -ne 0) { throw 'INSTALLER_SIGNING_FAILED' }

  $out = [IO.Path]::GetFullPath($OutputDirectory)
  New-Item -ItemType Directory -Force $out | Out-Null
  $signatureEvidence = Join-Path $out 'windows-signature-evidence.json'
  & (Join-Path $PSScriptRoot 'verify_windows_signatures.ps1') -Mode production -PolicyPath $policyPath -Artifact @($desktop, $resourceService, $installer) -EvidenceOut $signatureEvidence
  if ($LASTEXITCODE -ne 0) { throw 'SIGNATURE_EVIDENCE_FAILED' }

  $rustc = (& rustc --version).Trim()
  $node = (& node --version).Trim()
  $npm = (& npm --version).Trim()
  $baseDir = Join-Path $out 'base'
  & python tools/release/generate_release_evidence.py --repo-root . --artifact $desktop --artifact $resourceService --artifact $installer --source-commit $sourceCommit --rustc-version $rustc --node-version $node --npm-version $npm --output-dir $baseDir
  if ($LASTEXITCODE -ne 0) { throw 'BASE_RELEASE_EVIDENCE_FAILED' }

  $final = Join-Path $out 'ergaxiom-final-windows-release-evidence.json'
  & python tools/release/finalize_windows_release_evidence.py `
    --base-manifest (Join-Path $baseDir 'ergaxiom-release-manifest.json') `
    --policy $policyPath `
    --signature-evidence $signatureEvidence `
    --lifecycle-evidence (Resolve-Path $LifecycleEvidence).Path `
    --production-chain-evidence (Resolve-Path $ProductionChainEvidence).Path `
    --hardware-operational-evidence (Resolve-Path $HardwareOperationalEvidence).Path `
    --license-decision (Resolve-Path $LicenseDecision).Path `
    --output $final
  if ($LASTEXITCODE -ne 0) { throw 'FINAL_RELEASE_EVIDENCE_FAILED' }

  $decision = Get-Content $final -Raw | ConvertFrom-Json -Depth 32
  if ($decision.release_eligible -ne $true) {
    $blockers = @($decision.blocking_reasons) -join ','
    throw "PRODUCTION_RELEASE_INELIGIBLE: $blockers"
  }
  Write-Host "Production release evidence accepted for commit $sourceCommit and installer $([IO.Path]::GetFileName($installer))."
}
finally {
  Pop-Location
}
