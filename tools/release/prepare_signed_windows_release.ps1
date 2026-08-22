[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
$repoRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
Push-Location $repoRoot
try {
  $sourceCommit=(& git rev-parse HEAD).Trim()
  if($LASTEXITCODE-ne0 -or $sourceCommit-notmatch'^[0-9a-f]{40}$'){throw 'SOURCE_COMMIT_UNRESOLVED'}
  if((& git status --porcelain --untracked-files=no)){throw 'TRACKED_WORKTREE_NOT_CLEAN'}
  $policyPath=Join-Path $repoRoot 'tools\release\windows_release_policy.json'
  $policy=Get-Content $policyPath -Raw|ConvertFrom-Json -Depth 32
  if($policy.signing.identity_status-ne'OWNER_APPROVED_PINNED'){throw 'SIGNING_IDENTITY_POLICY_UNRESOLVED'}

  & cargo metadata --locked --no-deps --format-version 1 *> $null; if($LASTEXITCODE-ne0){throw 'CARGO_LOCK_REJECTED'}
  & npm --prefix apps/desktop ci; if($LASTEXITCODE-ne0){throw 'NPM_CI_FAILED'}
  & npm --prefix apps/desktop run tauri -- build --no-bundle; if($LASTEXITCODE-ne0){throw 'DESKTOP_BUILD_FAILED'}
  & cargo build --release --locked -p ergaxiom-windows-production-signer-service; if($LASTEXITCODE-ne0){throw 'PRODUCTION_SIGNER_SERVICE_BUILD_FAILED'}

  $desktop=Join-Path $repoRoot 'apps\desktop\src-tauri\target\release\ergaxiom-desktop.exe'
  $service=Join-Path $repoRoot 'target\release\ergaxiom-windows-production-signer-service.exe'
  if(-not(Test-Path $desktop -PathType Leaf)-or-not(Test-Path $service -PathType Leaf)){throw 'RELEASE_PE_INPUT_MISSING'}
  & (Join-Path $PSScriptRoot 'sign_windows_release.ps1') -PolicyPath $policyPath -Artifact @($desktop,$service)
  if($LASTEXITCODE-ne0){throw 'PE_SIGNING_FAILED'}

  $resourceDir=Join-Path $repoRoot 'apps\desktop\src-tauri\release-resources'; New-Item -ItemType Directory -Force $resourceDir|Out-Null
  Copy-Item $service (Join-Path $resourceDir 'ergaxiom-windows-production-signer-service.exe') -Force
  & npm --prefix apps/desktop run tauri -- bundle --config src-tauri/tauri.release.conf.json; if($LASTEXITCODE-ne0){throw 'NSIS_BUNDLE_FAILED'}
  $installers=@(Get-ChildItem (Join-Path $repoRoot 'apps\desktop\src-tauri\target\release\bundle\nsis') -Filter '*-setup.exe' -File)
  if($installers.Count-ne1){throw "INSTALLER_CARDINALITY_REJECTED: $($installers.Count)"}
  & (Join-Path $PSScriptRoot 'sign_windows_release.ps1') -PolicyPath $policyPath -Artifact @($installers[0].FullName)
  if($LASTEXITCODE-ne0){throw 'INSTALLER_SIGNING_FAILED'}

  $out=[IO.Path]::GetFullPath($OutputDirectory); $artifactDir=Join-Path $out 'artifacts'; New-Item -ItemType Directory -Force $artifactDir|Out-Null
  $preparedDesktop=Join-Path $artifactDir 'ergaxiom-desktop.exe'
  $preparedService=Join-Path $artifactDir 'ergaxiom-windows-production-signer-service.exe'
  $preparedInstaller=Join-Path $artifactDir $installers[0].Name
  Copy-Item $desktop $preparedDesktop -Force; Copy-Item $service $preparedService -Force; Copy-Item $installers[0].FullName $preparedInstaller -Force

  $signatureEvidence=Join-Path $out 'windows-signature-evidence.json'
  & (Join-Path $PSScriptRoot 'verify_windows_signatures.ps1') -Mode production -PolicyPath $policyPath -Artifact @($preparedDesktop,$preparedService,$preparedInstaller) -EvidenceOut $signatureEvidence
  if($LASTEXITCODE-ne0){throw 'SIGNATURE_EVIDENCE_FAILED'}

  $rustc=(& rustc --version).Trim(); $node=(& node --version).Trim(); $npm=(& npm --version).Trim(); $baseDir=Join-Path $out 'base'
  & python tools/release/generate_release_evidence.py --repo-root . --artifact $preparedDesktop --artifact $preparedService --artifact $preparedInstaller --source-commit $sourceCommit --rustc-version $rustc --node-version $node --npm-version $npm --output-dir $baseDir
  if($LASTEXITCODE-ne0){throw 'BASE_RELEASE_EVIDENCE_FAILED'}

  $manifest=Get-Content (Join-Path $baseDir 'ergaxiom-release-manifest.json') -Raw|ConvertFrom-Json -Depth 32
  $handoff=[ordered]@{schema_version='0.1.0';source_commit=$sourceCommit;status='SIGNED_CANDIDATE_NOT_RELEASED';release_eligible=$false;next_required_step='Run controlled #77 physical ceremony against the exact prepared signer-service, then finalize the same candidate';artifacts=@($manifest.artifacts|ForEach-Object{[ordered]@{name=$_.name;sha256=$_.sha256}})}
  $handoff|ConvertTo-Json -Depth 16|Set-Content (Join-Path $out 'signed-candidate-handoff.json') -Encoding utf8
  Write-Host "Prepared signed candidate for $sourceCommit. This is NOT a production release. Run #77 ceremony against $preparedService before finalization."
}
finally{Pop-Location}
