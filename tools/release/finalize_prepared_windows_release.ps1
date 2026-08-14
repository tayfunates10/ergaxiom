[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$PreparedReleaseDirectory,
  [Parameter(Mandatory)][string]$LifecycleEvidence,
  [Parameter(Mandatory)][string]$ProductionChainEvidence,
  [Parameter(Mandatory)][string]$CapabilityProvisioningEvidence,
  [Parameter(Mandatory)][string]$AttestationProvisioningEvidence,
  [Parameter(Mandatory)][string]$PhysicalTpmPromotionEvidence,
  [Parameter(Mandatory)][string]$GovernanceRecoveryReceipt,
  [Parameter(Mandatory)][string]$SignerInstallationReceipt,
  [Parameter(Mandatory)][string]$SignerRestartRecoveryReceipt,
  [Parameter(Mandatory)][string]$LicenseDecision,
  [Parameter(Mandatory)][string]$OutputDirectory
)
$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
$repoRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
Push-Location $repoRoot
try {
  $prepared=[IO.Path]::GetFullPath($PreparedReleaseDirectory)
  $baseManifestPath=Join-Path $prepared 'base\ergaxiom-release-manifest.json'
  $handoffPath=Join-Path $prepared 'signed-candidate-handoff.json'
  $artifactDir=Join-Path $prepared 'artifacts'
  foreach($path in @($baseManifestPath,$handoffPath)) { if(-not(Test-Path $path -PathType Leaf)){throw "PREPARED_RELEASE_METADATA_MISSING: $path"} }
  if(-not(Test-Path $artifactDir -PathType Container)){throw 'PREPARED_ARTIFACT_DIRECTORY_MISSING'}

  $manifest=Get-Content $baseManifestPath -Raw|ConvertFrom-Json -Depth 32
  $handoff=Get-Content $handoffPath -Raw|ConvertFrom-Json -Depth 32
  $sourceCommit=(& git rev-parse HEAD).Trim()
  if($LASTEXITCODE-ne0 -or $manifest.source.commit-ne$sourceCommit -or $handoff.source_commit-ne$sourceCommit){throw 'PREPARED_SOURCE_COMMIT_MISMATCH'}
  if((& git status --porcelain --untracked-files=no)){throw 'TRACKED_WORKTREE_NOT_CLEAN'}
  if($handoff.status-ne'SIGNED_CANDIDATE_NOT_RELEASED' -or $handoff.release_eligible-ne$false){throw 'PREPARED_HANDOFF_STATE_REJECTED'}

  $records=@($manifest.artifacts)
  if($records.Count-ne3){throw "PREPARED_ARTIFACT_CARDINALITY_REJECTED: $($records.Count)"}
  $expectedNames=@($records|ForEach-Object{$_.name}|Sort-Object)
  $actualFiles=@(Get-ChildItem $artifactDir -File)
  $actualNames=@($actualFiles|ForEach-Object{$_.Name}|Sort-Object)
  if(($expectedNames -join "`n")-cne($actualNames -join "`n")){throw 'PREPARED_ARTIFACT_INVENTORY_SUBSTITUTED'}
  foreach($record in $records){
    $path=Join-Path $artifactDir $record.name
    $digest=(Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if($digest-cne[string]$record.sha256){throw "PREPARED_ARTIFACT_MUTATED: $($record.name)"}
  }

  $policyPath=Join-Path $repoRoot 'tools\release\windows_release_policy.json'
  $policy=Get-Content $policyPath -Raw|ConvertFrom-Json -Depth 32
  if($policy.signing.identity_status-ne'OWNER_APPROVED_PINNED'){throw 'SIGNING_IDENTITY_POLICY_UNRESOLVED'}
  if($policy.license.owner_decision_status-ne'APPROVED'){throw 'DISTRIBUTION_LICENSE_NOT_APPROVED'}

  $mandatory=@($LifecycleEvidence,$ProductionChainEvidence,$CapabilityProvisioningEvidence,$AttestationProvisioningEvidence,$PhysicalTpmPromotionEvidence,$GovernanceRecoveryReceipt,$SignerInstallationReceipt,$SignerRestartRecoveryReceipt,$LicenseDecision)
  foreach($path in $mandatory){if(-not(Test-Path $path -PathType Leaf)){throw "MANDATORY_EVIDENCE_MISSING: $path"}}

  $out=[IO.Path]::GetFullPath($OutputDirectory); New-Item -ItemType Directory -Force $out|Out-Null
  $signatureEvidence=Join-Path $out 'windows-signature-evidence-reverified.json'
  & (Join-Path $PSScriptRoot 'verify_windows_signatures.ps1') -Mode production -PolicyPath $policyPath -Artifact @($actualFiles.FullName) -EvidenceOut $signatureEvidence
  if($LASTEXITCODE-ne0){throw 'PREPARED_SIGNATURE_REVERIFY_FAILED'}

  $hardwareSummary=Join-Path $out 'controlled-trust-gate.json'
  & python tools/windows/controlled_trust_gate.py verify `
    --physical (Resolve-Path $PhysicalTpmPromotionEvidence).Path `
    --governance (Resolve-Path $GovernanceRecoveryReceipt).Path `
    --installation (Resolve-Path $SignerInstallationReceipt).Path `
    --recovery (Resolve-Path $SignerRestartRecoveryReceipt).Path `
    --capability-provisioning (Resolve-Path $CapabilityProvisioningEvidence).Path `
    --attestation-provisioning (Resolve-Path $AttestationProvisioningEvidence).Path `
    --output $hardwareSummary
  if($LASTEXITCODE-ne0){throw 'CONTROLLED_TRUST_GATE_REJECTED'}

  $final=Join-Path $out 'ergaxiom-final-windows-release-evidence.json'
  & python tools/release/finalize_windows_release_evidence.py `
    --base-manifest $baseManifestPath `
    --policy $policyPath `
    --signature-evidence $signatureEvidence `
    --lifecycle-evidence (Resolve-Path $LifecycleEvidence).Path `
    --production-chain-evidence (Resolve-Path $ProductionChainEvidence).Path `
    --capability-provisioning-evidence (Resolve-Path $CapabilityProvisioningEvidence).Path `
    --attestation-provisioning-evidence (Resolve-Path $AttestationProvisioningEvidence).Path `
    --physical-tpm-promotion-evidence (Resolve-Path $PhysicalTpmPromotionEvidence).Path `
    --governance-recovery-receipt (Resolve-Path $GovernanceRecoveryReceipt).Path `
    --signer-installation-receipt (Resolve-Path $SignerInstallationReceipt).Path `
    --signer-restart-recovery-receipt (Resolve-Path $SignerRestartRecoveryReceipt).Path `
    --license-decision (Resolve-Path $LicenseDecision).Path `
    --output $final
  if($LASTEXITCODE-ne0){throw 'FINAL_RELEASE_EVIDENCE_FAILED'}
  $decision=Get-Content $final -Raw|ConvertFrom-Json -Depth 32
  if($decision.release_eligible-ne$true){throw "PRODUCTION_RELEASE_INELIGIBLE: $(@($decision.blocking_reasons)-join',')"}
  Write-Host "Prepared candidate finalized as production-eligible for exact source $sourceCommit."
}
finally{Pop-Location}
