[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$PreparedReleaseDirectory,
  [Parameter(Mandatory)][string]$LifecycleEvidence,
  [Parameter(Mandatory)][string]$ProductionChainRoot,
  [Parameter(Mandatory)][string]$ProductionJobId,
  [Parameter(Mandatory)][string]$ProductionGovernancePolicy,
  [Parameter(Mandatory)][string]$ProductionTrustStateEnvelope,
  [Parameter(Mandatory)][string]$ProductionDeploymentPolicy,
  [Parameter(Mandatory)][string]$ProductionIdentityChallenge,
  [Parameter(Mandatory)][string]$ProductionIdentityProof,
  [Parameter(Mandatory)][string]$ProductionCompiledContract,
  [Parameter(Mandatory)][string]$ProductionCompiledPlan,
  [Parameter(Mandatory)][ValidateSet('E0','E1','E2','E3','E4','E5')][string]$ProductionAssuranceLevel,
  [Parameter(Mandatory)][string]$ProductionExpectedExecutorId,
  [string]$ProductionExpectedDeviceId,
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
  # Defense in depth for Stage B. These environment markers are not themselves
  # hardware attestation and therefore can never satisfy the hardware-origin
  # requirement below; they only prevent accidental local finalization.
  if($env:GITHUB_ACTIONS-cne'true'){throw 'PROTECTED_ENVIRONMENT_REQUIRED: Stage B must run in GitHub Actions'}
  if($env:GITHUB_REPOSITORY-cne'tayfunates10/ergaxiom'){throw 'PROTECTED_ENVIRONMENT_REPOSITORY_MISMATCH'}
  if($env:GITHUB_REF_PROTECTED-cne'true'){throw 'PROTECTED_REF_REQUIRED'}
  if($env:ERGAXIOM_PRODUCTION_ENVIRONMENT-cne'controlled-windows-production'){throw 'CONTROLLED_PRODUCTION_ENVIRONMENT_MARKER_REQUIRED'}

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
  if($env:GITHUB_SHA-cne$sourceCommit){throw 'PROTECTED_ENVIRONMENT_SOURCE_COMMIT_MISMATCH'}
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
  $serviceRecord=@($records|Where-Object{$_.name-ceq'ergaxiom-windows-production-signer-service.exe'})
  if($serviceRecord.Count-ne1){throw 'PREPARED_SIGNER_SERVICE_CARDINALITY_REJECTED'}
  $serviceDigest=[string]$serviceRecord[0].sha256
  if($serviceDigest-notmatch'^[0-9a-f]{64}$'){throw 'PREPARED_SIGNER_SERVICE_DIGEST_REJECTED'}

  $policyPath=Join-Path $repoRoot 'tools\release\windows_release_policy.json'
  $policy=Get-Content $policyPath -Raw|ConvertFrom-Json -Depth 32
  if($policy.signing.identity_status-ne'OWNER_APPROVED_PINNED'){throw 'SIGNING_IDENTITY_POLICY_UNRESOLVED'}
  if($policy.license.owner_decision_status-ne'APPROVED'){throw 'DISTRIBUTION_LICENSE_NOT_APPROVED'}

  $mandatoryFiles=@($LifecycleEvidence,$ProductionGovernancePolicy,$ProductionTrustStateEnvelope,$ProductionDeploymentPolicy,$ProductionIdentityChallenge,$ProductionIdentityProof,$ProductionCompiledContract,$ProductionCompiledPlan,$CapabilityProvisioningEvidence,$AttestationProvisioningEvidence,$PhysicalTpmPromotionEvidence,$GovernanceRecoveryReceipt,$SignerInstallationReceipt,$SignerRestartRecoveryReceipt,$LicenseDecision)
  foreach($path in $mandatoryFiles){if(-not(Test-Path $path -PathType Leaf)){throw "MANDATORY_EVIDENCE_MISSING: $path"}}
  if(-not(Test-Path $ProductionChainRoot -PathType Container)){throw 'PRODUCTION_CHAIN_ROOT_MISSING'}

  $out=[IO.Path]::GetFullPath($OutputDirectory); New-Item -ItemType Directory -Force $out|Out-Null
  $signatureEvidence=Join-Path $out 'windows-signature-evidence-reverified.json'
  & (Join-Path $PSScriptRoot 'verify_windows_signatures.ps1') -Mode production -PolicyPath $policyPath -Artifact @($actualFiles.FullName) -EvidenceOut $signatureEvidence
  if($LASTEXITCODE-ne0){throw 'PREPARED_SIGNATURE_REVERIFY_FAILED'}

  # IMPORTANT: controlled_trust_gate.py currently proves structural consistency
  # of the six evidence files. It does NOT cryptographically prove that the
  # provisioned private keys are TPM-resident/non-exportable. Do not promote
  # this result to release eligibility by itself.
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

  $trustedNow=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $productionEvidence=Join-Path $out 'production-release-chain-verification.json'
  $productionArgs=@(
    'run','--quiet','--locked','-p','ergaxiom-production-execution-runtime','--bin','verify_production_release_chain','--',
    '--repo-root',$repoRoot,
    '--chain-root',(Resolve-Path $ProductionChainRoot).Path,
    '--job-id',$ProductionJobId,
    '--governance-policy',(Resolve-Path $ProductionGovernancePolicy).Path,
    '--trust-state-envelope',(Resolve-Path $ProductionTrustStateEnvelope).Path,
    '--deployment-policy',(Resolve-Path $ProductionDeploymentPolicy).Path,
    '--identity-challenge',(Resolve-Path $ProductionIdentityChallenge).Path,
    '--identity-proof',(Resolve-Path $ProductionIdentityProof).Path,
    '--compiled-contract',(Resolve-Path $ProductionCompiledContract).Path,
    '--compiled-plan',(Resolve-Path $ProductionCompiledPlan).Path,
    '--assurance-level',$ProductionAssuranceLevel,
    '--expected-executor-id',$ProductionExpectedExecutorId,
    '--trusted-now-epoch-s',[string]$trustedNow,
    '--source-commit',$sourceCommit,
    '--expected-signed-service-sha256',$serviceDigest,
    '--output',$productionEvidence
  )
  if(-not[string]::IsNullOrWhiteSpace($ProductionExpectedDeviceId)){$productionArgs+=@('--expected-device-id',$ProductionExpectedDeviceId)}
  & cargo @productionArgs
  if($LASTEXITCODE-ne0){throw 'PRODUCTION_CHAIN_CANONICAL_VERIFICATION_FAILED'}
  $production=Get-Content $productionEvidence -Raw|ConvertFrom-Json -Depth 32
  if($production.verified-ne$true -or $production.gate-ne'PRODUCTION_CHAIN_VERIFIED' -or $production.source_commit-ne$sourceCommit -or $production.signer_service_sha256-ne$serviceDigest){throw 'PRODUCTION_CHAIN_CANONICAL_OUTPUT_REJECTED'}

  $final=Join-Path $out 'ergaxiom-final-windows-release-evidence.json'
  & python tools/release/finalize_windows_release_evidence.py `
    --base-manifest $baseManifestPath `
    --policy $policyPath `
    --signature-evidence $signatureEvidence `
    --lifecycle-evidence (Resolve-Path $LifecycleEvidence).Path `
    --production-chain-evidence $productionEvidence `
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

  # G-01 hard stop: until Ergaxiom validates vendor-rooted TPM key attestation
  # (for example EK/AK chain + TPM2_Certify binding for the production keys),
  # a structurally valid evidence bundle must never become a shippable release.
  # This intentionally keeps production fail-closed even when the local
  # structural finalizer calculates release_eligible=true.
  if($decision.release_eligible-eq$true){
    throw 'TPM_KEY_ATTESTATION_NOT_VERIFIED: structural evidence is insufficient for hardware-origin assurance'
  }
  throw "PRODUCTION_RELEASE_INELIGIBLE: $(@($decision.blocking_reasons)-join',')"
}
finally{Pop-Location}
