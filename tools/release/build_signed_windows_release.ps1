[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Prepare','Finalize')][string]$Mode,
  [string]$OutputDirectory,
  [string]$PreparedReleaseDirectory,
  [string]$LifecycleEvidence,
  [string]$ProductionChainRoot,
  [string]$ProductionJobId,
  [string]$ProductionGovernancePolicy,
  [string]$ProductionTrustStateEnvelope,
  [string]$ProductionDeploymentPolicy,
  [string]$ProductionIdentityChallenge,
  [string]$ProductionIdentityProof,
  [string]$ProductionCompiledContract,
  [string]$ProductionCompiledPlan,
  [ValidateSet('E0','E1','E2','E3','E4','E5')][string]$ProductionAssuranceLevel,
  [string]$ProductionExpectedExecutorId,
  [string]$ProductionExpectedDeviceId,
  [string]$CapabilityProvisioningEvidence,
  [string]$AttestationProvisioningEvidence,
  [string]$PhysicalTpmPromotionEvidence,
  [string]$GovernanceRecoveryReceipt,
  [string]$SignerInstallationReceipt,
  [string]$SignerRestartRecoveryReceipt,
  [string]$LicenseDecision
)
$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
if([string]::IsNullOrWhiteSpace($OutputDirectory)){throw 'OUTPUT_DIRECTORY_REQUIRED'}
if($Mode-eq'Prepare'){
  & (Join-Path $PSScriptRoot 'prepare_signed_windows_release.ps1') -OutputDirectory $OutputDirectory
  exit $LASTEXITCODE
}
$required=@{
  PreparedReleaseDirectory=$PreparedReleaseDirectory; LifecycleEvidence=$LifecycleEvidence; ProductionChainRoot=$ProductionChainRoot;
  ProductionJobId=$ProductionJobId; ProductionGovernancePolicy=$ProductionGovernancePolicy; ProductionTrustStateEnvelope=$ProductionTrustStateEnvelope;
  ProductionDeploymentPolicy=$ProductionDeploymentPolicy; ProductionIdentityChallenge=$ProductionIdentityChallenge; ProductionIdentityProof=$ProductionIdentityProof;
  ProductionCompiledContract=$ProductionCompiledContract; ProductionCompiledPlan=$ProductionCompiledPlan; ProductionAssuranceLevel=$ProductionAssuranceLevel;
  ProductionExpectedExecutorId=$ProductionExpectedExecutorId; CapabilityProvisioningEvidence=$CapabilityProvisioningEvidence;
  AttestationProvisioningEvidence=$AttestationProvisioningEvidence; PhysicalTpmPromotionEvidence=$PhysicalTpmPromotionEvidence;
  GovernanceRecoveryReceipt=$GovernanceRecoveryReceipt; SignerInstallationReceipt=$SignerInstallationReceipt;
  SignerRestartRecoveryReceipt=$SignerRestartRecoveryReceipt; LicenseDecision=$LicenseDecision
}
foreach($item in $required.GetEnumerator()){if([string]::IsNullOrWhiteSpace([string]$item.Value)){throw "FINALIZE_ARGUMENT_REQUIRED: $($item.Key)"}}
$params=@{
  PreparedReleaseDirectory=$PreparedReleaseDirectory; LifecycleEvidence=$LifecycleEvidence; ProductionChainRoot=$ProductionChainRoot;
  ProductionJobId=$ProductionJobId; ProductionGovernancePolicy=$ProductionGovernancePolicy; ProductionTrustStateEnvelope=$ProductionTrustStateEnvelope;
  ProductionDeploymentPolicy=$ProductionDeploymentPolicy; ProductionIdentityChallenge=$ProductionIdentityChallenge; ProductionIdentityProof=$ProductionIdentityProof;
  ProductionCompiledContract=$ProductionCompiledContract; ProductionCompiledPlan=$ProductionCompiledPlan; ProductionAssuranceLevel=$ProductionAssuranceLevel;
  ProductionExpectedExecutorId=$ProductionExpectedExecutorId; CapabilityProvisioningEvidence=$CapabilityProvisioningEvidence;
  AttestationProvisioningEvidence=$AttestationProvisioningEvidence; PhysicalTpmPromotionEvidence=$PhysicalTpmPromotionEvidence;
  GovernanceRecoveryReceipt=$GovernanceRecoveryReceipt; SignerInstallationReceipt=$SignerInstallationReceipt;
  SignerRestartRecoveryReceipt=$SignerRestartRecoveryReceipt; LicenseDecision=$LicenseDecision; OutputDirectory=$OutputDirectory
}
if(-not[string]::IsNullOrWhiteSpace($ProductionExpectedDeviceId)){$params.ProductionExpectedDeviceId=$ProductionExpectedDeviceId}
& (Join-Path $PSScriptRoot 'finalize_prepared_windows_release.ps1') @params
exit $LASTEXITCODE
