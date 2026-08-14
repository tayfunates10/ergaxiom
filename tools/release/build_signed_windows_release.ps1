[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Prepare','Finalize')][string]$Mode,
  [string]$OutputDirectory,
  [string]$PreparedReleaseDirectory,
  [string]$LifecycleEvidence,
  [string]$ProductionChainEvidence,
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
  PreparedReleaseDirectory=$PreparedReleaseDirectory; LifecycleEvidence=$LifecycleEvidence; ProductionChainEvidence=$ProductionChainEvidence;
  CapabilityProvisioningEvidence=$CapabilityProvisioningEvidence; AttestationProvisioningEvidence=$AttestationProvisioningEvidence;
  PhysicalTpmPromotionEvidence=$PhysicalTpmPromotionEvidence; GovernanceRecoveryReceipt=$GovernanceRecoveryReceipt;
  SignerInstallationReceipt=$SignerInstallationReceipt; SignerRestartRecoveryReceipt=$SignerRestartRecoveryReceipt; LicenseDecision=$LicenseDecision
}
foreach($item in $required.GetEnumerator()){if([string]::IsNullOrWhiteSpace([string]$item.Value)){throw "FINALIZE_ARGUMENT_REQUIRED: $($item.Key)"}}
& (Join-Path $PSScriptRoot 'finalize_prepared_windows_release.ps1') `
  -PreparedReleaseDirectory $PreparedReleaseDirectory -LifecycleEvidence $LifecycleEvidence -ProductionChainEvidence $ProductionChainEvidence `
  -CapabilityProvisioningEvidence $CapabilityProvisioningEvidence -AttestationProvisioningEvidence $AttestationProvisioningEvidence `
  -PhysicalTpmPromotionEvidence $PhysicalTpmPromotionEvidence -GovernanceRecoveryReceipt $GovernanceRecoveryReceipt `
  -SignerInstallationReceipt $SignerInstallationReceipt -SignerRestartRecoveryReceipt $SignerRestartRecoveryReceipt `
  -LicenseDecision $LicenseDecision -OutputDirectory $OutputDirectory
exit $LASTEXITCODE
