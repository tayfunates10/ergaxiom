[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$PolicyPath,
  [Parameter(Mandatory)][string[]]$Artifact
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-DerSha256([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
  return ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Certificate.RawData))).ToLowerInvariant()
}

function Find-SignTool {
  $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($command) { return $command.Source }
  $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
  if (-not (Test-Path $kits)) { throw 'SIGNTOOL_NOT_FOUND' }
  $candidate = Get-ChildItem $kits -Directory | Sort-Object Name -Descending | ForEach-Object {
    Join-Path $_.FullName 'x64\signtool.exe'
  } | Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $candidate) { throw 'SIGNTOOL_NOT_FOUND' }
  return $candidate
}

$policyPathResolved = (Resolve-Path $PolicyPath).Path
$policy = Get-Content $policyPathResolved -Raw | ConvertFrom-Json -Depth 32
if ($policy.policy_id -ne 'ergaxiom.windows-production-release' -or $policy.schema_version -ne '0.1.0') { throw 'POLICY_REJECTED' }
$signing = $policy.signing
if ($signing.identity_status -ne 'OWNER_APPROVED_PINNED') { throw 'SIGNING_IDENTITY_POLICY_UNRESOLVED' }
if ($signing.digest_algorithm -ne 'SHA256' -or $signing.timestamp_digest_algorithm -ne 'SHA256' -or $signing.timestamp_protocol -ne 'RFC3161') { throw 'SIGNING_ALGORITHM_POLICY_REJECTED' }
if ($signing.certificate_store_location -notin @('CurrentUser','LocalMachine') -or $signing.certificate_store_name -ne 'My') { throw 'CERTIFICATE_STORE_POLICY_REJECTED' }
if ([string]::IsNullOrWhiteSpace([string]$signing.expected_subject) -or [string]$signing.expected_certificate_sha256 -notmatch '^[0-9a-f]{64}$') { throw 'SIGNING_IDENTITY_POLICY_UNRESOLVED' }
if ([string]$signing.timestamp_url -notmatch '^https://') { throw 'TIMESTAMP_POLICY_REJECTED' }

$storePath = "Cert:\$($signing.certificate_store_location)\$($signing.certificate_store_name)"
$matches = @(Get-ChildItem $storePath | Where-Object {
  $_.Subject -ceq [string]$signing.expected_subject -and
  (Get-DerSha256 $_) -ceq [string]$signing.expected_certificate_sha256
})
if ($matches.Count -ne 1) { throw 'PINNED_CODE_SIGNING_CERTIFICATE_NOT_UNIQUE' }
$certificate = $matches[0]
if (-not $certificate.HasPrivateKey) { throw 'PINNED_CODE_SIGNING_PRIVATE_KEY_UNAVAILABLE' }
if ($certificate.Subject -eq $certificate.Issuer) { throw 'SELF_SIGNED_CODE_SIGNING_CERTIFICATE_REJECTED' }
$now = Get-Date
if ($now -lt $certificate.NotBefore -or $now -ge $certificate.NotAfter) { throw 'CODE_SIGNING_CERTIFICATE_OUTSIDE_VALIDITY' }
$eku = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | ForEach-Object {
  ([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$_).EnhancedKeyUsages | ForEach-Object { $_.Value }
})
if ([string]$signing.code_signing_eku_oid -notin $eku) { throw 'CODE_SIGNING_EKU_MISSING' }

$resolved = @()
$seen = @{}
foreach ($path in $Artifact) {
  $full = (Resolve-Path $path).Path
  if (-not [IO.File]::Exists($full)) { throw "ARTIFACT_NOT_FILE: $path" }
  $name = [IO.Path]::GetFileName($full)
  if ($seen.ContainsKey($name)) { throw "DUPLICATE_ARTIFACT: $name" }
  $seen[$name] = $true
  $resolved += $full
}
if ($resolved.Count -eq 0) { throw 'NO_ARTIFACTS' }

$signTool = Find-SignTool
foreach ($full in $resolved) {
  $args = @('sign','/fd','SHA256','/td','SHA256','/tr',[string]$signing.timestamp_url,'/s',[string]$signing.certificate_store_name,'/sha1',$certificate.Thumbprint)
  if ($signing.certificate_store_location -eq 'LocalMachine') { $args += '/sm' }
  $args += $full
  & $signTool @args
  if ($LASTEXITCODE -ne 0) { throw "AUTHENTICODE_SIGN_FAILED: $([IO.Path]::GetFileName($full))" }
  & $signTool verify /pa /all /v $full
  if ($LASTEXITCODE -ne 0) { throw "AUTHENTICODE_VERIFY_FAILED: $([IO.Path]::GetFileName($full))" }
}

Write-Host "Signed and verified $($resolved.Count) artifact(s) with the exact owner-pinned certificate."
