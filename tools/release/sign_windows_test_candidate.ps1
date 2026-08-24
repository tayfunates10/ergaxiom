[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$PolicyPath,
  [Parameter(Mandatory)][string[]]$Artifact,
  [Parameter(Mandatory)][string]$IdentityEvidenceOut,
  [string]$Subject = 'CN=Ergaxiom Self-Signed Test Identity'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_REQUIRED' }

function Get-DerSha256([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
  return ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Certificate.RawData))).ToLowerInvariant()
}

function Find-SignTool {
  $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($command) { return $command.Source }
  $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
  if (-not (Test-Path $kits -PathType Container)) { throw 'SIGNTOOL_NOT_FOUND' }
  $candidate = Get-ChildItem $kits -Directory | Sort-Object Name -Descending | ForEach-Object {
    Join-Path $_.FullName 'x64\signtool.exe'
  } | Where-Object { Test-Path $_ -PathType Leaf } | Select-Object -First 1
  if (-not $candidate) { throw 'SIGNTOOL_NOT_FOUND' }
  return $candidate
}

$policyResolved = (Resolve-Path $PolicyPath).Path
$policy = Get-Content $policyResolved -Raw | ConvertFrom-Json -Depth 32
if ($policy.policy_id -ne 'ergaxiom.windows-production-release' -or $policy.schema_version -ne '0.1.0') { throw 'POLICY_REJECTED' }
if ($policy.signing.digest_algorithm -ne 'SHA256' -or $policy.signing.timestamp_digest_algorithm -ne 'SHA256' -or $policy.signing.timestamp_protocol -ne 'RFC3161') { throw 'SIGNING_ALGORITHM_POLICY_REJECTED' }
if ([string]$policy.signing.timestamp_url -notmatch '^https://') { throw 'TIMESTAMP_POLICY_REJECTED' }

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

$cert = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject $Subject `
  -CertStoreLocation 'Cert:\CurrentUser\My' `
  -KeyAlgorithm RSA `
  -KeyLength 3072 `
  -HashAlgorithm SHA256 `
  -KeyExportPolicy NonExportable `
  -NotAfter (Get-Date).AddDays(7)

if (-not $cert -or -not $cert.HasPrivateKey) { throw 'TEST_CERTIFICATE_CREATION_FAILED' }
if ($cert.Subject -ne $cert.Issuer) { throw 'TEST_IDENTITY_MUST_BE_SELF_SIGNED' }
$eku = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | ForEach-Object {
  ([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$_).EnhancedKeyUsages | ForEach-Object { $_.Value }
})
if ([string]$policy.signing.code_signing_eku_oid -notin $eku) { throw 'TEST_CODE_SIGNING_EKU_MISSING' }

$cerPath = Join-Path $env:TEMP ("ergaxiom-test-signing-{0}.cer" -f $cert.Thumbprint)
Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
Import-Certificate -FilePath $cerPath -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null

$signTool = Find-SignTool
foreach ($full in $resolved) {
  & $signTool sign /fd SHA256 /td SHA256 /tr ([string]$policy.signing.timestamp_url) /s My /sha1 $cert.Thumbprint $full
  if ($LASTEXITCODE -ne 0) { throw "TEST_AUTHENTICODE_SIGN_FAILED: $([IO.Path]::GetFileName($full))" }
  & $signTool verify /pa /all /v $full
  if ($LASTEXITCODE -ne 0) { throw "TEST_AUTHENTICODE_VERIFY_FAILED: $([IO.Path]::GetFileName($full))" }
}

$evidence = [ordered]@{
  schema_version = '0.1.0'
  mode = 'test'
  test_identity = $true
  self_signed = $true
  production_eligible = $false
  subject = [string]$cert.Subject
  issuer = [string]$cert.Issuer
  der_sha256 = Get-DerSha256 $cert
  thumbprint = ([string]$cert.Thumbprint).ToLowerInvariant()
  has_private_key = [bool]$cert.HasPrivateKey
  private_key_exported = $false
  certificate_store_location = 'CurrentUser'
  certificate_store_name = 'My'
  trusted_test_root_store = 'CurrentUser\\Root'
  not_before = $cert.NotBefore.ToUniversalTime().ToString('o')
  not_after = $cert.NotAfter.ToUniversalTime().ToString('o')
  artifact_names = @($resolved | ForEach-Object { [IO.Path]::GetFileName($_) } | Sort-Object)
  note = 'Ephemeral self-signed test identity only. Never valid production release evidence.'
}
$out = [IO.Path]::GetFullPath($IdentityEvidenceOut)
New-Item -ItemType Directory -Force (Split-Path $out) | Out-Null
[IO.File]::WriteAllText($out, (($evidence | ConvertTo-Json -Depth 8) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
Write-Host "Self-signed and verified $($resolved.Count) test artifact(s). Identity evidence: $out"
