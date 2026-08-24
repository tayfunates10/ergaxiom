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

function Invoke-SignToolBounded {
  param(
    [Parameter(Mandatory)][string]$SignTool,
    [Parameter(Mandatory)][string[]]$Arguments,
    [Parameter(Mandatory)][string]$Operation,
    [int]$TimeoutSeconds = 60
  )

  Write-Host "SignTool start: $Operation"
  $psi = [Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = $SignTool
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  foreach ($argument in $Arguments) { [void]$psi.ArgumentList.Add([string]$argument) }

  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $psi
  if (-not $process.Start()) { throw "SIGNTOOL_START_FAILED: $Operation" }
  $stdoutTask = $process.StandardOutput.ReadToEndAsync()
  $stderrTask = $process.StandardError.ReadToEndAsync()

  if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    try { $process.Kill($true) } catch { }
    throw "SIGNTOOL_TIMEOUT: $Operation"
  }

  $stdout = $stdoutTask.GetAwaiter().GetResult()
  $stderr = $stderrTask.GetAwaiter().GetResult()
  if ($stdout) { Write-Host $stdout.TrimEnd() }
  if ($stderr) { Write-Host $stderr.TrimEnd() }
  if ($process.ExitCode -ne 0) { throw "SIGNTOOL_FAILED: $Operation (exit=$($process.ExitCode))" }
  Write-Host "SignTool success: $Operation"
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

Write-Host 'Creating ephemeral self-signed test code-signing certificate.'
$cert = New-SelfSignedCertificate `
  -Type Custom `
  -Subject $Subject `
  -CertStoreLocation 'Cert:\CurrentUser\My' `
  -KeyUsage DigitalSignature `
  -KeySpec Signature `
  -KeyAlgorithm RSA `
  -KeyLength 2048 `
  -HashAlgorithm SHA256 `
  -KeyExportPolicy NonExportable `
  -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3','2.5.29.19={text}') `
  -NotAfter (Get-Date).AddDays(7)

if (-not $cert -or -not $cert.HasPrivateKey) { throw 'TEST_CERTIFICATE_CREATION_FAILED' }
if ($cert.Subject -ne $cert.Issuer) { throw 'TEST_IDENTITY_MUST_BE_SELF_SIGNED' }
$eku = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | ForEach-Object {
  ([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$_).EnhancedKeyUsages | ForEach-Object { $_.Value }
})
if ([string]$policy.signing.code_signing_eku_oid -notin $eku) { throw 'TEST_CODE_SIGNING_EKU_MISSING' }
Write-Host "Created test certificate thumbprint=$($cert.Thumbprint)"

# Deliberately do not add this self-signed identity to Root or TrustedPeople.
# The CI test proves two separate facts: SignTool can embed an Authenticode
# signature with the ephemeral private key, and Windows/final release policy
# still refuses to treat that untrusted self-signed identity as production.
$signTool = Find-SignTool
Write-Host "Using SignTool: $signTool"
foreach ($full in $resolved) {
  $name = [IO.Path]::GetFileName($full)
  # Test-only identities deliberately do not contact an external TSA. Production
  # signing remains timestamp-mandatory in sign_windows_release.ps1/finalizer.
  Invoke-SignToolBounded -SignTool $signTool -Arguments @('sign','/fd','SHA256','/s','My','/sha1',$cert.Thumbprint,$full) -Operation "sign:$name"
}

$evidence = [ordered]@{
  schema_version = '0.1.0'
  mode = 'test'
  test_identity = $true
  self_signed = $true
  production_eligible = $false
  timestamp_requested = $false
  subprocess_timeout_seconds = 60
  subject = [string]$cert.Subject
  issuer = [string]$cert.Issuer
  der_sha256 = Get-DerSha256 $cert
  thumbprint = ([string]$cert.Thumbprint).ToLowerInvariant()
  has_private_key = [bool]$cert.HasPrivateKey
  private_key_exported = $false
  certificate_store_location = 'CurrentUser'
  certificate_store_name = 'My'
  trust_store_modified = $false
  windows_trust_expected = $false
  not_before = $cert.NotBefore.ToUniversalTime().ToString('o')
  not_after = $cert.NotAfter.ToUniversalTime().ToString('o')
  artifact_names = @($resolved | ForEach-Object { [IO.Path]::GetFileName($_) } | Sort-Object)
  note = 'Ephemeral self-signed test identity only; intentionally untrusted; bounded SignTool signing; no external timestamp. Never valid production release evidence.'
}
$out = [IO.Path]::GetFullPath($IdentityEvidenceOut)
New-Item -ItemType Directory -Force (Split-Path $out) | Out-Null
[IO.File]::WriteAllText($out, (($evidence | ConvertTo-Json -Depth 8) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
Write-Host "Self-signed $($resolved.Count) test artifact(s) without modifying Windows trust stores. Identity evidence: $out"
