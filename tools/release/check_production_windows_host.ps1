[CmdletBinding()]
param(
  [string]$PolicyPath = 'tools/release/windows_release_policy.json',
  [string]$OutputPath,
  [switch]$RequireReady
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-DerSha256([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
  return ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Certificate.RawData))).ToLowerInvariant()
}

function Get-CodeSigningEkus([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
  return @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | ForEach-Object {
    ([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$_).EnhancedKeyUsages | ForEach-Object { $_.Value }
  })
}

function Resolve-Executable([string]$Name) {
  $command = Get-Command $Name -ErrorAction SilentlyContinue
  if ($command) { return [string]$command.Source }
  return $null
}

function Resolve-SignTool {
  $direct = Resolve-Executable 'signtool.exe'
  if ($direct) { return $direct }
  if (-not ${env:ProgramFiles(x86)}) { return $null }
  $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
  if (-not (Test-Path $kits -PathType Container)) { return $null }
  return Get-ChildItem $kits -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending |
    ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
    Where-Object { Test-Path $_ -PathType Leaf } |
    Select-Object -First 1
}

function New-UnavailableProviderReport([bool]$IsWindowsHost) {
  # Fail-closed placeholder used when the detector cannot run at all. A provider
  # is never assumed present; only a real probe may set `present`.
  return [ordered]@{
    schema_version = '0.1.0'
    provider_name = 'Microsoft Platform Crypto Provider'
    platform_windows = [bool]$IsWindowsHost
    present = $false
    detection_method = $null
    registered = $false
    registration_method = $null
    native_open = [ordered]@{ attempted = $false; opened = $false; status = $null; error = 'PROVIDER_DETECTION_UNAVAILABLE' }
    native_enumeration = [ordered]@{ attempted = $false; found = $false; provider_count = 0; status = $null; error = 'PROVIDER_DETECTION_UNAVAILABLE' }
    certutil_csplist = [ordered]@{ attempted = $false; matched = $false; exit_code = $null; error = 'PROVIDER_DETECTION_UNAVAILABLE' }
    note = 'Read-only provider inventory. Not TPM ceremony evidence and never release evidence.'
  }
}

function Get-ToolRecord([string]$Name, [string]$Executable) {
  if ([string]::IsNullOrWhiteSpace($Executable)) {
    return [ordered]@{ present = $false; path = $null }
  }
  return [ordered]@{ present = $true; path = $Executable }
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$policyResolved = if ([IO.Path]::IsPathRooted($PolicyPath)) { $PolicyPath } else { Join-Path $repoRoot $PolicyPath }
if (-not (Test-Path $policyResolved -PathType Leaf)) { throw "POLICY_MISSING: $policyResolved" }
$policy = Get-Content $policyResolved -Raw | ConvertFrom-Json -Depth 32
if ($policy.schema_version -ne '0.1.0' -or $policy.policy_id -ne 'ergaxiom.windows-production-release') { throw 'POLICY_REJECTED' }

$windowsHost = $env:OS -eq 'Windows_NT'
$sourceCommit = $null
$trackedClean = $false
$gitPath = Resolve-Executable 'git.exe'
if (-not $gitPath) { $gitPath = Resolve-Executable 'git' }
if ($gitPath) {
  $sourceCommit = (& $gitPath -C $repoRoot rev-parse HEAD 2>$null).Trim()
  if ($LASTEXITCODE -eq 0 -and $sourceCommit -match '^[0-9a-f]{40}$') {
    $trackedStatus = & $gitPath -C $repoRoot status --porcelain --untracked-files=no 2>$null
    $trackedClean = $LASTEXITCODE -eq 0 -and -not $trackedStatus
  }
}

$elevated = $false
if ($windowsHost) {
  try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { $elevated = $false }
}

$tpm = [ordered]@{
  command_available = $false
  present = $false
  ready = $false
  enabled = $false
  activated = $false
}
if ($windowsHost -and (Get-Command Get-Tpm -ErrorAction SilentlyContinue)) {
  $tpm.command_available = $true
  try {
    $observed = Get-Tpm
    $tpm.present = [bool]$observed.TpmPresent
    $tpm.ready = [bool]$observed.TpmReady
    $tpm.enabled = [bool]$observed.TpmEnabled
    $tpm.activated = [bool]$observed.TpmActivated
  } catch { }
}

$certutilPath = Resolve-Executable 'certutil.exe'
$platformProvider = New-UnavailableProviderReport $windowsHost
$detectorPath = Join-Path $PSScriptRoot 'detect_platform_crypto_provider.ps1'
if (Test-Path $detectorPath -PathType Leaf) {
  try {
    $detected = & $detectorPath
    if ($detected) { $platformProvider = $detected }
  } catch {
    $platformProvider = New-UnavailableProviderReport $windowsHost
    $platformProvider.native_open.error = [string]$_.Exception.Message
    $platformProvider.native_enumeration.error = [string]$_.Exception.Message
  }
}
$platformProviderPresent = [bool]$platformProvider.present

$signToolPath = if ($windowsHost) { Resolve-SignTool } else { $null }
$cargoPath = Resolve-Executable 'cargo.exe'; if (-not $cargoPath) { $cargoPath = Resolve-Executable 'cargo' }
$rustcPath = Resolve-Executable 'rustc.exe'; if (-not $rustcPath) { $rustcPath = Resolve-Executable 'rustc' }
$nodePath = Resolve-Executable 'node.exe'; if (-not $nodePath) { $nodePath = Resolve-Executable 'node' }
$npmPath = Resolve-Executable 'npm.cmd'; if (-not $npmPath) { $npmPath = Resolve-Executable 'npm' }
$pythonPath = Resolve-Executable 'python.exe'; if (-not $pythonPath) { $pythonPath = Resolve-Executable 'python' }

$signing = $policy.signing
$storePath = "Cert:\$($signing.certificate_store_location)\$($signing.certificate_store_name)"
$candidates = @()
if ($windowsHost -and (Test-Path $storePath)) {
  $now = Get-Date
  foreach ($certificate in @(Get-ChildItem $storePath -ErrorAction SilentlyContinue)) {
    $ekus = @(Get-CodeSigningEkus $certificate)
    if ([string]$signing.code_signing_eku_oid -notin $ekus) { continue }
    $der = Get-DerSha256 $certificate
    $selfSigned = $certificate.Subject -eq $certificate.Issuer
    $validNow = $now -ge $certificate.NotBefore -and $now -lt $certificate.NotAfter
    $candidates += [ordered]@{
      subject = [string]$certificate.Subject
      der_sha256 = $der
      thumbprint = ([string]$certificate.Thumbprint).ToLowerInvariant()
      has_private_key = [bool]$certificate.HasPrivateKey
      self_signed = [bool]$selfSigned
      valid_now = [bool]$validNow
      not_before = $certificate.NotBefore.ToUniversalTime().ToString('o')
      not_after = $certificate.NotAfter.ToUniversalTime().ToString('o')
      acceptable_for_pinning = [bool]($certificate.HasPrivateKey -and -not $selfSigned -and $validNow)
    }
  }
}

$pinnedResolved = $signing.identity_status -eq 'OWNER_APPROVED_PINNED' -and
  -not [string]::IsNullOrWhiteSpace([string]$signing.expected_subject) -and
  [string]$signing.expected_certificate_sha256 -match '^[0-9a-f]{64}$'
$pinnedMatches = @()
if ($pinnedResolved) {
  $pinnedMatches = @($candidates | Where-Object {
    $_.subject -ceq [string]$signing.expected_subject -and
    $_.der_sha256 -ceq [string]$signing.expected_certificate_sha256
  })
}

$toolchainReady = [bool]($gitPath -and $cargoPath -and $rustcPath -and $nodePath -and $npmPath -and $pythonPath -and $signToolPath)
$physicalTpmReady = [bool]($tpm.present -and $tpm.ready -and $tpm.enabled -and $tpm.activated -and $platformProviderPresent)
$prepareReady = [bool](
  $windowsHost -and $trackedClean -and $toolchainReady -and $pinnedResolved -and
  $pinnedMatches.Count -eq 1 -and $pinnedMatches[0].acceptable_for_pinning
)
$controlledHardwareReady = [bool]($windowsHost -and $elevated -and $physicalTpmReady)

$report = [ordered]@{
  schema_version = '0.1.0'
  source_commit = $sourceCommit
  tracked_worktree_clean = [bool]$trackedClean
  platform_windows = [bool]$windowsHost
  elevated_administrator = [bool]$elevated
  tools = [ordered]@{
    git = Get-ToolRecord 'git' $gitPath
    cargo = Get-ToolRecord 'cargo' $cargoPath
    rustc = Get-ToolRecord 'rustc' $rustcPath
    node = Get-ToolRecord 'node' $nodePath
    npm = Get-ToolRecord 'npm' $npmPath
    python = Get-ToolRecord 'python' $pythonPath
    signtool = Get-ToolRecord 'signtool' $signToolPath
    certutil = Get-ToolRecord 'certutil' $certutilPath
  }
  tpm = $tpm
  microsoft_platform_crypto_provider_present = [bool]$platformProviderPresent
  microsoft_platform_crypto_provider = $platformProvider
  signing_policy = [ordered]@{
    identity_status = [string]$signing.identity_status
    certificate_store_location = [string]$signing.certificate_store_location
    certificate_store_name = [string]$signing.certificate_store_name
    expected_subject = $signing.expected_subject
    expected_certificate_sha256 = $signing.expected_certificate_sha256
    policy_pin_resolved = [bool]$pinnedResolved
  }
  code_signing_candidates = $candidates
  exact_pinned_certificate_count = [int]$pinnedMatches.Count
  ready_for_signed_candidate_prepare = $prepareReady
  ready_for_controlled_hardware_ceremony = $controlledHardwareReady
  physical_tpm_evidence_proven = $false
  release_eligible = $false
  note = 'Read-only preflight only. This report is not Authenticode, physical TPM, lifecycle, or production-chain evidence.'
}

# Informational native probes inside this read-only inventory (certutil) may leave
# their own non-zero exit code behind. This script signals failure by throwing, so
# a successful inventory must not hand a stale failure code to its caller.
$global:LASTEXITCODE = 0

$json = $report | ConvertTo-Json -Depth 16
if ($OutputPath) {
  $out = if ([IO.Path]::IsPathRooted($OutputPath)) { $OutputPath } else { Join-Path $repoRoot $OutputPath }
  $parent = Split-Path $out -Parent
  if ($parent) { New-Item -ItemType Directory -Force $parent | Out-Null }
  [IO.File]::WriteAllText($out, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}
$json

if ($RequireReady -and -not ($prepareReady -and $controlledHardwareReady)) {
  throw 'PRODUCTION_WINDOWS_HOST_NOT_READY'
}
