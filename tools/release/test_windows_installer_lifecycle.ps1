[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$PolicyPath,
  [Parameter(Mandatory)][string]$PreviousInstaller,
  [Parameter(Mandatory)][string]$CurrentInstaller,
  [Parameter(Mandatory)][string]$SourceCommit,
  [Parameter(Mandatory)][string]$EvidenceOut
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($SourceCommit -notmatch '^[0-9a-f]{40}$') { throw 'SOURCE_COMMIT_REJECTED' }
$policy = Get-Content (Resolve-Path $PolicyPath) -Raw | ConvertFrom-Json -Depth 32
if ($policy.policy_id -ne 'ergaxiom.windows-production-release' -or $policy.canonical_installer -ne 'nsis') { throw 'POLICY_REJECTED' }
if (
  $policy.packaging.install_mode -ne 'perMachine' -or
  $policy.packaging.allow_downgrades -ne $false -or
  $policy.packaging.install_root -ne '%ProgramFiles%\Ergaxiom' -or
  $policy.packaging.production_state_root -ne '%ProgramData%\Ergaxiom' -or
  $policy.packaging.uninstall_preserves_production_state -ne $true
) { throw 'LIFECYCLE_POLICY_REJECTED' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'ADMINISTRATOR_REQUIRED' }

$previous = (Resolve-Path $PreviousInstaller).Path
$current = (Resolve-Path $CurrentInstaller).Path
if ($previous -eq $current) { throw 'INSTALLER_SUBSTITUTION' }
$installRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Ergaxiom'
$stateRoot = Join-Path $env:ProgramData 'Ergaxiom'
$sentinel = Join-Path $stateRoot 'ci-lifecycle-state.txt'
$marker = [Guid]::NewGuid().ToString('N')
$processTimeoutMs = 180000
$stateConvergenceTimeoutMs = 30000

function RunProcess([string]$path, [string[]]$arguments) {
  $process = Start-Process -FilePath $path -ArgumentList $arguments -PassThru
  if (-not $process.WaitForExit($processTimeoutMs)) {
    try { $process.Kill($true) } catch {}
    throw "PROCESS_TIMEOUT: $([IO.Path]::GetFileName($path))"
  }
  return $process.ExitCode
}
function RunInstaller([string]$path, [bool]$expectSuccess, [string[]]$arguments = @('/S')) {
  $exitCode = RunProcess $path $arguments
  if ($expectSuccess -and $exitCode -ne 0) { throw "INSTALLER_FAILED: $exitCode" }
  return $exitCode
}
function RunUpdater([string]$path, [bool]$expectSuccess) {
  # Match Tauri's Windows updater contract: passive UI plus explicit update mode.
  # Do not use /S here; silent install is retained below for clean-install and
  # downgrade-attack coverage, while /UPDATE exercises the real update path.
  return RunInstaller $path $expectSuccess @('/P', '/UPDATE')
}
function Entries {
  $result = @()
  foreach ($root in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
    $items = @(Get-ItemProperty $root -ErrorAction SilentlyContinue)
    foreach ($item in $items) {
      $displayNameProperty = $item.PSObject.Properties['DisplayName']
      if ($null -ne $displayNameProperty -and [string]$displayNameProperty.Value -eq 'Ergaxiom') {
        $result += $item
      }
    }
  }
  return @($result)
}
function ObservedVersions {
  $versions = @()
  foreach ($entry in @(Entries)) {
    $property = $entry.PSObject.Properties['DisplayVersion']
    if ($null -ne $property) { $versions += [string]$property.Value } else { $versions += '<missing>' }
  }
  return @($versions)
}
function WaitForVersion([string]$version) {
  $stopwatch = [Diagnostics.Stopwatch]::StartNew()
  do {
    $entries = @(Entries)
    if ($entries.Count -eq 1) {
      $displayVersionProperty = $entries[0].PSObject.Properties['DisplayVersion']
      if ($null -ne $displayVersionProperty -and [string]$displayVersionProperty.Value -eq $version) { return }
    }
    Start-Sleep -Milliseconds 250
  } while ($stopwatch.ElapsedMilliseconds -lt $stateConvergenceTimeoutMs)
  $observed = @(ObservedVersions)
  throw "VERSION_TRANSITION_TIMEOUT: expected=$version observed=$($observed -join ',') entries=$(@(Entries).Count)"
}
function OneEntry([string]$version) {
  $entries = @(Entries)
  if ($entries.Count -ne 1) { throw "UNINSTALL_REGISTRY_CARDINALITY: $($entries.Count)" }
  $displayVersionProperty = $entries[0].PSObject.Properties['DisplayVersion']
  if ($null -eq $displayVersionProperty) { throw 'DISPLAY_VERSION_MISSING' }
  if ([string]$displayVersionProperty.Value -ne $version) { throw "VERSION_MISMATCH: expected=$version actual=$($displayVersionProperty.Value)" }
  return $entries[0]
}
function AssertInstalled([string]$version) {
  $entry = OneEntry $version
  if (-not (Test-Path $installRoot)) { throw 'INSTALL_ROOT_MISSING' }
  $desktop = @(Get-ChildItem $installRoot -Recurse -File -Filter 'ergaxiom-desktop.exe')
  $service = @(Get-ChildItem $installRoot -Recurse -File -Filter 'ergaxiom-windows-production-signer-service.exe')
  if ($desktop.Count -ne 1 -or $service.Count -ne 1) { throw 'INSTALLED_ARTIFACT_INVENTORY_MISMATCH' }
  return $entry
}
function UninstallCurrent {
  $entry = OneEntry '0.1.0'
  $uninstallProperty = $entry.PSObject.Properties['UninstallString']
  if ($null -eq $uninstallProperty) { throw 'UNINSTALL_STRING_MISSING' }
  $text = [string]$uninstallProperty.Value
  if ([string]::IsNullOrWhiteSpace($text)) { throw 'UNINSTALL_STRING_MISSING' }
  $exe = $text.Trim().Trim('"')
  if ($exe.Contains('"') -or $exe.Contains(' /') -or $exe.Contains(' -')) { throw 'UNINSTALL_COMMAND_REJECTED' }
  $full = [IO.Path]::GetFullPath($exe)
  $rootWithSeparator = [IO.Path]::GetFullPath($installRoot) + [IO.Path]::DirectorySeparatorChar
  if (-not $full.StartsWith($rootWithSeparator, [StringComparison]::OrdinalIgnoreCase)) { throw 'UNINSTALL_PATH_OUTSIDE_INSTALL_ROOT' }
  if (-not (Test-Path $full)) { throw 'UNINSTALLER_MISSING' }
  $exitCode = RunProcess $full @('/S')
  if ($exitCode -ne 0) { throw "UNINSTALL_FAILED: $exitCode" }
  Start-Sleep -Seconds 1
  if (@(Entries).Count -ne 0) { throw 'UNINSTALL_REGISTRY_REMAINS' }
}
function AssertSentinel {
  if (-not (Test-Path $sentinel) -or (Get-Content $sentinel -Raw).Trim() -ne $marker) { throw 'PRODUCTION_STATE_SENTINEL_LOST' }
}

if ((Test-Path $installRoot) -or @(Entries).Count -ne 0) { throw 'RUNNER_NOT_CLEAN' }
New-Item -ItemType Directory -Force $stateRoot | Out-Null
Set-Content -Path $sentinel -Value $marker -Encoding ascii -NoNewline

RunInstaller $previous $true | Out-Null
WaitForVersion '0.0.9'
AssertInstalled '0.0.9' | Out-Null
AssertSentinel
$clean = $true

RunUpdater $current $true | Out-Null
WaitForVersion '0.1.0'
AssertInstalled '0.1.0' | Out-Null
AssertSentinel
$upgrade = $true

$downgradeExit = RunInstaller $previous $false
AssertInstalled '0.1.0' | Out-Null
AssertSentinel
$downgradeRejected = $true

UninstallCurrent
AssertSentinel
RunInstaller $previous $true | Out-Null
WaitForVersion '0.0.9'
AssertInstalled '0.0.9' | Out-Null
AssertSentinel

$env:ERGA_CI_INTERRUPT = '1'
try { $interruptExit = RunUpdater $current $false } finally { Remove-Item Env:ERGA_CI_INTERRUPT -ErrorAction SilentlyContinue }
if ($interruptExit -eq 0) { throw 'INTERRUPTED_UPGRADE_UNEXPECTED_SUCCESS' }
AssertInstalled '0.0.9' | Out-Null
AssertSentinel
$interrupted = $true

RunUpdater $current $true | Out-Null
WaitForVersion '0.1.0'
AssertInstalled '0.1.0' | Out-Null
AssertSentinel
$recovery = $true

UninstallCurrent
AssertSentinel
$uninstall = $true
$statePreserved = $true

$evidence = [ordered]@{
  schema_version = '0.1.0'
  source_commit = $SourceCommit
  test_mode = $true
  installer_name = [IO.Path]::GetFileName($current)
  installer_sha256 = (Get-FileHash $current -Algorithm SHA256).Hash.ToLowerInvariant()
  previous_installer_name = [IO.Path]::GetFileName($previous)
  previous_installer_sha256 = (Get-FileHash $previous -Algorithm SHA256).Hash.ToLowerInvariant()
  observed_versions = [ordered]@{ previous = '0.0.9'; current = '0.1.0' }
  attack_observations = [ordered]@{ downgrade_exit_code = $downgradeExit; interrupted_upgrade_exit_code = $interruptExit }
  phases = [ordered]@{
    clean_install = $clean
    upgrade = $upgrade
    downgrade_rejected = $downgradeRejected
    interrupted_upgrade_preserved_state = $interrupted
    recovery_install = $recovery
    uninstall = $uninstall
    production_state_preserved = $statePreserved
  }
}
$out = [IO.Path]::GetFullPath($EvidenceOut)
New-Item -ItemType Directory -Force (Split-Path $out) | Out-Null
$evidence | ConvertTo-Json -Depth 8 | Set-Content $out -Encoding utf8NoBOM
