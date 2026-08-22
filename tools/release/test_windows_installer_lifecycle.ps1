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
  $policy.packaging.updater_install_mode -ne 'quiet' -or
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
$installerVersionMarker = Join-Path $installRoot 'ci-installer-version.txt'
$stateRoot = Join-Path $env:ProgramData 'Ergaxiom'
$sentinel = Join-Path $stateRoot 'ci-lifecycle-state.txt'
$installerProcessMarker = Join-Path $stateRoot 'ci-installer-process.txt'
$marker = [Guid]::NewGuid().ToString('N')
$processTimeoutMs = 180000
$stateConvergenceTimeoutMs = 30000
$stateStableWindowMs = 3000

function RunProcess([string]$path, [string[]]$arguments) {
  # Start-Process -Wait normally waits for descendants, but an elevated NSIS
  # execution process can detach/reparent across the Windows elevation boundary.
  # The test-only hook records the process that actually reaches the installer
  # section; RunInstaller/UninstallCurrent wait for that process separately.
  $pipeline = [PowerShell]::Create()
  $invocation = $null
  try {
    [void]$pipeline.AddCommand('Start-Process')
    [void]$pipeline.AddParameter('FilePath', $path)
    [void]$pipeline.AddParameter('ArgumentList', $arguments)
    [void]$pipeline.AddParameter('PassThru')
    [void]$pipeline.AddParameter('Wait')
    [void]$pipeline.AddParameter('ErrorAction', 'Stop')
    $invocation = $pipeline.BeginInvoke()
    if (-not $invocation.AsyncWaitHandle.WaitOne($processTimeoutMs)) {
      $pipeline.Stop()
      throw "PROCESS_TREE_TIMEOUT: $([IO.Path]::GetFileName($path))"
    }
    $result = @($pipeline.EndInvoke($invocation))
    if ($pipeline.HadErrors) {
      $detail = ($pipeline.Streams.Error | ForEach-Object { $_.ToString() }) -join '; '
      throw "PROCESS_TREE_FAILED: $([IO.Path]::GetFileName($path)): $detail"
    }
    if ($result.Count -ne 1) {
      throw "PROCESS_TREE_RESULT_CARDINALITY: $([IO.Path]::GetFileName($path)) count=$($result.Count)"
    }
    return [int]$result[0].ExitCode
  } finally {
    if ($null -ne $invocation) { $invocation.AsyncWaitHandle.Close() }
    $pipeline.Dispose()
  }
}
function ClearInstallerProcessMarker {
  Remove-Item $installerProcessMarker -Force -ErrorAction SilentlyContinue
}
function WaitForInstallerHookProcessExit([string]$operation, [string]$version, [bool]$required) {
  $recordStopwatch = [Diagnostics.Stopwatch]::StartNew()
  $recordedProcessId = $null
  do {
    if (Test-Path $installerProcessMarker) {
      $record = (Get-Content $installerProcessMarker -Raw).Trim()
      if ($record -notmatch '^(install|uninstall)\|([0-9]+\.[0-9]+\.[0-9]+)\|([1-9][0-9]*)$') {
        throw "INSTALLER_PROCESS_MARKER_MALFORMED: $record"
      }
      if ($Matches[1] -ne $operation -or $Matches[2] -ne $version) {
        throw "INSTALLER_PROCESS_MARKER_MISMATCH: expected=$operation|$version actual=$record"
      }
      $recordedProcessId = [int]$Matches[3]
      break
    }
    if (-not $required) { return }
    Start-Sleep -Milliseconds 100
  } while ($recordStopwatch.ElapsedMilliseconds -lt $processTimeoutMs)

  if ($null -eq $recordedProcessId) {
    throw "INSTALLER_PROCESS_MARKER_TIMEOUT: expected=$operation|$version"
  }

  $processStopwatch = [Diagnostics.Stopwatch]::StartNew()
  do {
    try {
      $observedProcess = [Diagnostics.Process]::GetProcessById($recordedProcessId)
      try {
        if ($observedProcess.HasExited) {
          ClearInstallerProcessMarker
          return
        }
      } finally {
        $observedProcess.Dispose()
      }
    } catch [ArgumentException] {
      ClearInstallerProcessMarker
      return
    } catch {
      throw "INSTALLER_PROCESS_PROBE_FAILED: operation=$operation version=$version pid=$recordedProcessId detail=$($_.Exception.Message)"
    }
    Start-Sleep -Milliseconds 100
  } while ($processStopwatch.ElapsedMilliseconds -lt $processTimeoutMs)

  throw "INSTALLER_PROCESS_EXIT_TIMEOUT: operation=$operation version=$version pid=$recordedProcessId"
}
function RunInstaller([string]$path, [bool]$expectSuccess, [string]$version, [bool]$hookRequired, [string[]]$arguments = @('/S')) {
  ClearInstallerProcessMarker
  $exitCode = RunProcess $path $arguments
  WaitForInstallerHookProcessExit 'install' $version $hookRequired
  if ($expectSuccess -and $exitCode -ne 0) { throw "INSTALLER_FAILED: $exitCode" }
  return $exitCode
}
function RunUpdater([string]$path, [bool]$expectSuccess, [bool]$hookRequired = $true) {
  # The release policy pins Tauri's quiet Windows updater contract. Tauri maps
  # quiet NSIS updates to /S plus /UPDATE, keeping the lifecycle fully unattended
  # while still exercising the real updater-specific install path.
  return RunInstaller $path $expectSuccess '0.1.0' $hookRequired @('/S', '/UPDATE')
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
function ReadInstallerVersionMarker {
  if (-not (Test-Path $installerVersionMarker)) { return '<missing>' }
  return (Get-Content $installerVersionMarker -Raw).Trim()
}
function AssertInstallerVersionMarker([string]$version) {
  $observed = ReadInstallerVersionMarker
  if ($observed -ne $version) { throw "POSTINSTALL_VERSION_MARKER_MISMATCH: expected=$version actual=$observed" }
}
function WaitForStableVersion([string]$version) {
  $stopwatch = [Diagnostics.Stopwatch]::StartNew()
  $stableSinceMs = $null
  do {
    $entries = @(Entries)
    $matches = $false
    if ($entries.Count -eq 1) {
      $displayVersionProperty = $entries[0].PSObject.Properties['DisplayVersion']
      $matches = $null -ne $displayVersionProperty -and [string]$displayVersionProperty.Value -eq $version
    }
    if ($matches) {
      if ($null -eq $stableSinceMs) { $stableSinceMs = $stopwatch.ElapsedMilliseconds }
      if (($stopwatch.ElapsedMilliseconds - $stableSinceMs) -ge $stateStableWindowMs) { return }
    } else {
      $stableSinceMs = $null
    }
    Start-Sleep -Milliseconds 250
  } while ($stopwatch.ElapsedMilliseconds -lt $stateConvergenceTimeoutMs)
  $observed = @(ObservedVersions)
  $postInstallMarker = ReadInstallerVersionMarker
  throw "VERSION_STABILITY_TIMEOUT: expected=$version observed=$($observed -join ',') entries=$(@(Entries).Count) postinstall_marker=$postInstallMarker stable_window_ms=$stateStableWindowMs"
}
function WaitForStableUninstalled {
  $stopwatch = [Diagnostics.Stopwatch]::StartNew()
  $stableSinceMs = $null
  do {
    if (@(Entries).Count -eq 0) {
      if ($null -eq $stableSinceMs) { $stableSinceMs = $stopwatch.ElapsedMilliseconds }
      if (($stopwatch.ElapsedMilliseconds - $stableSinceMs) -ge $stateStableWindowMs) { return }
    } else {
      $stableSinceMs = $null
    }
    Start-Sleep -Milliseconds 250
  } while ($stopwatch.ElapsedMilliseconds -lt $stateConvergenceTimeoutMs)
  $observed = @(ObservedVersions)
  throw "UNINSTALL_STABILITY_TIMEOUT: observed=$($observed -join ',') entries=$(@(Entries).Count) stable_window_ms=$stateStableWindowMs"
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
  AssertInstallerVersionMarker $version
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
  ClearInstallerProcessMarker
  $exitCode = RunProcess $full @('/S')
  WaitForInstallerHookProcessExit 'uninstall' '0.1.0' $true
  if ($exitCode -ne 0) { throw "UNINSTALL_FAILED: $exitCode" }
  WaitForStableUninstalled
  if (Test-Path $installerVersionMarker) { throw 'POSTUNINSTALL_VERSION_MARKER_PRESENT' }
}
function AssertSentinel {
  if (-not (Test-Path $sentinel) -or (Get-Content $sentinel -Raw).Trim() -ne $marker) { throw 'PRODUCTION_STATE_SENTINEL_LOST' }
}

if ((Test-Path $installRoot) -or @(Entries).Count -ne 0) { throw 'RUNNER_NOT_CLEAN' }
New-Item -ItemType Directory -Force $stateRoot | Out-Null
Set-Content -Path $sentinel -Value $marker -Encoding ascii -NoNewline
ClearInstallerProcessMarker

RunInstaller $previous $true '0.0.9' $true | Out-Null
WaitForStableVersion '0.0.9'
AssertInstalled '0.0.9' | Out-Null
AssertSentinel
$clean = $true

RunUpdater $current $true | Out-Null
Write-Host "TEST_ONLY: updater returned; registry=$(@(ObservedVersions) -join ',') postinstall_marker=$(ReadInstallerVersionMarker)"
WaitForStableVersion '0.1.0'
AssertInstalled '0.1.0' | Out-Null
AssertSentinel
$upgrade = $true

$downgradeExit = RunInstaller $previous $false '0.0.9' $false
WaitForStableVersion '0.1.0'
AssertInstalled '0.1.0' | Out-Null
AssertSentinel
$downgradeRejected = $true

UninstallCurrent
AssertSentinel
RunInstaller $previous $true '0.0.9' $true | Out-Null
WaitForStableVersion '0.0.9'
AssertInstalled '0.0.9' | Out-Null
AssertSentinel

$env:ERGA_CI_INTERRUPT = '1'
try { $interruptExit = RunUpdater $current $false $true } finally { Remove-Item Env:ERGA_CI_INTERRUPT -ErrorAction SilentlyContinue }
if ($interruptExit -eq 0) { throw 'INTERRUPTED_UPGRADE_UNEXPECTED_SUCCESS' }
WaitForStableVersion '0.0.9'
AssertInstalled '0.0.9' | Out-Null
AssertSentinel
$interrupted = $true

RunUpdater $current $true | Out-Null
WaitForStableVersion '0.1.0'
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
  updater_install_mode = [string]$policy.packaging.updater_install_mode
  test_only_postinstall_marker = '0.1.0'
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
