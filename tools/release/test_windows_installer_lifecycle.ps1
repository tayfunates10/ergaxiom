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
$installerActiveMarker = Join-Path $stateRoot 'ci-installer-active.txt'
$installerCompleteMarker = Join-Path $stateRoot 'ci-installer-complete.txt'
$marker = [Guid]::NewGuid().ToString('N')
$processTimeoutMs = 180000
$processTreeStableWindowMs = 1000
$stateConvergenceTimeoutMs = 30000
$stateStableWindowMs = 3000

function RunProcess([string]$path, [string[]]$arguments) {
  # NSIS may keep a descendant alive after the launcher and the hook-owning
  # process have exited. Track the complete Windows parent-PID tree from the
  # process we launch and do not advance the lifecycle until that tree has
  # been empty for a bounded stable window. This is stricter than relying on
  # Start-Process -Wait and prevents a delayed older installer from mutating
  # registry/files after the next lifecycle phase starts.
  $process = Start-Process -FilePath $path -ArgumentList $arguments -PassThru -ErrorAction Stop
  $rootPid = [int]$process.Id
  $tracked = [Collections.Generic.HashSet[int]]::new()
  [void]$tracked.Add($rootPid)
  $stopwatch = [Diagnostics.Stopwatch]::StartNew()
  $stableSinceMs = $null
  $rootExitCode = $null
  try {
    do {
      $snapshot = @(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object ProcessId, ParentProcessId, Name)

      # Expand transitively so descendants remain tracked even after an
      # intermediate parent exits. ParentProcessId preserves the creator PID.
      $changed = $true
      while ($changed) {
        $changed = $false
        foreach ($candidate in $snapshot) {
          $candidatePid = [int]$candidate.ProcessId
          $parentPid = [int]$candidate.ParentProcessId
          if ($candidatePid -gt 0 -and $tracked.Contains($parentPid) -and -not $tracked.Contains($candidatePid)) {
            [void]$tracked.Add($candidatePid)
            $changed = $true
          }
        }
      }

      if ($null -eq $rootExitCode -and $process.HasExited) {
        $process.WaitForExit()
        $rootExitCode = [int]$process.ExitCode
      }

      $activeTracked = @($snapshot | Where-Object { $tracked.Contains([int]$_.ProcessId) })
      if ($null -ne $rootExitCode -and $activeTracked.Count -eq 0) {
        if ($null -eq $stableSinceMs) { $stableSinceMs = $stopwatch.ElapsedMilliseconds }
        if (($stopwatch.ElapsedMilliseconds - $stableSinceMs) -ge $processTreeStableWindowMs) {
          return $rootExitCode
        }
      } else {
        $stableSinceMs = $null
      }

      Start-Sleep -Milliseconds 100
    } while ($stopwatch.ElapsedMilliseconds -lt $processTimeoutMs)

    $remaining = @(
      Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $tracked.Contains([int]$_.ProcessId) } |
        ForEach-Object { "$($_.ProcessId):$($_.Name):parent=$($_.ParentProcessId)" }
    )
    throw "PROCESS_TREE_TIMEOUT: $([IO.Path]::GetFileName($path)) root_pid=$rootPid tracked=$($tracked.Count) remaining=$($remaining -join ',')"
  } finally {
    $process.Dispose()
  }
}
function ClearInstallerInvocationMarkers {
  Remove-Item $installerActiveMarker -Force -ErrorAction SilentlyContinue
  Remove-Item $installerCompleteMarker -Force -ErrorAction SilentlyContinue
}
function ParseInstallerProcessRecord([string]$path) {
  $record = (Get-Content $path -Raw).Trim()
  if ($record -notmatch '^([0-9a-f]{32})\|(install|uninstall)\|([0-9]+\.[0-9]+\.[0-9]+)\|([1-9][0-9]*)$') {
    throw "INSTALLER_PROCESS_MARKER_MALFORMED: path=$path record=$record"
  }
  return [ordered]@{
    invocation_id = $Matches[1]
    operation = $Matches[2]
    version = $Matches[3]
    process_id = [int]$Matches[4]
  }
}
function WaitForInstallerMarker([string]$path, [string]$phase, [string]$invocationId, [string]$operation, [string]$version, [bool]$required) {
  $stopwatch = [Diagnostics.Stopwatch]::StartNew()
  do {
    if (Test-Path $path) {
      $record = ParseInstallerProcessRecord $path
      if ($record.invocation_id -ne $invocationId) {
        throw "STALE_INSTALLER_PROCESS_MARKER: phase=$phase expected_invocation=$invocationId actual_invocation=$($record.invocation_id) operation=$($record.operation) version=$($record.version) pid=$($record.process_id)"
      }
      if ($record.operation -ne $operation -or $record.version -ne $version) {
        throw "INSTALLER_PROCESS_MARKER_MISMATCH: phase=$phase expected=$operation|$version actual=$($record.operation)|$($record.version)"
      }
      return $record
    }
    if (-not $required) { return $null }
    Start-Sleep -Milliseconds 100
  } while ($stopwatch.ElapsedMilliseconds -lt $processTimeoutMs)
  throw "INSTALLER_PROCESS_MARKER_TIMEOUT: phase=$phase expected_invocation=$invocationId expected=$operation|$version"
}
function WaitForProcessExit([int]$processId, [string]$operation, [string]$version, [string]$invocationId) {
  $stopwatch = [Diagnostics.Stopwatch]::StartNew()
  do {
    try {
      $observedProcess = [Diagnostics.Process]::GetProcessById($processId)
      try {
        if ($observedProcess.HasExited) { return }
      } finally {
        $observedProcess.Dispose()
      }
    } catch [ArgumentException] {
      return
    } catch {
      throw "INSTALLER_PROCESS_PROBE_FAILED: invocation=$invocationId operation=$operation version=$version pid=$processId detail=$($_.Exception.Message)"
    }
    Start-Sleep -Milliseconds 100
  } while ($stopwatch.ElapsedMilliseconds -lt $processTimeoutMs)
  throw "INSTALLER_PROCESS_EXIT_TIMEOUT: invocation=$invocationId operation=$operation version=$version pid=$processId"
}
function RunInstaller([string]$path, [bool]$expectSuccess, [string]$version, [bool]$hookRequired, [string[]]$arguments = @('/S')) {
  ClearInstallerInvocationMarkers
  $invocationId = [Guid]::NewGuid().ToString('N')
  $env:ERGA_CI_INVOCATION_ID = $invocationId
  try {
    $exitCode = RunProcess $path $arguments
  } finally {
    Remove-Item Env:ERGA_CI_INVOCATION_ID -ErrorAction SilentlyContinue
  }

  if ($hookRequired) {
    $active = WaitForInstallerMarker $installerActiveMarker 'active' $invocationId 'install' $version $true
    $completeRequired = $expectSuccess
    $complete = WaitForInstallerMarker $installerCompleteMarker 'complete' $invocationId 'install' $version $completeRequired
    if ($null -ne $complete -and $complete.process_id -ne $active.process_id) {
      throw "INSTALLER_PROCESS_ID_MISMATCH: invocation=$invocationId active_pid=$($active.process_id) complete_pid=$($complete.process_id)"
    }
    WaitForProcessExit $active.process_id 'install' $version $invocationId
  }

  if ($expectSuccess -and $exitCode -ne 0) { throw "INSTALLER_FAILED: $exitCode" }
  return $exitCode
}
function RunUpdater([string]$path, [bool]$expectSuccess, [bool]$hookRequired = $true) {
  return RunInstaller $path $expectSuccess '0.1.0' $hookRequired @('/S', '/UPDATE')
}
function Entries {
  $result = @()
  foreach ($root in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
    $items = @(Get-ItemProperty $root -ErrorAction SilentlyContinue)
    foreach ($item in $items) {
      $displayNameProperty = $item.PSObject.Properties['DisplayName']
      if ($null -ne $displayNameProperty -and [string]$displayNameProperty.Value -eq 'Ergaxiom') { $result += $item }
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

  ClearInstallerInvocationMarkers
  $invocationId = [Guid]::NewGuid().ToString('N')
  $env:ERGA_CI_INVOCATION_ID = $invocationId
  try {
    $exitCode = RunProcess $full @('/S')
  } finally {
    Remove-Item Env:ERGA_CI_INVOCATION_ID -ErrorAction SilentlyContinue
  }
  $active = WaitForInstallerMarker $installerActiveMarker 'active' $invocationId 'uninstall' '0.1.0' $true
  $complete = WaitForInstallerMarker $installerCompleteMarker 'complete' $invocationId 'uninstall' '0.1.0' $true
  if ($complete.process_id -ne $active.process_id) {
    throw "UNINSTALL_PROCESS_ID_MISMATCH: invocation=$invocationId active_pid=$($active.process_id) complete_pid=$($complete.process_id)"
  }
  WaitForProcessExit $active.process_id 'uninstall' '0.1.0' $invocationId
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
ClearInstallerInvocationMarkers

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