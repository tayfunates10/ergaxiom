[CmdletBinding()]
param(
  [string]$ProviderName = 'Microsoft Platform Crypto Provider',
  [string]$OutputPath,
  [switch]$AsJson
)

# Read-only detection of a Windows CNG key storage provider.
#
# Detection is fail-closed and never infers presence from a localized string that
# a probe did not actually produce. `certutil -csplist` renders localized labels
# on non-English Windows installations and can exit non-zero when an unrelated
# provider fails to enumerate, so it is only a tertiary corroborating probe. The
# authoritative probes are the native CNG entry points, which are locale
# independent:
#   * NCryptOpenStorageProvider - the provider actually opens. Only this proves
#     the provider is usable, so only this may set `present`.
#   * NCryptEnumStorageProviders - the provider name is registered. Corroborating
#     only: the TPM KSP is registered on every Windows install, including hosts
#     with no usable TPM device, so registration alone is not presence.
#
# This report is host inventory only. It is not TPM ceremony evidence, not
# Authenticode evidence and can never make a release eligible.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Format-NCryptStatus([int]$Status) {
  return ('0x{0:x8}' -f $Status)
}

function Initialize-NativeCng {
  if ('Ergaxiom.Release.NativeCng' -as [type]) { return $null }
  $source = @'
using System;
using System.Runtime.InteropServices;

namespace Ergaxiom.Release {
  public sealed class ProviderEnumeration {
    public int Status;
    public string[] Names;
    public ProviderEnumeration() { this.Status = -1; this.Names = new string[0]; }
  }

  public static class NativeCng {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NCryptProviderName {
      [MarshalAs(UnmanagedType.LPWStr)] public string pszName;
      [MarshalAs(UnmanagedType.LPWStr)] public string pszComment;
    }

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, uint dwFlags);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptFreeObject(IntPtr hObject);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptEnumStorageProviders(out uint pdwProviderCount, out IntPtr ppProviderList, uint dwFlags);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptFreeBuffer(IntPtr pvInput);

    public static int TryOpenProvider(string providerName) {
      IntPtr handle = IntPtr.Zero;
      int status = NCryptOpenStorageProvider(out handle, providerName, 0);
      if (status == 0 && handle != IntPtr.Zero) {
        NCryptFreeObject(handle);
      }
      return status;
    }

    public static ProviderEnumeration EnumerateProviders() {
      ProviderEnumeration result = new ProviderEnumeration();
      uint count = 0;
      IntPtr list = IntPtr.Zero;
      result.Status = NCryptEnumStorageProviders(out count, out list, 0);
      if (result.Status != 0 || list == IntPtr.Zero) { return result; }
      try {
        string[] names = new string[count];
        int size = Marshal.SizeOf(typeof(NCryptProviderName));
        for (int index = 0; index < count; index++) {
          IntPtr item = new IntPtr(list.ToInt64() + ((long)index * size));
          NCryptProviderName entry = (NCryptProviderName)Marshal.PtrToStructure(item, typeof(NCryptProviderName));
          names[index] = entry.pszName;
        }
        result.Names = names;
      } finally {
        NCryptFreeBuffer(list);
      }
      return result;
    }
  }
}
'@
  Add-Type -TypeDefinition $source -Language CSharp
  return $null
}

$isWindowsHost = $env:OS -eq 'Windows_NT'

$report = [ordered]@{
  schema_version = '0.1.0'
  provider_name = [string]$ProviderName
  platform_windows = [bool]$isWindowsHost
  present = $false
  detection_method = $null
  registered = $false
  registration_method = $null
  native_open = [ordered]@{ attempted = $false; opened = $false; status = $null; error = $null }
  native_enumeration = [ordered]@{ attempted = $false; found = $false; provider_count = 0; status = $null; error = $null }
  certutil_csplist = [ordered]@{ attempted = $false; matched = $false; exit_code = $null; error = $null }
  note = 'Read-only provider inventory. Not TPM ceremony evidence and never release evidence.'
}

if ($isWindowsHost) {
  try {
    Initialize-NativeCng | Out-Null

    $report.native_open.attempted = $true
    try {
      $openStatus = [Ergaxiom.Release.NativeCng]::TryOpenProvider($ProviderName)
      $report.native_open.status = Format-NCryptStatus $openStatus
      $report.native_open.opened = [bool]($openStatus -eq 0)
    } catch {
      $report.native_open.error = [string]$_.Exception.Message
    }

    $report.native_enumeration.attempted = $true
    try {
      $enumeration = [Ergaxiom.Release.NativeCng]::EnumerateProviders()
      $report.native_enumeration.status = Format-NCryptStatus ([int]$enumeration.Status)
      $names = @($enumeration.Names)
      $report.native_enumeration.provider_count = [int]$names.Count
      $report.native_enumeration.found = [bool](@($names | Where-Object { $_ -ceq $ProviderName }).Count -ge 1)
    } catch {
      $report.native_enumeration.error = [string]$_.Exception.Message
    }
  } catch {
    $report.native_open.error = [string]$_.Exception.Message
    $report.native_enumeration.error = [string]$_.Exception.Message
  }

  $certutil = Get-Command 'certutil.exe' -ErrorAction SilentlyContinue
  if ($certutil) {
    $report.certutil_csplist.attempted = $true
    try {
      $providers = & $certutil.Source -csplist 2>$null | Out-String
      $report.certutil_csplist.exit_code = [int]$LASTEXITCODE
      # The CNG provider identifier itself is not localized; only the surrounding
      # labels and the non-zero exit code of an unrelated provider are. Match the
      # identifier alone so a localized host is not a false negative.
      $report.certutil_csplist.matched = [bool]($providers.Contains($ProviderName))
      # certutil exits non-zero when any unrelated provider fails to enumerate.
      # That is recorded above as probe data; it is not this script's own result,
      # and leaving it in $LASTEXITCODE would fail an otherwise successful caller.
      $global:LASTEXITCODE = 0
    } catch {
      $report.certutil_csplist.error = [string]$_.Exception.Message
    }
  }
}

# Presence means usable, not merely registered. `NCryptOpenStorageProvider` is
# the only probe that distinguishes the two: on a host with no usable TPM the
# Platform KSP is still enumerated and still listed by certutil, but opening it
# fails with NTE_DEVICE_NOT_READY. Registration is therefore recorded separately
# and can never raise `present`.
if ($report.native_open.opened) {
  $report.present = $true
  $report.detection_method = 'ncrypt_open_storage_provider'
}
if ($report.native_enumeration.found) {
  $report.registered = $true
  $report.registration_method = 'ncrypt_enum_storage_providers'
} elseif ($report.certutil_csplist.matched) {
  $report.registered = $true
  $report.registration_method = 'certutil_csplist'
}

if ($OutputPath) {
  $json = $report | ConvertTo-Json -Depth 8
  $parent = Split-Path $OutputPath -Parent
  if ($parent) { New-Item -ItemType Directory -Force $parent | Out-Null }
  [IO.File]::WriteAllText($OutputPath, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

if ($AsJson) { return ($report | ConvertTo-Json -Depth 8) }
return $report
