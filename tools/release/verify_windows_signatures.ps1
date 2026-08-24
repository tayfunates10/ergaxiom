[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet('test', 'production')]
  [string]$Mode,

  [Parameter(Mandatory)]
  [string]$PolicyPath,

  [Parameter(Mandatory)]
  [string[]]$Artifact,

  [Parameter(Mandatory)]
  [string]$EvidenceOut
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$policyPathResolved = (Resolve-Path $PolicyPath).Path
$policy = Get-Content $policyPathResolved -Raw | ConvertFrom-Json -Depth 32
if (
  $policy.policy_id -ne 'ergaxiom.windows-production-release' -or
  $policy.signing.digest_algorithm -ne 'SHA256' -or
  $policy.signing.timestamp_protocol -ne 'RFC3161'
) {
  throw 'POLICY_REJECTED'
}

function Get-CertificateDerSha256 {
  param(
    [Parameter(Mandatory)]
    [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
  )

  return ([Convert]::ToHexString(
      [Security.Cryptography.SHA256]::HashData($Certificate.RawData)
    )).ToLowerInvariant()
}

function Test-CertificateChain {
  param(
    [Parameter(Mandatory)]
    [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

    [Parameter(Mandatory)]
    [bool]$Online
  )

  $certificateChain = [Security.Cryptography.X509Certificates.X509Chain]::new()
  try {
    $certificateChain.ChainPolicy.RevocationMode = if ($Online) {
      [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    } else {
      [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    }
    $certificateChain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
    $certificateChain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(20)
    return [bool]$certificateChain.Build($Certificate)
  } finally {
    $certificateChain.Dispose()
  }
}

function Get-SignToolPath {
  $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($command) {
    return $command.Source
  }

  $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
  if (-not (Test-Path $kitsRoot -PathType Container)) {
    return $null
  }

  return Get-ChildItem $kitsRoot -Directory |
    Sort-Object Name -Descending |
    ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
    Where-Object { Test-Path $_ -PathType Leaf } |
    Select-Object -First 1
}

function Test-SignToolSignature {
  param(
    [Parameter(Mandatory)]
    [string]$SignTool,

    [Parameter(Mandatory)]
    [string]$Path
  )

  try {
    $startProcessArgs = @{
      FilePath = $SignTool
      ArgumentList = @('verify', '/pa', '/all', '/v', $Path)
      Wait = $true
      PassThru = $true
      WindowStyle = 'Hidden'
    }
    $process = Start-Process @startProcessArgs
    return $process.ExitCode -eq 0
  } catch {
    return $false
  }
}

$policyHash = & python -c "import hashlib,json,sys;v=json.load(open(sys.argv[1],encoding='utf-8'));print(hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest())" $policyPathResolved
if ($LASTEXITCODE -ne 0) {
  throw 'POLICY_HASH_FAILED'
}

$signTool = Get-SignToolPath
$records = @()
$seen = @{}

foreach ($artifactPath in $Artifact) {
  $resolvedArtifact = (Resolve-Path $artifactPath).Path
  $name = [IO.Path]::GetFileName($resolvedArtifact)
  if ($seen.ContainsKey($name)) {
    throw 'DUPLICATE_ARTIFACT'
  }
  $seen[$name] = $true

  $signature = Get-AuthenticodeSignature $resolvedArtifact
  $signerCertificate = $signature.SignerCertificate
  $timestampCertificate = $signature.TimeStamperCertificate

  $eku = if ($signerCertificate) {
    @(
      $signerCertificate.Extensions |
        Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
        ForEach-Object {
          ([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$_).EnhancedKeyUsages |
            ForEach-Object { $_.Value }
        }
    )
  } else {
    @()
  }

  $records += [ordered]@{
    name = $name
    sha256 = (Get-FileHash $resolvedArtifact -Algorithm SHA256).Hash.ToLowerInvariant()
    authenticode_valid = ($signature.Status -eq [Management.Automation.SignatureStatus]::Valid)
    signtool_verify_ok = if ($signTool) {
      Test-SignToolSignature -SignTool $signTool -Path $resolvedArtifact
    } else {
      $false
    }
    signer_subject = if ($signerCertificate) { $signerCertificate.Subject } else { $null }
    signer_certificate_sha256 = if ($signerCertificate) {
      Get-CertificateDerSha256 -Certificate $signerCertificate
    } else {
      $null
    }
    code_signing_eku_present = ([string]$policy.signing.code_signing_eku_oid -in $eku)
    certificate_chain_valid = if ($signerCertificate) {
      Test-CertificateChain -Certificate $signerCertificate -Online ($Mode -eq 'production')
    } else {
      $false
    }
    revocation_checked_online = ($Mode -eq 'production')
    timestamp_present = ($null -ne $timestampCertificate)
    timestamp_chain_valid = if ($timestampCertificate) {
      Test-CertificateChain -Certificate $timestampCertificate -Online $true
    } else {
      $false
    }
    timestamp_url = [string]$policy.signing.timestamp_url
    self_signed = if ($signerCertificate) {
      $signerCertificate.Subject -eq $signerCertificate.Issuer
    } else {
      $false
    }
  }
}

$evidence = [ordered]@{
  schema_version = '0.1.0'
  mode = $Mode
  test_identity = ($Mode -ne 'production')
  policy_sha256 = $policyHash.Trim()
  signtool_available = ($null -ne $signTool)
  artifacts = @($records | Sort-Object name)
}

$outputPath = [IO.Path]::GetFullPath($EvidenceOut)
New-Item -ItemType Directory -Force (Split-Path $outputPath) | Out-Null
$evidence | ConvertTo-Json -Depth 8 | Set-Content $outputPath -Encoding utf8NoBOM
