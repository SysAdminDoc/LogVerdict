#requires -Version 5.1

<#!
.SYNOPSIS
Verify LogVerdict release SBOM and provenance records without network access.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$')]
    [string]$Version,

    [Parameter(Mandatory)][string]$MetadataDirectory,

    [string]$AssetDirectory,

    [string]$SourceDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $SourceDirectory) { $SourceDirectory = $repoRoot }
if (-not $Version) { $Version = (& (Join-Path $repoRoot 'Tools\Get-LogVerdictVersion.ps1')).Trim() }

function Get-LVFileSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::OpenRead($Path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose(); $stream.Dispose() }
}

function Get-LVTextSha256 {
    param([Parameter(Mandatory)][string]$Text)

    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}

function Read-LVJson {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw ("Metadata file not found: {0}" -f $Path) }
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Assert-LVEqual {
    param(
        [Parameter(Mandatory)]$Actual,
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)][string]$Message
    )
    if ([string]$Actual -cne [string]$Expected) { throw ("{0}: expected '{1}', got '{2}'." -f $Message, $Expected, $Actual) }
}

function Get-LVRelativePath {
    param([Parameter(Mandatory)][string]$BasePath, [Parameter(Mandatory)][string]$Path)
    $baseUri = New-Object Uri (([IO.Path]::GetFullPath($BasePath).TrimEnd('\') + '\'))
    $pathUri = New-Object Uri ([IO.Path]::GetFullPath($Path))
    return [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($pathUri).ToString()).Replace('\', '/')
}

function Get-LVManifestTreeHash {
    param([Parameter(Mandatory)]$Manifest, [Parameter(Mandatory)][string]$BasePath)

    foreach ($record in @($Manifest.files)) {
        $path = Join-Path $BasePath ($record.path -replace '/', '\')
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ("Source file missing: {0}" -f $record.path) }
        Assert-LVEqual -Actual (Get-LVFileSha256 -Path $path) -Expected $record.sha256 -Message ("Source hash {0}" -f $record.path)
        Assert-LVEqual -Actual ([int64](Get-Item -LiteralPath $path).Length) -Expected ([int64]$record.bytes) -Message ("Source size {0}" -f $record.path)
    }
    $canonical = ((@($Manifest.files) | ForEach-Object { '{0}|{1}|{2}' -f $_.path, $_.sha256, $_.bytes }) -join "`n") + "`n"
    $hash = Get-LVTextSha256 -Text $canonical
    Assert-LVEqual -Actual $hash -Expected $Manifest.sourceTreeSha256 -Message 'Source tree hash'
    return $hash
}

function Get-LVDependencyTreeHash {
    param([Parameter(Mandatory)]$Dependency)

    $canonical = ((@($Dependency.files) | ForEach-Object { '{0}|{1}|{2}' -f $_.path, $_.sha256, $_.bytes }) -join "`n") + "`n"
    $hash = Get-LVTextSha256 -Text $canonical
    Assert-LVEqual -Actual $hash -Expected $Dependency.contentSha256 -Message ("Dependency manifest hash {0}" -f $Dependency.name)
    return $hash
}

$indexPath = Join-Path $MetadataDirectory 'logverdict-supply-chain.json'
$index = Read-LVJson -Path $indexPath
Assert-LVEqual -Actual $index.schemaVersion -Expected 1 -Message 'Supply-chain schema version'
Assert-LVEqual -Actual $index.name -Expected 'LogVerdict.ReleaseSupplyChain' -Message 'Supply-chain name'
Assert-LVEqual -Actual $index.version -Expected $Version -Message 'Supply-chain version'
$assets = @($index.assets)
if ($assets.Count -ne 2) { throw ("Supply-chain index must contain two assets; found {0}." -f $assets.Count) }

$sourceManifestPath = Join-Path $MetadataDirectory ([string]$index.sourceManifest)
Assert-LVEqual -Actual (Get-LVFileSha256 -Path $sourceManifestPath) -Expected $index.sourceManifestSha256 -Message 'Source manifest hash'
$sourceManifest = Read-LVJson -Path $sourceManifestPath
Assert-LVEqual -Actual $sourceManifest.schemaVersion -Expected 1 -Message 'Source manifest schema version'
Get-LVManifestTreeHash -Manifest $sourceManifest -BasePath $SourceDirectory | Out-Null

$dependencyManifestPath = Join-Path $MetadataDirectory ([string]$index.dependencyManifest)
Assert-LVEqual -Actual (Get-LVFileSha256 -Path $dependencyManifestPath) -Expected $index.dependencyManifestSha256 -Message 'Dependency manifest hash'
$dependencyManifest = Read-LVJson -Path $dependencyManifestPath
Assert-LVEqual -Actual $dependencyManifest.schemaVersion -Expected 1 -Message 'Dependency manifest schema version'
foreach ($dependency in @($dependencyManifest.dependencies)) {
    if ([string]$dependency.contentSha256 -notmatch '^[0-9a-f]{64}$') { throw ("Dependency {0} has no content hash." -f $dependency.name) }
    Get-LVDependencyTreeHash -Dependency $dependency | Out-Null
}

foreach ($asset in $assets) {
    if ([string]$asset.name -notin @('LogVerdict.exe', 'LogVerdict-GUI.exe')) { throw ("Unexpected release asset '{0}'." -f $asset.name) }
    if ([string]$asset.sha256 -notmatch '^[0-9a-f]{64}$') { throw ("Invalid release hash for {0}." -f $asset.name) }
    $spdxPath = Join-Path $MetadataDirectory ([string]$asset.sbom)
    $provenancePath = Join-Path $MetadataDirectory ([string]$asset.provenance)
    Assert-LVEqual -Actual (Get-LVFileSha256 -Path $spdxPath) -Expected $asset.sbomSha256 -Message ("SBOM hash {0}" -f $asset.name)
    Assert-LVEqual -Actual (Get-LVFileSha256 -Path $provenancePath) -Expected $asset.provenanceSha256 -Message ("Provenance hash {0}" -f $asset.name)

    if ($AssetDirectory) {
        $assetPath = Join-Path $AssetDirectory $asset.name
        if (-not (Test-Path -LiteralPath $assetPath -PathType Leaf)) { throw ("Release asset not found: {0}" -f $assetPath) }
        Assert-LVEqual -Actual (Get-LVFileSha256 -Path $assetPath) -Expected $asset.sha256 -Message ("Release hash {0}" -f $asset.name)
    }

    $spdx = Read-LVJson -Path $spdxPath
    Assert-LVEqual -Actual $spdx.spdxVersion -Expected 'SPDX-2.3' -Message ("SPDX version {0}" -f $asset.name)
    Assert-LVEqual -Actual $spdx.dataLicense -Expected 'CC0-1.0' -Message ("SPDX data license {0}" -f $asset.name)
    $spdxFile = @($spdx.files | Where-Object { $_.fileName -eq $asset.name })
    if ($spdxFile.Count -ne 1) { throw ("SPDX must describe exactly one {0} file." -f $asset.name) }
    $checksum = @($spdxFile[0].checksums | Where-Object { $_.algorithm -eq 'SHA256' })
    if ($checksum.Count -ne 1) { throw ("SPDX is missing one SHA-256 checksum for {0}." -f $asset.name) }
    Assert-LVEqual -Actual $checksum[0].checksum -Expected $asset.sha256 -Message ("SPDX asset hash {0}" -f $asset.name)

    $provenance = Read-LVJson -Path $provenancePath
    Assert-LVEqual -Actual $provenance.schemaVersion -Expected 1 -Message ("Provenance schema version {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.name -Expected 'LogVerdict.BuildProvenance' -Message ("Provenance name {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.subject[0].name -Expected $asset.name -Message ("Provenance subject {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.subject[0].digest.sha256 -Expected $asset.sha256 -Message ("Provenance asset hash {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.verification.artifactSha256 -Expected $asset.sha256 -Message ("Provenance verification hash {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.source.version -Expected $Version -Message ("Provenance version {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.source.manifestSha256 -Expected $index.sourceManifestSha256 -Message ("Provenance source manifest {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.dependencyManifestSha256 -Expected $index.dependencyManifestSha256 -Message ("Provenance dependency manifest {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.sbom.sha256 -Expected $asset.sbomSha256 -Message ("Provenance SBOM hash {0}" -f $asset.name)
    if ($provenance.verification.signed -ne $false -or $provenance.build.unsigned -ne $true) { throw ("Unsigned verification contract failed for {0}." -f $asset.name) }
}

Write-Output ("Supply-chain verification passed for LogVerdict v{0}: {1} assets." -f $Version, $assets.Count)
