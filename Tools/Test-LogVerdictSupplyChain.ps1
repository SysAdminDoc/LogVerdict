#requires -Version 5.1

<#!
.SYNOPSIS
Verify LogVerdict release SPDX, CycloneDX, and provenance records without network access.
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

function Assert-LVHasProperty {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Message
    )

    if ($null -eq $Object -or -not $Object.PSObject.Properties[$Name]) {
        throw ("{0}: required property '{1}' is missing." -f $Message, $Name)
    }
}

function Test-LVCycloneDxDocument {
    param(
        [Parameter(Mandatory)]$Document,
        [Parameter(Mandatory)][string]$AssetName,
        [Parameter(Mandatory)][string]$AssetHash,
        [Parameter(Mandatory)][string]$Version
    )

    Assert-LVHasProperty -Object $Document -Name '$schema' -Message ("CycloneDX {0}" -f $AssetName)
    Assert-LVEqual -Actual $Document.'$schema' -Expected 'https://cyclonedx.org/schema/bom-1.7.schema.json' -Message ("CycloneDX schema {0}" -f $AssetName)
    Assert-LVEqual -Actual $Document.bomFormat -Expected 'CycloneDX' -Message ("CycloneDX format {0}" -f $AssetName)
    Assert-LVEqual -Actual $Document.specVersion -Expected '1.7' -Message ("CycloneDX version {0}" -f $AssetName)
    if ([string]$Document.serialNumber -notmatch '^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        throw ("CycloneDX serial number is invalid for {0}." -f $AssetName)
    }
    if ([int]$Document.version -lt 1) { throw ("CycloneDX document version is invalid for {0}." -f $AssetName) }
    Assert-LVHasProperty -Object $Document -Name 'metadata' -Message ("CycloneDX {0}" -f $AssetName)
    Assert-LVHasProperty -Object $Document.metadata -Name 'timestamp' -Message ("CycloneDX metadata {0}" -f $AssetName)
    $components = @($Document.components | Where-Object { $_ })
    if ($components.Count -ne 1) { throw ("CycloneDX must describe exactly one component for {0}." -f $AssetName) }
    $component = $components[0]
    Assert-LVEqual -Actual $component.type -Expected 'application' -Message ("CycloneDX component type {0}" -f $AssetName)
    Assert-LVEqual -Actual $component.name -Expected $AssetName -Message ("CycloneDX component name {0}" -f $AssetName)
    Assert-LVEqual -Actual $component.version -Expected $Version -Message ("CycloneDX component version {0}" -f $AssetName)
    $hashes = @($component.hashes | Where-Object { $_.alg -eq 'SHA-256' })
    if ($hashes.Count -ne 1) { throw ("CycloneDX must contain one SHA-256 hash for {0}." -f $AssetName) }
    Assert-LVEqual -Actual $hashes[0].content -Expected $AssetHash -Message ("CycloneDX asset hash {0}" -f $AssetName)
    $properties = @($component.properties | Where-Object { $_ })
    if (@($properties | Where-Object { $_.name -eq 'logverdict:provenance-signed' -and $_.value -eq 'false' }).Count -ne 1) {
        throw ("CycloneDX must label the provenance unsigned for {0}." -f $AssetName)
    }
}

function Get-LVRelativePath {
    param([Parameter(Mandatory)][string]$BasePath, [Parameter(Mandatory)][string]$Path)
    $baseUri = New-Object Uri (([IO.Path]::GetFullPath($BasePath).TrimEnd('\') + '\'))
    $pathUri = New-Object Uri ([IO.Path]::GetFullPath($Path))
    return [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($pathUri).ToString()).Replace('\', '/')
}

function Get-LVTrackedSourcePath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$BasePath)

    $output = @(& git -c safe.directory='*' -C $BasePath ls-files 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'Unable to enumerate tracked source files with git.' }
    return @($output | Where-Object {
            $_ -and $_ -notmatch '^(?i)(?:dist|obj)/' -and $_ -notmatch '^(?i)\.git/'
        } | ForEach-Object { ([string]$_).Replace('\', '/') } | Sort-Object -Unique)
}

function Invoke-LVGitText {
    param([Parameter(Mandatory)][string]$BasePath, [Parameter(Mandatory)][string[]]$ArgumentList)

    $output = @(& git -c safe.directory='*' -C $BasePath @ArgumentList 2>$null)
    if ($LASTEXITCODE -ne 0) { throw ("git {0} failed." -f ($ArgumentList -join ' ')) }
    return (($output | Where-Object { $_ }) -join "`n").Trim()
}

function Get-LVManifestTreeHash {
    param([Parameter(Mandatory)]$Manifest, [Parameter(Mandatory)][string]$BasePath)

    $manifestPaths = @($Manifest.files | ForEach-Object { ([string]$_.path).Replace('\', '/') })
    if ($manifestPaths.Count -ne @($manifestPaths | Sort-Object -Unique).Count) { throw 'Source manifest contains duplicate file paths.' }
    $trackedPaths = @(Get-LVTrackedSourcePath -BasePath $BasePath)
    $missing = @($trackedPaths | Where-Object { $manifestPaths -notcontains $_ })
    $unexpected = @($manifestPaths | Where-Object { $trackedPaths -notcontains $_ })
    if ($missing.Count -gt 0) { throw ("Source manifest is missing tracked file(s): {0}" -f ($missing -join ', ')) }
    if ($unexpected.Count -gt 0) { throw ("Source manifest contains file(s) that are not tracked: {0}" -f ($unexpected -join ', ')) }
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
Assert-LVHasProperty -Object $index -Name 'sourceDirty' -Message 'Supply-chain index'
Assert-LVHasProperty -Object $index -Name 'sourceRevision' -Message 'Supply-chain index'
Assert-LVEqual -Actual ([bool]$index.sourceDirty) -Expected $false -Message 'Source checkout dirty state'
$headRevision = Invoke-LVGitText -BasePath $SourceDirectory -ArgumentList @('rev-parse', 'HEAD')
Assert-LVEqual -Actual $index.sourceRevision -Expected $headRevision -Message 'Source revision'
$assets = @($index.assets)
if ($assets.Count -ne 2) { throw ("Supply-chain index must contain two assets; found {0}." -f $assets.Count) }

$sourceManifestPath = Join-Path $MetadataDirectory ([string]$index.sourceManifest)
Assert-LVEqual -Actual (Get-LVFileSha256 -Path $sourceManifestPath) -Expected $index.sourceManifestSha256 -Message 'Source manifest hash'
$sourceManifest = Read-LVJson -Path $sourceManifestPath
Assert-LVEqual -Actual $sourceManifest.schemaVersion -Expected 1 -Message 'Source manifest schema version'
Get-LVManifestTreeHash -Manifest $sourceManifest -BasePath $SourceDirectory | Out-Null

$pinnedDependencyPath = Join-Path $SourceDirectory 'Data/build-dependencies.json'
$pinnedDependencies = Read-LVJson -Path $pinnedDependencyPath
Assert-LVEqual -Actual $pinnedDependencies.schemaVersion -Expected 1 -Message 'Pinned dependency schema version'
Assert-LVEqual -Actual $pinnedDependencies.name -Expected 'LogVerdict.BuildDependencies' -Message 'Pinned dependency name'

$dependencyManifestPath = Join-Path $MetadataDirectory ([string]$index.dependencyManifest)
Assert-LVEqual -Actual (Get-LVFileSha256 -Path $dependencyManifestPath) -Expected $index.dependencyManifestSha256 -Message 'Dependency manifest hash'
$dependencyManifest = Read-LVJson -Path $dependencyManifestPath
Assert-LVEqual -Actual $dependencyManifest.schemaVersion -Expected 1 -Message 'Dependency manifest schema version'
$pinnedDependencySpecs = @($pinnedDependencies.dependencies | Where-Object { $_ })
if ($pinnedDependencySpecs.Count -ne @($dependencyManifest.dependencies).Count) {
    throw ("Dependency manifest contains {0} entries, but the tracked pin file contains {1}." -f
        @($dependencyManifest.dependencies).Count, $pinnedDependencySpecs.Count)
}
foreach ($dependency in @($dependencyManifest.dependencies)) {
    if ([string]$dependency.contentSha256 -notmatch '^[0-9a-f]{64}$') { throw ("Dependency {0} has no content hash." -f $dependency.name) }
    Get-LVDependencyTreeHash -Dependency $dependency | Out-Null
    $pin = @($pinnedDependencies.dependencies | Where-Object { $_.name -eq $dependency.name -and $_.version -eq $dependency.version })
    if ($pin.Count -ne 1) { throw ("Dependency {0} v{1} is not present exactly once in the tracked pin file." -f $dependency.name, $dependency.version) }
    Assert-LVEqual -Actual $dependency.source -Expected $pin[0].source -Message ("Dependency source {0}" -f $dependency.name)
    Assert-LVEqual -Actual $dependency.hashKind -Expected $pin[0].hashKind -Message ("Dependency hash kind {0}" -f $dependency.name)
    Assert-LVEqual -Actual $dependency.contentSha256 -Expected $pin[0].contentSha256 -Message ("Pinned dependency hash {0}" -f $dependency.name)
    Assert-LVEqual -Actual ([int]$dependency.fileCount) -Expected ([int]$pin[0].fileCount) -Message ("Pinned dependency file count {0}" -f $dependency.name)
    Assert-LVEqual -Actual ([int64]$dependency.totalBytes) -Expected ([int64]$pin[0].totalBytes) -Message ("Pinned dependency byte count {0}" -f $dependency.name)
}

foreach ($asset in $assets) {
    if ([string]$asset.name -notin @('LogVerdict.exe', 'LogVerdict-GUI.exe')) { throw ("Unexpected release asset '{0}'." -f $asset.name) }
    if ([string]$asset.sha256 -notmatch '^[0-9a-f]{64}$') { throw ("Invalid release hash for {0}." -f $asset.name) }
    $spdxPath = Join-Path $MetadataDirectory ([string]$asset.sbom)
    $cycloneDxPath = Join-Path $MetadataDirectory ([string]$asset.cyclonedx)
    $provenancePath = Join-Path $MetadataDirectory ([string]$asset.provenance)
    Assert-LVEqual -Actual (Get-LVFileSha256 -Path $spdxPath) -Expected $asset.sbomSha256 -Message ("SBOM hash {0}" -f $asset.name)
    Assert-LVEqual -Actual (Get-LVFileSha256 -Path $cycloneDxPath) -Expected $asset.cyclonedxSha256 -Message ("CycloneDX hash {0}" -f $asset.name)
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

    $cycloneDx = Read-LVJson -Path $cycloneDxPath
    Test-LVCycloneDxDocument -Document $cycloneDx -AssetName ([string]$asset.name) -AssetHash ([string]$asset.sha256) -Version $Version

    $provenance = Read-LVJson -Path $provenancePath
    Assert-LVEqual -Actual $provenance.schemaVersion -Expected 1 -Message ("Provenance schema version {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.name -Expected 'LogVerdict.BuildProvenance' -Message ("Provenance name {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.subject[0].name -Expected $asset.name -Message ("Provenance subject {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.subject[0].digest.sha256 -Expected $asset.sha256 -Message ("Provenance asset hash {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.verification.artifactSha256 -Expected $asset.sha256 -Message ("Provenance verification hash {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.source.version -Expected $Version -Message ("Provenance version {0}" -f $asset.name)
    Assert-LVHasProperty -Object $provenance.source -Name 'revision' -Message ("Provenance source {0}" -f $asset.name)
    Assert-LVHasProperty -Object $provenance.source -Name 'dirty' -Message ("Provenance source {0}" -f $asset.name)
    Assert-LVHasProperty -Object $provenance.source -Name 'sourceTreeSha256' -Message ("Provenance source {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.source.revision -Expected $index.sourceRevision -Message ("Provenance source revision {0}" -f $asset.name)
    Assert-LVEqual -Actual ([bool]$provenance.source.dirty) -Expected $false -Message ("Provenance source dirty state {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.source.sourceTreeSha256 -Expected $sourceManifest.sourceTreeSha256 -Message ("Provenance source tree {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.source.manifestSha256 -Expected $index.sourceManifestSha256 -Message ("Provenance source manifest {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.dependencyManifestSha256 -Expected $index.dependencyManifestSha256 -Message ("Provenance dependency manifest {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.sbom.sha256 -Expected $asset.sbomSha256 -Message ("Provenance SBOM hash {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.cyclonedx.path -Expected $asset.cyclonedx -Message ("Provenance CycloneDX path {0}" -f $asset.name)
    Assert-LVEqual -Actual $provenance.cyclonedx.sha256 -Expected $asset.cyclonedxSha256 -Message ("Provenance CycloneDX hash {0}" -f $asset.name)
    if ($provenance.verification.signed -ne $false -or $provenance.build.unsigned -ne $true) { throw ("Unsigned verification contract failed for {0}." -f $asset.name) }
}

Write-Output ("Supply-chain verification passed for LogVerdict v{0}: {1} assets." -f $Version, $assets.Count)
