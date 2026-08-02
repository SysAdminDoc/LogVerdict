#requires -Version 5.1

<#!
.SYNOPSIS
Write hash-verifiable SPDX and build-provenance records for release assets.

.DESCRIPTION
The records are deliberately portable and unsigned. Each release executable gets
an SPDX 2.3 document and a provenance record containing the source revision,
source-tree hash, build runtime, and exact content hashes for the pinned build and
test modules. The companion verifier can validate the records offline.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$')]
    [string]$Version,

    [string]$AssetDirectory,

    [string]$OutputDirectory,

    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string]$Repository = 'SysAdminDoc/LogVerdict',

    [string]$SourceDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# The mapped repository is intentionally outside the local Windows path namespace.
# Ignore the host's malformed global safe.directory entry and explicitly allow only
# the repository passed to git below; this keeps PowerShell 5.1 from promoting git's
# warning stream to a terminating error.
$env:GIT_CONFIG_GLOBAL = 'NUL'

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $SourceDirectory) { $SourceDirectory = $repoRoot }
if (-not $AssetDirectory) { $AssetDirectory = Join-Path $repoRoot 'dist' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repoRoot 'Packaging/supply-chain' }
if (-not $Version) {
    $Version = (& (Join-Path $repoRoot 'Tools\Get-LogVerdictVersion.ps1')).Trim()
}

function Get-LVFileSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::OpenRead($Path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

function Get-LVTextSha256 {
    param([Parameter(Mandatory)][string]$Text)

    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Write-LVJsonFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value,
        [int]$Depth = 20
    )

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }
    $temporary = $Path + '.tmp-' + [Guid]::NewGuid().ToString('N')
    try {
        $json = $Value | ConvertTo-Json -Depth $Depth
        [IO.File]::WriteAllText($temporary, ($json + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Get-LVRelativePath {
    param(
        [Parameter(Mandatory)][string]$BasePath,
        [Parameter(Mandatory)][string]$Path
    )

    $baseUri = New-Object Uri (([IO.Path]::GetFullPath($BasePath).TrimEnd('\') + '\'))
    $pathUri = New-Object Uri ([IO.Path]::GetFullPath($Path))
    return [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($pathUri).ToString()).Replace('\', '/')
}

function Get-LVSourceManifest {
    param([Parameter(Mandatory)][string]$BasePath)

    $trackedPaths = @(& git -c safe.directory='*' -C $BasePath ls-files 2>$null | Where-Object { $_ -notmatch '^(?i)(?:warning|fatal):' })
    if ($LASTEXITCODE -ne 0 -or $trackedPaths.Count -eq 0) { throw 'Unable to enumerate tracked source files with git.' }
    $files = @($trackedPaths | Where-Object {
        $_ -notmatch '^(?i)(?:dist|obj)/' -and $_ -notmatch '^(?i)\.git/'
    } | ForEach-Object { Get-Item -LiteralPath (Join-Path $BasePath ($_ -replace '/', '\')) } |
        Sort-Object { Get-LVRelativePath -BasePath $BasePath -Path $_.FullName })
    $records = @()
    foreach ($file in $files) {
        $records += [ordered]@{
            path = Get-LVRelativePath -BasePath $BasePath -Path $file.FullName
            sha256 = Get-LVFileSha256 -Path $file.FullName
            bytes = [int64]$file.Length
        }
    }
    $canonical = (($records | ForEach-Object { '{0}|{1}|{2}' -f $_.path, $_.sha256, $_.bytes }) -join "`n") + "`n"
    return [ordered]@{
        schemaVersion = 1
        sourceDirectory = 'repository checkout'
        files = $records
        sourceTreeSha256 = Get-LVTextSha256 -Text $canonical
    }
}

function Get-LVModuleManifest {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ExpectedVersion
    )

    $module = @(Get-Module -ListAvailable -Name $Name | Where-Object { $_.Version.ToString() -eq $ExpectedVersion } | Select-Object -First 1)
    if ($module.Count -ne 1) {
        throw ("Pinned dependency {0} v{1} is not installed." -f $Name, $ExpectedVersion)
    }
    $base = $module[0].ModuleBase
    $files = @(Get-ChildItem -LiteralPath $base -File -Recurse | Sort-Object { Get-LVRelativePath -BasePath $base -Path $_.FullName })
    $records = @()
    foreach ($file in $files) {
        $records += [ordered]@{
            path = Get-LVRelativePath -BasePath $base -Path $file.FullName
            sha256 = Get-LVFileSha256 -Path $file.FullName
            bytes = [int64]$file.Length
        }
    }
    $canonical = (($records | ForEach-Object { '{0}|{1}|{2}' -f $_.path, $_.sha256, $_.bytes }) -join "`n") + "`n"
    return [ordered]@{
        name = $Name
        version = $ExpectedVersion
        source = 'PowerShell Gallery'
        hashKind = 'module-file-manifest'
        contentSha256 = Get-LVTextSha256 -Text $canonical
        fileCount = $records.Count
        files = $records
    }
}

function Invoke-LVGit {
    param([Parameter(Mandatory)][string[]]$ArgumentList)

    $output = @(& git -c safe.directory='*' -C $SourceDirectory @ArgumentList 2>$null | Where-Object { $_ -notmatch '^(?i)(?:warning|fatal):' })
    if ($LASTEXITCODE -ne 0) {
        throw ("git {0} failed: {1}" -f ($ArgumentList -join ' '), ($output -join ' '))
    }
    return ($output -join "`n").Trim()
}

$assetNames = @('LogVerdict.exe', 'LogVerdict-GUI.exe')
foreach ($name in $assetNames) {
    $path = Join-Path $AssetDirectory $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw ("Release asset not found: {0}" -f $path)
    }
}

$sourceManifest = Get-LVSourceManifest -BasePath $SourceDirectory
$sourceManifestPath = Join-Path $OutputDirectory 'source-manifest.json'
Write-LVJsonFile -Path $sourceManifestPath -Value $sourceManifest

$dependencySpecs = @(
    [ordered]@{ name = 'Pester'; version = '5.9.0'; purpose = 'test' }
    [ordered]@{ name = 'PSScriptAnalyzer'; version = '1.25.0'; purpose = 'quality-gate' }
    [ordered]@{ name = 'ps2exe'; version = '1.0.18'; purpose = 'executable-builder' }
)
$dependencies = @()
foreach ($spec in $dependencySpecs) {
    $dependency = Get-LVModuleManifest -Name $spec.name -ExpectedVersion $spec.version
    $dependency.purpose = $spec.purpose
    $dependencies += $dependency
}
$dependencyManifest = [ordered]@{
    schemaVersion = 1
    dependencies = $dependencies
}
$dependencyManifestPath = Join-Path $OutputDirectory 'dependency-manifest.json'
Write-LVJsonFile -Path $dependencyManifestPath -Value $dependencyManifest -Depth 30

$revision = Invoke-LVGit -ArgumentList @('rev-parse', 'HEAD')
$status = Invoke-LVGit -ArgumentList @('status', '--porcelain', '--untracked-files=no')
$sourceDirty = -not [string]::IsNullOrWhiteSpace($status)
$createdAt = [DateTime]::UtcNow.ToString('o')
$runtimeOs = ''
if ($PSVersionTable.ContainsKey('OS')) { $runtimeOs = [string]$PSVersionTable.OS }
$runtimeArchitecture = [string]$env:PROCESSOR_ARCHITECTURE
if ($PSVersionTable.ContainsKey('Platform')) { $runtimeArchitecture = [string]$PSVersionTable.Platform }
$runtime = [ordered]@{
    edition = [string]$PSVersionTable.PSEdition
    version = $PSVersionTable.PSVersion.ToString()
    os = $runtimeOs
    architecture = $runtimeArchitecture
}

$sourceManifestHash = Get-LVFileSha256 -Path $sourceManifestPath
$dependencyManifestHash = Get-LVFileSha256 -Path $dependencyManifestPath
$assetRecords = @()
foreach ($name in $assetNames) {
    $assetPath = Join-Path $AssetDirectory $name
    $assetHash = Get-LVFileSha256 -Path $assetPath
    $safeName = [IO.Path]::GetFileNameWithoutExtension($name)
    $spdxName = $safeName + '.spdx.json'
    $provenanceName = $safeName + '.provenance.json'
    $spdxPath = Join-Path $OutputDirectory $spdxName
    $provenancePath = Join-Path $OutputDirectory $provenanceName
    $namespace = 'https://github.com/{0}/releases/download/v{1}/{2}' -f $Repository, $Version, $spdxName

    $spdx = [ordered]@{
        spdxVersion = 'SPDX-2.3'
        dataLicense = 'CC0-1.0'
        SPDXID = 'SPDXRef-DOCUMENT'
        name = 'LogVerdict ' + $name
        documentNamespace = $namespace
        creationInfo = [ordered]@{
            created = $createdAt
            creators = @('Tool: LogVerdict supply-chain metadata 1')
            licenseListVersion = '3.23'
        }
        documentDescribes = @('SPDXRef-Package-LogVerdict')
        packages = @([ordered]@{
            SPDXID = 'SPDXRef-Package-LogVerdict'
            name = 'LogVerdict'
            versionInfo = $Version
            downloadLocation = 'NOASSERTION'
            filesAnalyzed = $true
            licenseConcluded = 'NOASSERTION'
            licenseDeclared = 'NOASSERTION'
            copyrightText = 'NOASSERTION'
            hasFiles = @('SPDXRef-File-' + $safeName)
        })
        files = @([ordered]@{
            SPDXID = 'SPDXRef-File-' + $safeName
            fileName = $name
            checksums = @([ordered]@{ algorithm = 'SHA256'; checksum = $assetHash })
            licenseConcluded = 'NOASSERTION'
            copyrightText = 'NOASSERTION'
        })
        relationships = @([ordered]@{
            spdxElementId = 'SPDXRef-Package-LogVerdict'
            relationshipType = 'CONTAINS'
            relatedSpdxElement = 'SPDXRef-File-' + $safeName
        })
        comment = 'Build-time dependency hashes and source provenance are attached in the companion provenance record; this document does not claim test tools are runtime dependencies.'
    }
    Write-LVJsonFile -Path $spdxPath -Value $spdx -Depth 20

    $provenance = [ordered]@{
        schemaVersion = 1
        name = 'LogVerdict.BuildProvenance'
        predicateType = 'https://slsa.dev/provenance/v1'
        subject = @([ordered]@{
            name = $name
            digest = [ordered]@{ sha256 = $assetHash }
        })
        source = [ordered]@{
            repository = 'https://github.com/' + $Repository
            revision = $revision
            version = $Version
            dirty = $sourceDirty
            manifest = 'source-manifest.json'
            manifestSha256 = $sourceManifestHash
            sourceTreeSha256 = $sourceManifest.sourceTreeSha256
        }
        build = [ordered]@{
            builder = 'Tools/Build-LogVerdictExe.ps1'
            workflow = '.github/workflows/ci.yml:package'
            runtime = $runtime
            startedAt = $createdAt
            finishedAt = [DateTime]::UtcNow.ToString('o')
            unsigned = $true
        }
        dependencies = $dependencies
        dependencyManifest = 'dependency-manifest.json'
        dependencyManifestSha256 = $dependencyManifestHash
        sbom = [ordered]@{
            path = $spdxName
            sha256 = Get-LVFileSha256 -Path $spdxPath
        }
        verification = [ordered]@{
            artifactSha256 = $assetHash
            signed = $false
            verifier = 'Tools/Test-LogVerdictSupplyChain.ps1'
        }
    }
    Write-LVJsonFile -Path $provenancePath -Value $provenance -Depth 30
    $assetRecords += [ordered]@{
        name = $name
        sha256 = $assetHash
        sbom = $spdxName
        sbomSha256 = Get-LVFileSha256 -Path $spdxPath
        provenance = $provenanceName
        provenanceSha256 = Get-LVFileSha256 -Path $provenancePath
    }
}

$index = [ordered]@{
    schemaVersion = 1
    name = 'LogVerdict.ReleaseSupplyChain'
    version = $Version
    created = $createdAt
    sourceRevision = $revision
    sourceDirty = $sourceDirty
    sourceManifest = 'source-manifest.json'
    sourceManifestSha256 = $sourceManifestHash
    dependencyManifest = 'dependency-manifest.json'
    dependencyManifestSha256 = $dependencyManifestHash
    assets = $assetRecords
}
$indexPath = Join-Path $OutputDirectory 'logverdict-supply-chain.json'
Write-LVJsonFile -Path $indexPath -Value $index -Depth 30

[pscustomobject]@{
    Version = $Version
    OutputDirectory = $OutputDirectory
    SourceRevision = $revision
    SourceTreeSha256 = $sourceManifest.sourceTreeSha256
    AssetCount = $assetRecords.Count
    Index = $indexPath
}
