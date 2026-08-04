#requires -Version 5.1

<#!
.SYNOPSIS
Write hash-verifiable SPDX and build-provenance records for release assets.

.DESCRIPTION
The records are deliberately portable and unsigned. Each release asset gets an
SPDX 2.3 document, a CycloneDX 1.7 document, and a provenance record containing
the source revision, source-tree hash, build runtime, and exact content hashes for
the pinned build and test modules. The companion verifier can validate the records
offline.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$')]
    [string]$Version,

    [string]$AssetDirectory,

    [string]$OutputDirectory,

    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string]$Repository = 'SysAdminDoc/LogVerdict',

    [string]$SourceDirectory,

    [string]$ModuleZipPath,

    [switch]$RequireModuleZip
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
        [Parameter(Mandatory)][string]$ExpectedVersion,
        [Parameter(Mandatory)][ValidatePattern('^(?i:[0-9a-f]{64})$')][string]$ExpectedContentSha256,
        [Parameter(Mandatory)][int]$ExpectedFileCount,
        [Parameter(Mandatory)][int64]$ExpectedTotalBytes
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
    $contentSha256 = Get-LVTextSha256 -Text $canonical
    if ($contentSha256 -ine $ExpectedContentSha256) {
        throw ("Pinned dependency {0} v{1} content hash mismatch. Expected {2}, got {3}." -f $Name, $ExpectedVersion, $ExpectedContentSha256, $contentSha256)
    }
    if ($records.Count -ne $ExpectedFileCount) {
        throw ("Pinned dependency {0} v{1} file count mismatch. Expected {2}, got {3}." -f $Name, $ExpectedVersion, $ExpectedFileCount, $records.Count)
    }
    $totalBytes = [int64]0
    foreach ($record in $records) {
        $totalBytes += [int64]$record['bytes']
    }
    if ($totalBytes -ne $ExpectedTotalBytes) {
        throw ("Pinned dependency {0} v{1} byte count mismatch. Expected {2}, got {3}." -f $Name, $ExpectedVersion, $ExpectedTotalBytes, $totalBytes)
    }
    return [ordered]@{
        name = $Name
        version = $ExpectedVersion
        source = 'PowerShell Gallery'
        hashKind = 'module-file-manifest'
        contentSha256 = $contentSha256
        fileCount = $records.Count
        totalBytes = $totalBytes
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

$moduleZipName = 'LogVerdict-Module-v{0}.zip' -f $Version
$moduleZipAssetPath = $null
if ($ModuleZipPath) {
    $ModuleZipPath = [IO.Path]::GetFullPath($ModuleZipPath)
    if (-not (Test-Path -LiteralPath $ModuleZipPath -PathType Leaf)) {
        throw ("Module ZIP release asset not found: {0}" -f $ModuleZipPath)
    }
    if ([IO.Path]::GetFileName($ModuleZipPath) -cne $moduleZipName) {
        throw ("Module ZIP must be named '{0}'." -f $moduleZipName)
    }
    $moduleZipAssetPath = $ModuleZipPath
    $assetNames += [IO.Path]::GetFileName($ModuleZipPath)
} else {
    $defaultModuleZipPath = Join-Path $AssetDirectory $moduleZipName
    if (Test-Path -LiteralPath $defaultModuleZipPath -PathType Leaf) {
        $moduleZipAssetPath = $defaultModuleZipPath
        $assetNames += $moduleZipName
    } elseif ($RequireModuleZip) {
        throw ("Required module ZIP release asset not found: {0}" -f $defaultModuleZipPath)
    }
}

$sourceManifest = Get-LVSourceManifest -BasePath $SourceDirectory
$sourceManifestPath = Join-Path $OutputDirectory 'source-manifest.json'
Write-LVJsonFile -Path $sourceManifestPath -Value $sourceManifest

$pinnedDependencyPath = Join-Path $repoRoot 'Data/build-dependencies.json'
if (-not (Test-Path -LiteralPath $pinnedDependencyPath -PathType Leaf)) { throw 'Tracked build dependency pin file is missing.' }
$pinnedDependencies = Get-Content -LiteralPath $pinnedDependencyPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$pinnedDependencies.schemaVersion -ne 1 -or [string]$pinnedDependencies.name -ne 'LogVerdict.BuildDependencies') {
    throw 'Tracked build dependency pin file has an unsupported contract.'
}
$dependencySpecs = @($pinnedDependencies.dependencies | Where-Object { $_ })
if ($dependencySpecs.Count -ne 3) { throw ("Tracked build dependency pin file must contain three dependencies; found {0}." -f $dependencySpecs.Count) }
$dependencies = @()
foreach ($spec in $dependencySpecs) {
    foreach ($propertyName in @('name', 'version', 'purpose', 'source', 'hashKind', 'contentSha256', 'fileCount', 'totalBytes')) {
        if (-not $spec.PSObject.Properties[$propertyName] -or [string]::IsNullOrWhiteSpace([string]$spec.$propertyName)) {
            throw ("Tracked build dependency {0} is missing '{1}'." -f $spec.name, $propertyName)
        }
    }
    if ([string]$spec.source -cne 'PowerShell Gallery' -or [string]$spec.hashKind -cne 'module-file-manifest') {
        throw ("Tracked build dependency {0} has unsupported provenance metadata." -f $spec.name)
    }
    $dependency = Get-LVModuleManifest -Name ([string]$spec.name) -ExpectedVersion ([string]$spec.version) `
        -ExpectedContentSha256 ([string]$spec.contentSha256) -ExpectedFileCount ([int]$spec.fileCount) -ExpectedTotalBytes ([int64]$spec.totalBytes)
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
$status = Invoke-LVGit -ArgumentList @('status', '--porcelain', '--untracked-files=all')
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
    $assetPath = if ($name -ceq $moduleZipName -and $moduleZipAssetPath) { $moduleZipAssetPath } else { Join-Path $AssetDirectory $name }
    $assetHash = Get-LVFileSha256 -Path $assetPath
    $safeName = [IO.Path]::GetFileNameWithoutExtension($name)
    $spdxName = $safeName + '.spdx.json'
    $cycloneDxName = $safeName + '.cyclonedx.json'
    $provenanceName = $safeName + '.provenance.json'
    $spdxPath = Join-Path $OutputDirectory $spdxName
    $cycloneDxPath = Join-Path $OutputDirectory $cycloneDxName
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

    $cycloneComponent = [ordered]@{
        type = 'application'
        'bom-ref' = 'pkg:generic/logverdict/' + $Version + '/' + $safeName
        group = 'SysAdminDoc'
        name = $name
        version = $Version
        description = 'Unsigned LogVerdict release asset; verify the companion provenance record and SHA-256 digest before use.'
        hashes = @([ordered]@{ alg = 'SHA-256'; content = $assetHash })
        licenses = @(
            [ordered]@{ license = [ordered]@{ id = 'MIT' } }
            [ordered]@{ license = [ordered]@{ id = 'CC-BY-4.0' } }
        )
        properties = @(
            [ordered]@{ name = 'logverdict:source-revision'; value = $revision }
            [ordered]@{ name = 'logverdict:source-tree-sha256'; value = $sourceManifest.sourceTreeSha256 }
            [ordered]@{ name = 'logverdict:provenance-signed'; value = 'false' }
            [ordered]@{ name = 'logverdict:provenance-note'; value = 'Self-asserted and unsigned; verify the published SHA-256 digest and companion provenance record.' }
        )
    }
    $cycloneDx = [ordered]@{
        '$schema' = 'https://cyclonedx.org/schema/bom-1.7.schema.json'
        bomFormat = 'CycloneDX'
        specVersion = '1.7'
        serialNumber = 'urn:uuid:' + ([Guid]::NewGuid().ToString())
        version = 1
        metadata = [ordered]@{
            timestamp = $createdAt
            tools = @([ordered]@{ vendor = 'SysAdminDoc'; name = 'LogVerdict supply-chain metadata'; version = '1' })
        }
        components = @($cycloneComponent)
    }
    Write-LVJsonFile -Path $cycloneDxPath -Value $cycloneDx -Depth 20

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
        cyclonedx = [ordered]@{
            path = $cycloneDxName
            sha256 = Get-LVFileSha256 -Path $cycloneDxPath
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
        cyclonedx = $cycloneDxName
        cyclonedxSha256 = Get-LVFileSha256 -Path $cycloneDxPath
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
