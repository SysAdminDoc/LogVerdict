#requires -Version 5.1

<#
.SYNOPSIS
Generate Scoop and winget manifests for an immutable LogVerdict release.

.DESCRIPTION
Downloads the two executables from an existing GitHub release, computes their
SHA-256 hashes, and writes the package-manager manifests atomically. The script
never creates or changes a release: a published asset URL is treated as
immutable because both package managers pin its hash.

For offline tests, -AssetDirectory supplies already-downloaded release assets;
-ReleaseDate is then required. The generated URLs still point at the selected
GitHub release.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\Tools\New-PackageManifests.ps1 -Version 0.8.0

.EXAMPLE
.\Tools\New-PackageManifests.ps1 -Version 0.8.0 -AssetDirectory .\dist -ReleaseDate 2026-08-01
#>

[CmdletBinding()]
param(
[ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$')]
[string]$Version,

    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string]$Repository = 'SysAdminDoc/LogVerdict',

    [string]$OutputDirectory,

    [string]$AssetDirectory,

    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$ReleaseDate
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Version) {
    $Version = (& (Join-Path $repoRoot 'Tools\Get-LogVerdictVersion.ps1')).Trim()
}

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot 'Packaging'
}

function Write-LVPackageFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )

    $directory = Split-Path $Path -Parent
    if (-not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }

    $temporary = $Path + '.tmp-' + [Guid]::NewGuid().ToString('N')
    try {
        [IO.File]::WriteAllText($temporary, $Content, (New-Object Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Get-LVFileSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::OpenRead($Path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '')
    } finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

function Get-LVReleaseAsset {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Release,
        [Parameter(Mandatory)][string]$DownloadDirectory
    )

    $asset = @($Release.assets | Where-Object { $_.name -eq $Name })
    if ($asset.Count -ne 1) {
        throw ("Release v{0} must contain exactly one {1} asset; found {2}." -f $Version, $Name, $asset.Count)
    }

    $path = Join-Path $DownloadDirectory $Name
    $null = Invoke-WebRequest -Uri $asset[0].browser_download_url -OutFile $path -Headers @{ 'User-Agent'='LogVerdict-package-manifest-generator' }
    return $path
}

$tag = 'v' + $Version
$releaseRoot = 'https://github.com/{0}/releases/download/{1}' -f $Repository, $tag
$consoleUrl = $releaseRoot + '/LogVerdict.exe'
$guiUrl = $releaseRoot + '/LogVerdict-GUI.exe'
$temporaryDirectory = $null

try {
    if ($AssetDirectory) {
        if (-not $ReleaseDate) {
            throw '-ReleaseDate is required with -AssetDirectory so generated manifests remain deterministic.'
        }
        $consoleAsset = Join-Path $AssetDirectory 'LogVerdict.exe'
        $guiAsset = Join-Path $AssetDirectory 'LogVerdict-GUI.exe'
        foreach ($path in @($consoleAsset, $guiAsset)) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw ("Release asset not found: {0}" -f $path)
            }
        }
    } else {
        $apiUrl = 'https://api.github.com/repos/{0}/releases/tags/{1}' -f $Repository, $tag
        $release = Invoke-RestMethod -Uri $apiUrl -Headers @{ 'User-Agent'='LogVerdict-package-manifest-generator' }
        if ($release.draft -or $release.prerelease) {
            throw ("Release {0} is not a published stable release." -f $tag)
        }
        if ([string]$release.tag_name -ne $tag) {
            throw ("GitHub returned tag {0}; expected {1}." -f $release.tag_name, $tag)
        }

        $ReleaseDate = ([datetime]$release.published_at).ToString('yyyy-MM-dd')
        $temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ('LogVerdict-packaging-' + [Guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $temporaryDirectory
        $consoleAsset = Get-LVReleaseAsset -Name 'LogVerdict.exe' -Release $release -DownloadDirectory $temporaryDirectory
        $guiAsset = Get-LVReleaseAsset -Name 'LogVerdict-GUI.exe' -Release $release -DownloadDirectory $temporaryDirectory
    }

    $consoleHash = Get-LVFileSha256 -Path $consoleAsset
    $guiHash = Get-LVFileSha256 -Path $guiAsset

    $scoop = [ordered]@{
        '$schema' = 'https://raw.githubusercontent.com/ScoopInstaller/Scoop/master/schema.json'
        version = $Version
        description = 'Local Windows log triage with curated plain-English verdicts'
        homepage = 'https://github.com/' + $Repository
        license = 'MIT, MS-LPL'
        architecture = [ordered]@{
            '64bit' = [ordered]@{
                url = @($consoleUrl, $guiUrl)
                hash = @($consoleHash.ToLowerInvariant(), $guiHash.ToLowerInvariant())
            }
        }
        bin = 'LogVerdict.exe'
        shortcuts = @(, @('LogVerdict-GUI.exe', 'LogVerdict'))
        checkver = [ordered]@{ github = 'https://github.com/' + $Repository }
        autoupdate = [ordered]@{
            architecture = [ordered]@{
                '64bit' = [ordered]@{
                    url = @(
                        ('https://github.com/{0}/releases/download/v$version/LogVerdict.exe' -f $Repository),
                        ('https://github.com/{0}/releases/download/v$version/LogVerdict-GUI.exe' -f $Repository)
                    )
                }
            }
        }
    }
    $scoopText = ($scoop | ConvertTo-Json -Depth 8) + [Environment]::NewLine

    $wingetLines = @(
        '# yaml-language-server: $schema=https://aka.ms/winget-manifest.singleton.1.12.0.schema.json'
        'PackageIdentifier: SysAdminDoc.LogVerdict'
        ('PackageVersion: {0}' -f $Version)
        'PackageLocale: en-US'
        'Publisher: SysAdminDoc'
        'PublisherUrl: https://github.com/SysAdminDoc'
        'PublisherSupportUrl: https://github.com/SysAdminDoc/LogVerdict/issues'
        'PackageName: LogVerdict'
        ('PackageUrl: https://github.com/{0}' -f $Repository)
        'License: MIT, MS-LPL'
        ('LicenseUrl: https://github.com/{0}/blob/main/LICENSE' -f $Repository)
        'ShortDescription: Local Windows log triage with curated plain-English verdicts'
        'Description: Scans Windows diagnostic logs, reduces repeated records into signatures, and explains each finding with a curated verdict and remediation.'
        'Moniker: logverdict'
        'Tags:'
        '  - diagnostics'
        '  - event-log'
        '  - powershell'
        '  - sysadmin'
        '  - troubleshooting'
        'InstallerType: portable'
        'Scope: user'
        'UpgradeBehavior: install'
        'Commands:'
        '  - LogVerdict'
        ('ReleaseDate: {0}' -f $ReleaseDate)
        'Installers:'
        '  - Architecture: x64'
        ('    InstallerUrl: {0}' -f $consoleUrl)
        ('    InstallerSha256: {0}' -f $consoleHash)
        'ManifestType: singleton'
        'ManifestVersion: 1.12.0'
    )
    $wingetText = ($wingetLines -join [Environment]::NewLine) + [Environment]::NewLine

    $scoopPath = Join-Path $OutputDirectory 'scoop/logverdict.json'
    $wingetPath = Join-Path $OutputDirectory 'winget/SysAdminDoc.LogVerdict.yaml'
    Write-LVPackageFile -Path $scoopPath -Content $scoopText
    Write-LVPackageFile -Path $wingetPath -Content $wingetText

    [pscustomobject]@{
        Version = $Version
        ReleaseDate = $ReleaseDate
        ConsoleSha256 = $consoleHash
        GuiSha256 = $guiHash
        ScoopManifest = $scoopPath
        WingetManifest = $wingetPath
    }
} finally {
    if ($temporaryDirectory -and (Test-Path -LiteralPath $temporaryDirectory)) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
