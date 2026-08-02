#requires -Version 5.1

<#
.SYNOPSIS
Run the offline release integrity gates for LogVerdict.

.DESCRIPTION
Checks the single version source against the module manifest, README badge,
package metadata, typed error catalog, and verdict database. When -AssetDirectory
is supplied, package hashes are checked against the exact built executables too.
The script never downloads or publishes anything.
##>
[CmdletBinding()]
param(
    [string]$ManifestDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Packaging'),
    [string]$AssetDirectory
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$version = (& (Join-Path $PSScriptRoot 'Get-LogVerdictVersion.ps1')).Trim()

if ($PSVersionTable.PSVersion -lt [version]'5.1') {
    throw ("Unsupported PowerShell runtime {0}; LogVerdict requires 5.1 or newer." -f $PSVersionTable.PSVersion)
}

$pester = @(Get-Module -ListAvailable Pester | Sort-Object Version -Descending | Select-Object -First 1)
if ($pester.Count -eq 0) {
    Write-Warning 'Pester is not installed; CI must install the pinned test dependency before running the suite.'
} elseif ($pester[0].Version.Major -ge 6) {
    Write-Warning ("Pester {0} is newer than the pinned Pester 5 test contract; CI uses Pester 5.9.0." -f $pester[0].Version)
}
$analyzer = @(Get-Module -ListAvailable PSScriptAnalyzer | Sort-Object Version -Descending | Select-Object -First 1)
if ($analyzer.Count -eq 0) {
    Write-Warning 'PSScriptAnalyzer is not installed; CI must install the pinned analyzer dependency before release.'
}

$manifest = Test-ModuleManifest -Path (Join-Path $repoRoot 'LogVerdict.psd1')
if ($manifest.Version.ToString() -ne $version) {
    throw ("Module manifest is v{0}, but VERSION is v{1}." -f $manifest.Version, $version)
}

$readme = Get-Content -LiteralPath (Join-Path $repoRoot 'README.md') -Raw -Encoding UTF8
if ($readme -notmatch ("shields\.io/badge/version-{0}-blue" -f [regex]::Escape($version))) {
    throw ("README version badge does not declare v{0}." -f $version)
}

Import-Module (Join-Path $repoRoot 'LogVerdict.psd1') -Force
if (-not (Test-LogVerdictDatabase -Quiet)) {
    throw 'Verdict database trust/provenance gate failed.'
}
$catalog = @(Get-LogVerdictErrorCatalog)
if ($catalog.Count -lt 3000) { throw ("Typed error catalog contains only {0} entries." -f $catalog.Count) }
foreach ($entry in $catalog) {
    if ($entry.sourceHash -notmatch '^(?i:[0-9a-f]{64})$' -or $entry.normalized.family -ne $entry.kind) {
        throw ("Typed error catalog entry '{0}' failed normalized metadata validation." -f $entry.id)
    }
}
$catalogSchema = Get-Content -LiteralPath (Join-Path $repoRoot 'Data/error-codes.schema.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$catalogSchema.properties.schemaVersion.const -ne 2) { throw 'Typed error catalog schema is not pinned at version 2.' }

$scoopPath = Join-Path $ManifestDirectory 'scoop/logverdict.json'
$wingetPath = Join-Path $ManifestDirectory 'winget/SysAdminDoc.LogVerdict.yaml'
if (-not (Test-Path -LiteralPath $scoopPath) -or -not (Test-Path -LiteralPath $wingetPath)) {
    throw 'Both Scoop and winget manifests are required for the release gate.'
}
$scoop = Get-Content -LiteralPath $scoopPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([string]$scoop.version -ne $version) { throw ("Scoop manifest is v{0}, but VERSION is v{1}." -f $scoop.version, $version) }
$winget = Get-Content -LiteralPath $wingetPath -Raw -Encoding UTF8
if ($winget -notmatch ("(?m)^PackageVersion: {0}\r?$" -f [regex]::Escape($version))) { throw 'winget manifest version does not match VERSION.' }
$scoopHashes = @($scoop.architecture.'64bit'.hash)
if ($scoopHashes.Count -ne 2 -or ($scoopHashes | Where-Object { $_ -notmatch '^(?i:[0-9a-f]{64})$' }).Count -gt 0) {
    throw 'Scoop manifest must contain two valid SHA-256 hashes.'
}
$wingetHash = [regex]::Match($winget, '(?m)^    InstallerSha256: ([0-9A-Fa-f]{64})\r?$')
if (-not $wingetHash.Success) { throw 'winget manifest is missing a valid installer SHA-256.' }
if ($AssetDirectory) {
    function Get-LVReleaseHash([string]$Path) {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    }
    $consoleHash = Get-LVReleaseHash (Join-Path $AssetDirectory 'LogVerdict.exe')
    $guiHash = Get-LVReleaseHash (Join-Path $AssetDirectory 'LogVerdict-GUI.exe')
    if ($scoopHashes[0] -ine $consoleHash -or $scoopHashes[1] -ine $guiHash -or $wingetHash.Groups[1].Value -ine $consoleHash) {
        throw 'Package manifest hashes do not match the supplied release assets.'
    }
}

Write-Output ("Release gates passed for LogVerdict v{0}: {1} typed catalog entries." -f $version, $catalog.Count)
