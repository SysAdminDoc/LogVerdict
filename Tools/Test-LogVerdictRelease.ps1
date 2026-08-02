#requires -Version 5.1

<#
.SYNOPSIS
Run the offline release integrity gates for LogVerdict.

.DESCRIPTION
Checks the single version source against the module manifest, README badge,
package metadata, typed error catalog, and verdict database. When -AssetDirectory
is supplied, package hashes are checked against the exact built executables too.
When -SupplyChainDirectory is supplied, the SPDX and provenance records in that
directory are also checked offline against the source checkout and assets.
The script never downloads or publishes anything.
##>
[CmdletBinding()]
param(
    [string]$ManifestDirectory,
    [string]$AssetDirectory,
    [string]$SupplyChainDirectory
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrWhiteSpace($ManifestDirectory)) {
    $ManifestDirectory = Join-Path $repoRoot 'Packaging'
}
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
$database = Get-LogVerdictDatabase
$ruleCount = @($database.rules).Count
$formattedCatalogCount = '{0:N0}' -f $catalog.Count
foreach ($stalePhrase in @('1,855 red icons', '71 signatures', '1,017 of them')) {
    if ($readme -match [regex]::Escape($stalePhrase)) {
        throw ("README contains a volatile scan example that must not be shipped: '{0}'." -f $stalePhrase)
    }
}
if ($readme -notmatch ('(?m)\b{0} rules ship\b' -f [regex]::Escape($ruleCount))) {
    throw ("README does not describe the current {0} bundled rules." -f $ruleCount)
}
if ($readme -notmatch ('(?m)\b{0}-entry typed\b' -f [regex]::Escape($formattedCatalogCount))) {
    throw ("README does not describe the current {0}-entry typed catalog." -f $formattedCatalogCount)
}
$databaseUsage = 'Update-LogVerdictDatabase -ReleaseTag v{0}' -f $version
if ($readme -notmatch [regex]::Escape($databaseUsage)) {
    throw ("README usage examples do not reference the current release tag v{0}." -f $version)
}
$guiHost = Get-Content -LiteralPath (Join-Path $repoRoot 'Public/Show-LogVerdictGui.ps1') -Raw -Encoding UTF8
$expectedGuiBinding = "`$ui.TxtVersion.Text = 'v{0}' -f `$script:LVVersion"
if ($guiHost -notmatch [regex]::Escape($expectedGuiBinding)) {
    throw 'GUI version text is not bound to the shared VERSION source.'
}
$guiXaml = Get-Content -LiteralPath (Join-Path $repoRoot 'Private/50-LVGuiXaml.ps1') -Raw -Encoding UTF8
if ($guiXaml -match 'x:Name="TxtVersion"[^>]*Text="v\d+\.\d+\.\d+"') {
    throw 'GUI XAML contains a stale hard-coded version.'
}
$documentationScreenshot = Join-Path $repoRoot 'docs/screenshot-gui.png'
$documentationMetadata = Join-Path $repoRoot 'docs/screenshot-gui.json'
if (-not (Test-Path -LiteralPath $documentationScreenshot -PathType Leaf) -or
    -not (Test-Path -LiteralPath $documentationMetadata -PathType Leaf)) {
    throw 'Current GUI screenshot and metadata sidecar are required.'
}
$screenshotMetadata = Get-Content -LiteralPath $documentationMetadata -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$screenshotMetadata.schemaVersion -ne 1 -or
    [string]$screenshotMetadata.artifactVersion -ne $version -or
    [string]$screenshotMetadata.theme -ne 'Normal' -or
    [string]$screenshotMetadata.screenshot -ne 'screenshot-gui.png') {
    throw 'GUI screenshot metadata does not describe the current normal release artifact.'
}
$screenshotSha = [Security.Cryptography.SHA256]::Create()
try {
    $screenshotHash = ([BitConverter]::ToString($screenshotSha.ComputeHash([IO.File]::ReadAllBytes($documentationScreenshot)))).Replace('-', '').ToLowerInvariant()
} finally {
    $screenshotSha.Dispose()
}
if ([string]$screenshotMetadata.screenshotSha256 -ne $screenshotHash) {
    throw 'GUI screenshot metadata hash does not match docs/screenshot-gui.png.'
}
if ([int]$screenshotMetadata.width -le 0 -or [int]$screenshotMetadata.height -le 0) {
    throw 'GUI screenshot metadata has invalid dimensions.'
}
$catalogSchema = Get-Content -LiteralPath (Join-Path $repoRoot 'Data/error-codes.schema.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$catalogSchema.properties.schemaVersion.const -ne 2) { throw 'Typed error catalog schema is not pinned at version 2.' }
$advisoryCache = Join-Path $repoRoot 'Data/advisories.json'
if (-not (Test-LogVerdictAdvisoryDatabase -Path $advisoryCache -Quiet)) { throw 'Offline advisory cache validation failed.' }
$advisorySchema = Get-Content -LiteralPath (Join-Path $repoRoot 'Data/advisories.schema.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$advisorySchema.properties.schemaVersion.const -ne 2) { throw 'Offline advisory schema is not pinned at version 2.' }
$advisoryStatus = Get-LogVerdictAdvisoryStatus -Path $advisoryCache
if ($advisoryStatus.Status -ne 'fresh') {
    throw ("Offline advisory cache is {0}: {1}" -f $advisoryStatus.Status, $advisoryStatus.Reason)
}
foreach ($runtimeName in @('Windows PowerShell 5.1', 'PowerShell 7.x')) {
    if (@($advisoryStatus.Coverage.runtime.verifiedRuntimes) -notcontains $runtimeName) {
        throw ("Supported-runtime coverage is missing {0}." -f $runtimeName)
    }
}
foreach ($requiredTool in @(
    [pscustomobject]@{ Name = 'Pester'; Version = '5.9.0' }
    [pscustomobject]@{ Name = 'PSScriptAnalyzer'; Version = '1.25.0' }
    [pscustomobject]@{ Name = 'ps2exe'; Version = '1.0.18' }
)) {
    $toolCoverage = @($advisoryStatus.Coverage.tools | Where-Object { $_.name -eq $requiredTool.Name -and $_.version -eq $requiredTool.Version })
    if ($toolCoverage.Count -ne 1) {
        throw ("Supported-runtime coverage is missing pinned {0} v{1}." -f $requiredTool.Name, $requiredTool.Version)
    }
}
$caseSchema = Get-Content -LiteralPath (Join-Path $repoRoot 'Data/case-profile.schema.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$caseSchema.properties.schemaVersion.const -ne 1) { throw 'Case profile schema is not pinned at version 1.' }
$reportSchema = Get-Content -LiteralPath (Join-Path $repoRoot 'Data/report-contract.schema.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$reportSchema.properties.Contract.properties.schemaVersion.const -ne 1) { throw 'Report contract schema is not pinned at version 1.' }
$evidenceSchema = Get-Content -LiteralPath (Join-Path $repoRoot 'Data/evidence-contract.schema.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$evidenceSchema.properties.Contract.properties.schemaVersion.const -ne 1) { throw 'Evidence contract schema is not pinned at version 1.' }
$reviewSchema = Get-Content -LiteralPath (Join-Path $repoRoot 'Data/review-artifact.schema.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$reviewSchema.properties.schemaVersion.const -ne 1) { throw 'Review artifact schema is not pinned at version 1.' }
$providerSchema = Get-Content -LiteralPath (Join-Path $repoRoot 'Data/provider.schema.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$providerSchema.properties.schemaVersion.const -ne 1 -or
    @($providerSchema.required) -notcontains 'entrypointSha256' -or
    @($providerSchema.properties.capabilities.items.enum) -notcontains 'redaction') {
    throw 'Provider extension manifest schema is not pinned at version 1 with the required redaction and entrypoint contract.'
}
$localization = Get-Content -LiteralPath (Join-Path $repoRoot 'Data/localization.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$locales = @($localization.locales.PSObject.Properties.Name)
if ([int]$localization.schemaVersion -ne 1 -or [string]$localization.defaultLocale -ne 'en-US' -or
    $locales -notcontains 'en-US' -or $locales -notcontains 'de-DE' -or $locales -notcontains 'ja-JP') {
    throw 'Localization resource must be schema version 1 with en-US, de-DE, and ja-JP locales.'
}
$englishKeys = @($localization.locales.'en-US'.PSObject.Properties.Name)
foreach ($localeName in @('de-DE', 'ja-JP')) {
    $missing = @($englishKeys | Where-Object { -not $localization.locales.$localeName.PSObject.Properties[$_] })
    if ($missing.Count -gt 0) { throw ("Localization locale {0} is missing {1} resource key(s)." -f $localeName, $missing.Count) }
}

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
if ($SupplyChainDirectory) {
    if (-not $AssetDirectory) {
        throw '-AssetDirectory is required when validating supply-chain metadata.'
    }
    & (Join-Path $PSScriptRoot 'Test-LogVerdictSupplyChain.ps1') -Version $version -MetadataDirectory $SupplyChainDirectory -AssetDirectory $AssetDirectory -SourceDirectory $repoRoot
}

Write-Output ("Release gates passed for LogVerdict v{0}: {1} typed catalog entries." -f $version, $catalog.Count)
