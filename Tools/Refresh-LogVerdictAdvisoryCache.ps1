#requires -Version 5.1

<#
.SYNOPSIS
Refresh the committed PowerShell advisory cache from the NVD 2.0 API.

.DESCRIPTION
The refresh is explicit and networked. It reads only the two PowerShell CVEs
that define this repository's historical 7.4 and 7.5 advisory coverage, derives
affected version ranges from NVD CPE records, validates the generated document
through the module, and installs it atomically. The supported PowerShell 7
runtime floor is the 7.6 LTS release; older 7.4/7.5 entries remain in the cache
so legacy installations can still be assessed. The ordinary scan and release
gate never contact the network.

.EXAMPLE
.\Tools\Refresh-LogVerdictAdvisoryCache.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputPath,
    [string[]]$CveId = @('CVE-2026-26143', 'CVE-2025-25004')
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) { $OutputPath = Join-Path $repoRoot 'Data\advisories.json' }
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$basePath = Join-Path $repoRoot 'Data\advisories.json'
$base = Get-Content -LiteralPath $basePath -Raw -Encoding UTF8 | ConvertFrom-Json
$retrieved = [datetime]::UtcNow.ToString('yyyy-MM-dd')
$advisories = New-Object System.Collections.Generic.List[object]

function ConvertTo-LVRefreshVersion {
    param([Parameter(Mandatory)][string]$Version)

    if ($Version -match '^\d+\.\d+$') { return ($Version + '.0') }
    if ($Version -match '^\d+\.\d+\.\d+$') { return $Version }
    throw ("NVD returned an unsupported PowerShell version boundary '{0}'." -f $Version)
}

function Get-LVRefreshAdvisoryHash {
    param([Parameter(Mandatory)]$Advisory)

    $cvss = ([double]$Advisory.cvss).ToString('0.0', [Globalization.CultureInfo]::InvariantCulture)
    $kev = ([bool]$Advisory.kev).ToString().ToLowerInvariant()
    $canonical = @(
        [string]$Advisory.id
        [string]$Advisory.ecosystem
        [string]$Advisory.package
        [string]$Advisory.affectedRange
        [string]$Advisory.fixedVersion
        $cvss
        [string]$Advisory.cvssVector
        $kev
        [string]$Advisory.kevDate
        [string]$Advisory.publishedDate
        [string]$Advisory.modifiedDate
        [string]$Advisory.title
        [string]$Advisory.description
        [string]$Advisory.source
        [string]$Advisory.sourceUri
    ) -join '|'
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($canonical)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-LVRefreshCacheHash {
    param([Parameter(Mandatory)]$Advisories)

    $canonical = @($Advisories | Where-Object { $_ } | Sort-Object id | ForEach-Object {
        '{0}:{1}' -f [string]$_.id, [string]$_.sourceHash
    }) -join '|'
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($canonical)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

foreach ($id in $CveId) {
    $uri = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={0}' -f ([uri]::EscapeDataString($id))
    $payload = (Invoke-WebRequest -Uri $uri -UseBasicParsing).Content | ConvertFrom-Json
    if (@($payload.vulnerabilities).Count -ne 1) {
        throw ("NVD returned no unique record for {0}." -f $id)
    }
    $cve = $payload.vulnerabilities[0].cve
    if ([string]$cve.id -ne $id) { throw ("NVD returned {0} while refreshing {1}." -f $cve.id, $id) }

    $metrics = @($cve.metrics.cvssMetricV31 | Where-Object { $_ })
    $metric = @($metrics | Where-Object { [string]$_.source -match '(?i)microsoft' } | Select-Object -First 1)
    if ($metric.Count -eq 0) { $metric = @($metrics | Select-Object -First 1) }
    if ($metric.Count -eq 0) { throw ("NVD record {0} has no CVSS v3.1 metric." -f $id) }

    $ranges = New-Object System.Collections.Generic.List[string]
    $fixed = New-Object System.Collections.Generic.List[string]
    $powerShellMatches = @($cve.configurations.nodes | ForEach-Object { $_.cpeMatch } | Where-Object {
        $_ -and $_.vulnerable -and [string]$_.criteria -match '(?i):microsoft:powershell:' -and
        $_.versionStartIncluding -and $_.versionEndExcluding
    } | Sort-Object versionStartIncluding)
    foreach ($match in $powerShellMatches) {
        $start = ConvertTo-LVRefreshVersion -Version ([string]$match.versionStartIncluding)
        $end = ConvertTo-LVRefreshVersion -Version ([string]$match.versionEndExcluding)
        $family = (($start -split '\.')[0..1] -join '.')
        $ranges.Add(('>={0} <{1}' -f $start, $end)) | Out-Null
        $fixed.Add(('{0} ({1})' -f $end, $family)) | Out-Null
    }
    if ($ranges.Count -eq 0) { throw ("NVD record {0} has no PowerShell affected ranges." -f $id) }

    $description = [string](@($cve.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1).value)
    $title = switch ($id) {
        'CVE-2026-26143' { 'PowerShell improper input validation' }
        'CVE-2025-25004' { 'PowerShell improper access control' }
        default { 'PowerShell security advisory' }
    }
    $entry = [ordered]@{
        id = $id
        ecosystem = 'PowerShell'
        package = 'PowerShell'
        affectedRange = $ranges -join '; '
        fixedVersion = $fixed -join '; '
        cvss = [double]$metric[0].cvssData.baseScore
        cvssVector = [string]$metric[0].cvssData.vectorString
        kev = $false
        kevDate = $null
        publishedDate = ([datetime]$cve.published).ToString('yyyy-MM-dd')
        modifiedDate = ([datetime]$cve.lastModified).ToString('yyyy-MM-dd')
        source = 'NVD/Microsoft'
        sourceUri = 'https://nvd.nist.gov/vuln/detail/{0}' -f $id
        title = $title
        description = $description + ' This advisory is dependency context, not a Windows event verdict.'
    }
    $entry.sourceHash = Get-LVRefreshAdvisoryHash -Advisory ([pscustomobject]$entry)
    $advisories.Add([pscustomobject]$entry) | Out-Null
}

$document = [ordered]@{
    schemaVersion = 2
    name = 'LogVerdict reviewed dependency and tool advisory cache'
    updated = $retrieved
    source = [ordered]@{
        name = 'National Vulnerability Database 2.0 API'
        uri = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        retrieved = $retrieved
    }
    sourceHash = Get-LVRefreshCacheHash -Advisories $advisories
    freshness = $base.freshness
    coverage = $base.coverage
    advisories = @($advisories.ToArray())
}
$json = $document | ConvertTo-Json -Depth 20
$temporary = Join-Path $outputDirectory ('.advisories-refresh-' + [guid]::NewGuid().ToString('N') + '.tmp')
$backup = $OutputPath + '.previous.json'
try {
    [IO.File]::WriteAllText($temporary, $json, (New-Object Text.UTF8Encoding($false)))
    Import-Module (Join-Path $repoRoot 'LogVerdict.psd1') -Force
    if (-not (Test-LogVerdictAdvisoryDatabase -Path $temporary -Quiet)) {
        throw 'Generated advisory cache failed the module validation gate.'
    }
    if (-not $PSCmdlet.ShouldProcess($OutputPath, 'refresh the committed advisory cache')) { return }
    if (Test-Path -LiteralPath $OutputPath -PathType Leaf) {
        [IO.File]::Replace($temporary, $OutputPath, $backup, $true)
    } else {
        Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
    }
    [pscustomobject]@{
        Action = 'refresh'
        OutputPath = $OutputPath
        BackupPath = if (Test-Path -LiteralPath $backup -PathType Leaf) { $backup } else { $null }
        Updated = $document.updated
        EntryCount = @($document.advisories).Count
        SourceHash = $document.sourceHash
    }
} finally {
    if (Test-Path -LiteralPath $temporary -PathType Leaf) {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}
