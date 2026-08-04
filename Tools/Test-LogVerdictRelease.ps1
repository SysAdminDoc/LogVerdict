<#
.SYNOPSIS
Run the offline release integrity gates for LogVerdict.

.DESCRIPTION
Checks the single version source against the module manifest, README badge,
package metadata, typed error catalog, and verdict database. When -AssetDirectory
is supplied, package hashes are checked against the exact built executables too.
When -SupplyChainDirectory is supplied, the SPDX, CycloneDX 1.7, and provenance
records in that directory are also checked offline against the source checkout and
assets.
The script never downloads or publishes anything. A stale advisory cache is a
warning during ordinary quality checks and a blocker when -ReleaseValidation is
supplied.
##>
[CmdletBinding()]
param(
    [string]$ManifestDirectory,
    [string]$AssetDirectory,
    [string]$SupplyChainDirectory,
    [string]$AdvisoryPath,
    [switch]$SkipSchemaValidation,
    [switch]$ReleaseValidation
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent

function Get-LVReleaseSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Write-LVReleaseJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )

    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, (($Value | ConvertTo-Json -Depth 30) + [Environment]::NewLine), $utf8NoBom)
}

function Test-LVReleaseJsonSchema {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SchemaPath,
        [Parameter(Mandatory)][string]$Label
    )

    if (-not (Get-Command -Name Test-Json -ErrorAction SilentlyContinue)) {
        throw 'JSON schema validation requires PowerShell 7.6 or newer with Test-Json.'
    }
    try {
        $valid = Test-Json -LiteralPath $Path -SchemaFile $SchemaPath -ErrorAction Stop
    } catch {
        throw ("{0} failed JSON schema validation: {1}" -f $Label, $_.Exception.Message)
    }
    if (-not $valid) { throw ("{0} failed JSON schema validation." -f $Label) }
}

function Read-LVReleaseJson {
    param([Parameter(Mandatory)][string]$Path)

    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if ($PSVersionTable.PSVersion -ge [version]'7.0') {
        return $raw | ConvertFrom-Json -DateKind String -ErrorAction Stop
    }
    return $raw | ConvertFrom-Json -ErrorAction Stop
}

function Assert-LVReleaseUtcTimestamp {
    param(
        [AllowNull()]$Value,
        [string]$Path = 'document'
    )

    if ($null -eq $Value) { return }
    $timestampNames = @(
        'ScanTime', 'GeneratedAt', 'FirstSeen', 'LastSeen', 'BurstOnset', 'WindowStart', 'WindowEnd',
        'OldestRecord', 'TimeCreated', 'StartTime', 'EndTime', 'Start', 'End', 'Times',
        'scanTime', 'generatedAt', 'firstObserved', 'lastObserved', 'completed', 'started',
        'windowStart', 'windowEnd', 'oldestRecord', 'timeCreated', 'timestampUtc', 'endTimestampUtc'
    )
    $utcPattern = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$'

    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($key in @($Value.Keys)) {
            Assert-LVReleaseUtcTimestamp -Value $Value[$key] -Path ("{0}.{1}" -f $Path, $key)
        }
        return
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $index = 0
        foreach ($item in @($Value)) {
            Assert-LVReleaseUtcTimestamp -Value $item -Path ("{0}[{1}]" -f $Path, $index)
            $index++
        }
        return
    }

    $properties = @($Value.PSObject.Properties)
    foreach ($property in $properties) {
        $propertyPath = "{0}.{1}" -f $Path, $property.Name
        $propertyValue = $property.Value
        if ($timestampNames -contains [string]$property.Name) {
            $timestampValues = if ($propertyValue -is [System.Collections.IEnumerable] -and $propertyValue -isnot [string]) {
                @($propertyValue)
            } else {
                @($propertyValue)
            }
            foreach ($timestampValue in $timestampValues) {
                if ($null -eq $timestampValue) { continue }
                if ($timestampValue -isnot [string] -or [string]$timestampValue -notmatch $utcPattern) {
                    throw ("{0} is not an RFC3339 UTC timestamp: {1}" -f $propertyPath, $timestampValue)
                }
            }
        }
        if ([string]$property.Name -eq 'Duration' -and $null -ne $propertyValue) {
            if ($propertyValue -isnot [string] -or [string]$propertyValue -notmatch '^P') {
                throw ("{0} must be an ISO-8601 duration string." -f $propertyPath)
            }
        }
        Assert-LVReleaseUtcTimestamp -Value $propertyValue -Path $propertyPath
    }
}

function Test-LVReleaseUtcDocument {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )

    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if ($raw -match '(?i)/Date\(') { throw ("{0} contains a legacy serialized DateTime." -f $Label) }
    $document = Read-LVReleaseJson -Path $Path
    Assert-LVReleaseUtcTimestamp -Value $document -Path $Label
}

if ([string]::IsNullOrWhiteSpace($ManifestDirectory)) {
    $ManifestDirectory = Join-Path $repoRoot 'Packaging'
}
$version = (& (Join-Path $PSScriptRoot 'Get-LogVerdictVersion.ps1')).Trim()

if ($PSVersionTable.PSVersion -lt [version]'5.1') {
    throw ("Unsupported PowerShell runtime {0}; LogVerdict requires 5.1 or newer." -f $PSVersionTable.PSVersion)
}

foreach ($requiredTool in @(
        [pscustomobject]@{ Name = 'Pester'; Version = '6.0.1' }
        [pscustomobject]@{ Name = 'PSScriptAnalyzer'; Version = '1.25.0' }
        [pscustomobject]@{ Name = 'ps2exe'; Version = '1.0.18' }
    )) {
    $installed = @(Get-Module -ListAvailable -Name $requiredTool.Name |
        Where-Object { $_.Version.ToString() -eq $requiredTool.Version } | Select-Object -First 1)
    if ($installed.Count -ne 1) {
        throw ("Pinned release dependency {0} v{1} is not installed." -f $requiredTool.Name, $requiredTool.Version)
    }
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
    if ($entry.sourceRepository -notmatch '^MicrosoftDocs/' -or
        $entry.sourcePath -notmatch '^(desktop-src|windows-driver-docs-pr|support)/' -or
        $entry.sourceRevision -notmatch '^(?i:[0-9a-f]{40})$' -or
        $entry.licence -ne 'CC-BY-4.0' -or
        $entry.sourceDocumentHash -notmatch '^(?i:[0-9a-f]{64})$') {
        throw ("Typed error catalog entry '{0}' failed licensed-source provenance validation." -f $entry.id)
    }
}
$noticePath = Join-Path $repoRoot 'NOTICE'
if (-not (Test-Path -LiteralPath $noticePath -PathType Leaf)) {
    throw 'NOTICE is missing the CC-BY-4.0 catalog attribution.'
}
$notice = Get-Content -LiteralPath $noticePath -Raw -Encoding UTF8
if ($notice -notmatch 'CC-BY-4\.0' -or $notice -notmatch 'MicrosoftDocs/win32' -or
    $notice -notmatch 'MicrosoftDocs/windows-driver-docs') {
    throw 'NOTICE does not identify the licensed MicrosoftDocs catalog sources.'
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
$guiHost = @(
    Get-Content -LiteralPath (Join-Path $repoRoot 'Public/Show-LogVerdictGui.ps1') -Raw -Encoding UTF8
    Get-Content -LiteralPath (Join-Path $repoRoot 'Private/54-LVGuiEvents.ps1') -Raw -Encoding UTF8
) -join [Environment]::NewLine
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
if ([int]$catalogSchema.properties.schemaVersion.const -ne 3) { throw 'Typed error catalog schema is not pinned at version 3.' }
$verdictPath = Join-Path $repoRoot 'Data/verdicts.json'
$verdictSchemaPath = Join-Path $repoRoot 'Data/verdicts.schema.json'
$fixturePath = Join-Path $repoRoot 'Data/fixtures.json'
$fixtureSchemaPath = Join-Path $repoRoot 'Data/fixtures.schema.json'
$catalogPath = Join-Path $repoRoot 'Data/error-codes.json'
$catalogSchemaPath = Join-Path $repoRoot 'Data/error-codes.schema.json'
$verdictSchema = Get-Content -LiteralPath $verdictSchemaPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$verdictSchema.properties.schemaVersion.maximum -ne 7 -or
    @($verdictSchema.definitions.correlation.properties.type.enum) -contains 'event_count' -or
    $verdictSchema.definitions.correlation.properties.PSObject.Properties['group-by']) {
    throw 'Verdict schema advertises correlation semantics the engine does not load.'
}
$fixtureSchema = Get-Content -LiteralPath $fixtureSchemaPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$fixtureSchema.properties.schemaVersion.const -ne 1) { throw 'Regression fixture schema is not pinned at version 1.' }
$advisoryCache = if ($AdvisoryPath) { [IO.Path]::GetFullPath($AdvisoryPath) } else { Join-Path $repoRoot 'Data/advisories.json' }
if (-not (Test-LogVerdictAdvisoryDatabase -Path $advisoryCache -Quiet)) { throw 'Offline advisory cache validation failed.' }
$advisorySchema = Get-Content -LiteralPath (Join-Path $repoRoot 'Data/advisories.schema.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$advisorySchema.properties.schemaVersion.const -ne 2) { throw 'Offline advisory schema is not pinned at version 2.' }
$advisoryStatus = Get-LogVerdictAdvisoryStatus -Path $advisoryCache
if ($advisoryStatus.Status -eq 'stale') {
    $staleMessage = "Offline advisory cache is stale: $($advisoryStatus.Reason)"
    if ($ReleaseValidation) {
        throw $staleMessage
    }
    Write-Warning $staleMessage
} elseif ($advisoryStatus.Status -ne 'fresh') {
    throw ("Offline advisory cache is {0}: {1}" -f $advisoryStatus.Status, $advisoryStatus.Reason)
}
foreach ($runtimeName in @('Windows PowerShell 5.1', 'PowerShell 7.6 LTS')) {
    if (@($advisoryStatus.Coverage.runtime.verifiedRuntimes) -notcontains $runtimeName) {
        throw ("Supported-runtime coverage is missing {0}." -f $runtimeName)
    }
}
foreach ($requiredTool in @(
    [pscustomobject]@{ Name = 'Pester'; Version = '6.0.1' }
    [pscustomobject]@{ Name = 'PSScriptAnalyzer'; Version = '1.25.0' }
    [pscustomobject]@{ Name = 'ps2exe'; Version = '1.0.18' }
)) {
    $toolCoverage = @($advisoryStatus.Coverage.tools | Where-Object { $_.name -eq $requiredTool.Name -and $_.version -eq $requiredTool.Version })
    if ($toolCoverage.Count -ne 1) {
        throw ("Supported-runtime coverage is missing pinned {0} v{1}." -f $requiredTool.Name, $requiredTool.Version)
    }
}
$caseSchemaPath = Join-Path $repoRoot 'Data/case-profile.schema.json'
$reportSchemaPath = Join-Path $repoRoot 'Data/report-contract.schema.json'
$evidenceSchemaPath = Join-Path $repoRoot 'Data/evidence-contract.schema.json'
$reviewSchemaPath = Join-Path $repoRoot 'Data/review-artifact.schema.json'
$providerSchemaPath = Join-Path $repoRoot 'Data/provider.schema.json'
$caseSchema = Get-Content -LiteralPath $caseSchemaPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$caseSchema.properties.schemaVersion.const -ne 1) { throw 'Case profile schema is not pinned at version 1.' }
$reportSchema = Get-Content -LiteralPath $reportSchemaPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$reportSchema.properties.Contract.properties.schemaVersion.const -ne 1) { throw 'Report contract schema is not pinned at version 1.' }
$evidenceSchema = Get-Content -LiteralPath $evidenceSchemaPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$evidenceSchema.properties.Contract.properties.schemaVersion.const -ne 1) { throw 'Evidence contract schema is not pinned at version 1.' }
$reviewSchema = Get-Content -LiteralPath $reviewSchemaPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$reviewSchema.properties.schemaVersion.const -ne 1) { throw 'Review artifact schema is not pinned at version 1.' }
$providerSchema = Get-Content -LiteralPath $providerSchemaPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$providerSchema.properties.schemaVersion.const -ne 1 -or
    @($providerSchema.required) -notcontains 'entrypointSha256' -or
    @($providerSchema.properties.capabilities.items.enum) -notcontains 'redaction') {
    throw 'Provider extension manifest schema is not pinned at version 1 with the required redaction and entrypoint contract.'
}
$exportTemplatePath = Join-Path $repoRoot 'Data/export-templates.json'
$exportTemplateSchemaPath = Join-Path $repoRoot 'Data/export-templates.schema.json'
$exportTemplateSchema = Get-Content -LiteralPath $exportTemplateSchemaPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$exportTemplateSchema.properties.schemaVersion.const -ne 1 -or
    [string]$exportTemplateSchema.properties.name.const -ne 'LogVerdict.ExportTemplates') {
    throw 'Export template schema is not pinned at version 1.'
}
if (-not $SkipSchemaValidation) {
    Test-LVReleaseJsonSchema -Path $exportTemplatePath -SchemaPath $exportTemplateSchemaPath -Label 'export templates'
}
$exportTemplates = Get-Content -LiteralPath $exportTemplatePath -Raw -Encoding UTF8 | ConvertFrom-Json
$reservedExportProjections = [ordered]@{
    Ecs            = [pscustomobject]@{ Projection = 'builtin:ecs'; Kind = 'line'; Source = 'findings' }
    Ocsf           = [pscustomobject]@{ Projection = 'builtin:ocsf'; Kind = 'single'; Source = $null }
    Sarif          = [pscustomobject]@{ Projection = 'builtin:sarif'; Kind = 'single'; Source = $null }
    OpenTelemetry  = [pscustomobject]@{ Projection = 'builtin:opentelemetry'; Kind = 'single'; Source = $null }
    Stix           = [pscustomobject]@{ Projection = 'builtin:stix'; Kind = 'single'; Source = $null }
    Jsonl          = [pscustomobject]@{ Projection = 'builtin:timeline'; Kind = 'line'; Source = 'timeline' }
}
foreach ($builtInFormat in @($reservedExportProjections.Keys)) {
    $builtIn = @($exportTemplates.templates | Where-Object { $_.id -eq $builtInFormat })
    if ($builtIn.Count -ne 1 -or -not $builtIn[0].projection) {
        throw ("Export template registry is missing built-in format '{0}'." -f $builtInFormat)
    }
    $expected = $reservedExportProjections[$builtInFormat]
    if ([string]$builtIn[0].projection -cne [string]$expected.Projection -or
        [string]$builtIn[0].kind -cne [string]$expected.Kind -or
        [string]$builtIn[0].source -cne [string]$expected.Source) {
        throw ("Export template '{0}' is reserved for projection '{1}', kind '{2}', and source '{3}'." -f
            $builtInFormat, $expected.Projection, $expected.Kind, $expected.Source)
    }
}

if (-not $SkipSchemaValidation) {
    $releaseSchemaRoot = Join-Path ([IO.Path]::GetTempPath()) ('LogVerdict-release-schema-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $releaseSchemaRoot -Force | Out-Null
    try {
    $releaseScanTime = Get-Date
    $releaseResult = [pscustomobject][ordered]@{
        Tool = 'LogVerdict'
        Version = $version
        MachineName = 'RELEASE-GATE'
        ScanTime = $releaseScanTime
        Duration = [timespan]::FromSeconds(1)
        DaysBack = 1
        Channels = @('System')
        Elevated = $false
        WorstVerdict = 'benign'
        ExitCode = 0
        Reduction = [pscustomobject]@{ RecordCount = 0; SignatureCount = 0; Ratio = 0 }
        Findings = @()
        Correlations = @()
        Coverage = @([pscustomobject]@{
            Source = 'event'; Kind = 'channel'; Name = 'System'; Status = 'empty'
            ObservedRecords = 0; SkippedRecords = 0; Reason = $null; ParserError = $null
            SHA256 = $null; CollectionBudget = $null; WindowStart = $releaseScanTime.AddDays(-1)
            WindowEnd = $releaseScanTime; Path = $null; Origin = 'release-gate'
        })
        Performance = @()
        HealthProfiles = @()
        EvidenceManifest = @()
        CoverageNotes = @()
        CrashArtifacts = @()
        Horizon = @{}
        HorizonWarning = $null
        Stability = $null
        SetupDiag = $null
        History = $null
        ProviderExtensions = @()
        ProviderProjections = @()
        Advisories = @()
        AdvisoryStatus = 'not-requested'
        AdvisoryCache = $null
        ScanOptions = [ordered]@{ channelMode = 'named'; channels = @('System'); skipTextLogs = $true; skipReliability = $true; includeBenign = $true }
    }

    $reportDirectory = Join-Path $releaseSchemaRoot 'report'
    Export-LogVerdictReport -Result $releaseResult -OutputDir $reportDirectory -Format Json 6>$null | Out-Null
    $reportPath = Join-Path $reportDirectory 'LogVerdict-Report.json'

    $casePath = Join-Path $releaseSchemaRoot 'CASE-PROFILE.json'
    New-LogVerdictCaseProfile -Result $releaseResult -Path $casePath | Out-Null

    $module = Get-Module LogVerdict
    $evidence = & $module {
        param($Result)
        $contract = New-LVEvidenceContract -Result $Result -Content @() -Omission @('release schema gate') -Redacted
        ConvertTo-LVJsonSafeValue -Value $contract
    } $releaseResult
    $evidencePath = Join-Path $releaseSchemaRoot 'EVIDENCE-CONTRACT.json'
    Write-LVReleaseJson -Path $evidencePath -Value $evidence

    $review = & $module {
        param($Result)
        $artifact = New-LVReviewArtifact -Result $Result -Candidate @() `
            -GeneratedAt (ConvertTo-LVUtcTimestamp (Get-Date)) -MachineName 'RELEASE-GATE'
        ConvertTo-LVJsonSafeValue -Value $artifact
    } $releaseResult
    $reviewPath = Join-Path $releaseSchemaRoot 'REVIEW-ARTIFACT.json'
    Write-LVReleaseJson -Path $reviewPath -Value $review

    $providerDirectory = Join-Path $releaseSchemaRoot 'provider'
    New-Item -ItemType Directory -Path $providerDirectory -Force | Out-Null
    $entrypointPath = Join-Path $providerDirectory 'provider.ps1'
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($entrypointPath, "param(`$Context)`r`n", $utf8NoBom)
    $providerManifest = [ordered]@{
        schemaVersion = 1
        id = 'release-gate.provider'
        name = 'Release gate provider'
        version = '1.0.0'
        entrypoint = 'provider.ps1'
        entrypointSha256 = Get-LVReleaseSha256 -Path $entrypointPath
        capabilities = @('collect', 'normalize', 'coverage', 'redaction')
        permissions = @('read-only')
    }
    $providerPath = Join-Path $providerDirectory 'manifest.json'
    Write-LVReleaseJson -Path $providerPath -Value ([pscustomobject]$providerManifest)
    if (-not (Test-LogVerdictProvider -Path $providerDirectory -Quiet)) {
        throw 'Generated provider fixture failed the provider manifest trust gate.'
    }

    $schemaDocuments = @(
        [pscustomobject]@{ Label = 'report'; Path = $reportPath; SchemaPath = $reportSchemaPath; InvalidProperty = 'Tool' }
        [pscustomobject]@{ Label = 'evidence'; Path = $evidencePath; SchemaPath = $evidenceSchemaPath; InvalidProperty = 'Contract.schemaVersion' }
        [pscustomobject]@{ Label = 'case'; Path = $casePath; SchemaPath = $caseSchemaPath; InvalidProperty = 'schemaVersion' }
        [pscustomobject]@{ Label = 'review'; Path = $reviewPath; SchemaPath = $reviewSchemaPath; InvalidProperty = 'schemaVersion' }
        [pscustomobject]@{ Label = 'provider'; Path = $providerPath; SchemaPath = $providerSchemaPath; InvalidProperty = 'schemaVersion' }
    )
    foreach ($documentInfo in $schemaDocuments) {
        $document = Read-LVReleaseJson -Path $documentInfo.Path
        switch ($documentInfo.Label) {
            'report' { $document.Tool = 'NotLogVerdict' }
            'evidence' { $document.Contract.schemaVersion = 999 }
            default { $document.schemaVersion = 999 }
        }
        $invalidPath = Join-Path $releaseSchemaRoot ('invalid-{0}.json' -f $documentInfo.Label)
        Write-LVReleaseJson -Path $invalidPath -Value $document
        $rejected = $false
        try {
            Test-LVReleaseJsonSchema -Path $invalidPath -SchemaPath $documentInfo.SchemaPath -Label ("malformed {0}" -f $documentInfo.Label)
        } catch { $rejected = $true }
        if (-not $rejected) {
            throw ("Malformed {0} document was accepted by its shipped schema." -f $documentInfo.Label)
        }
        Test-LVReleaseJsonSchema -Path $documentInfo.Path -SchemaPath $documentInfo.SchemaPath -Label $documentInfo.Label
        Test-LVReleaseUtcDocument -Path $documentInfo.Path -Label $documentInfo.Label
    }

    # Validate the source contracts as well as generated release documents. Each
    # malformed copy must be rejected so a schema that only exists on paper cannot
    # silently drift away from the data contributors actually edit.
    $dataSchemaDocuments = @(
        [pscustomobject]@{ Label = 'verdict database'; Path = $verdictPath; SchemaPath = $verdictSchemaPath }
        [pscustomobject]@{ Label = 'regression fixtures'; Path = $fixturePath; SchemaPath = $fixtureSchemaPath }
        [pscustomobject]@{ Label = 'typed error catalog'; Path = $catalogPath; SchemaPath = $catalogSchemaPath }
    )
    foreach ($documentInfo in $dataSchemaDocuments) {
        Test-LVReleaseJsonSchema -Path $documentInfo.Path -SchemaPath $documentInfo.SchemaPath -Label $documentInfo.Label
        $invalid = Read-LVReleaseJson -Path $documentInfo.Path
        switch ($documentInfo.Label) {
            'verdict database' { $invalid.schemaVersion = 999 }
            'regression fixtures' { $invalid.fixtures[0].ruleId = '' }
            'typed error catalog' { $invalid.entries[0].id = 'not-a-catalog-id' }
        }
        $invalidPath = Join-Path $releaseSchemaRoot ('invalid-{0}.json' -f ($documentInfo.Label -replace '\s+', '-'))
        Write-LVReleaseJson -Path $invalidPath -Value $invalid
        $rejected = $false
        try {
            Test-LVReleaseJsonSchema -Path $invalidPath -SchemaPath $documentInfo.SchemaPath -Label ("malformed {0}" -f $documentInfo.Label)
        } catch { $rejected = $true }
        if (-not $rejected) {
            throw ("Malformed {0} was accepted by its shipped schema." -f $documentInfo.Label)
        }
    }

    # Standards smoke contract. These assertions stay intentionally field-level:
    # an envelope can round-trip through ConvertFrom-Json while still violating the
    # target format's ingest rules.
    $standardFinding = [pscustomobject][ordered]@{
        Key = 'event|System|41'; Source = 'event'; Channel = 'System'; Provider = 'Microsoft-Windows-Kernel-Power'; Id = 41
        Level = 1; WorstLevel = 1; LevelName = 'Critical'; Count = 1; PerDay = 1; FirstSeen = $releaseScanTime; LastSeen = $releaseScanTime
        SampleMessage = 'Kernel-Power event 41'; Samples = @('Kernel-Power event 41');
        Verdict = 'actionable'; Title = 'Unexpected shutdown'; Plain = 'The system restarted without a clean shutdown.'
        Why = 'Release-gate fixture'; Action = 'Review the preceding bugcheck evidence.'; RuleId = 'LV-0001'; Confidence = 'high'
        Reference = $null; References = @(); Sources = @(); Suppressed = $false
    }
    $releaseResult.Findings = @($standardFinding)
    $releaseResult.Reduction.SignatureCount = 1

    $ecsPath = Join-Path $releaseSchemaRoot 'standard.ecs.jsonl'
    $ecsWritten = Export-LogVerdictStandard -Result $releaseResult -Format Ecs -Path $ecsPath
    if ([int]$ecsWritten.LineCount -ne 1) { throw 'ECS export must emit one line per finding.' }
    $ecsDocument = Get-Content -LiteralPath $ecsPath | Select-Object -First 1 | ConvertFrom-Json
    if ($ecsDocument.PSObject.Properties['findings'] -or $ecsDocument.event.PSObject.Properties['count'] -or
        $ecsDocument.rule.PSObject.Properties['confidence']) {
        throw 'ECS export leaked the old container or reserved field namespaces.'
    }
    if ([string]$ecsDocument.log.level -eq [string]$standardFinding.Verdict) {
        throw 'ECS log.level must describe the source event, not the LogVerdict verdict.'
    }

    $sarifDocument = (Export-LogVerdictStandard -Result $releaseResult -Format Sarif).Document
    if ([string]$sarifDocument.'$schema' -notmatch '/cos02/schemas/sarif-schema-2\.1\.0\.json$') {
        throw 'SARIF export is not pinned to the cos02 schema URL.'
    }
    $sarifRuleIds = @{}
    foreach ($rule in @($sarifDocument.runs[0].tool.driver.rules)) { $sarifRuleIds[[string]$rule.id] = $true }
    foreach ($sarifResult in @($sarifDocument.runs[0].results)) {
        if ($sarifResult.ruleId -and -not $sarifRuleIds.ContainsKey([string]$sarifResult.ruleId)) {
            throw ("SARIF result ruleId '{0}' is absent from driver.rules." -f $sarifResult.ruleId)
        }
        if ([string]$sarifResult.kind -ne 'fail' -and [string]$sarifResult.level -ne 'none') {
            throw 'SARIF non-fail results must use level=none.'
        }
        if ($sarifResult.locations[0].physicalLocation) {
            throw 'SARIF fabricated a physical source location for the release fixture.'
        }
    }
    if (-not [bool]$sarifDocument.runs[0].invocations[0].executionSuccessful) {
        throw 'SARIF executionSuccessful should be true for the zero-exit release fixture.'
    }

    $otelDocument = (Export-LogVerdictStandard -Result $releaseResult -Format OpenTelemetry).Document
    foreach ($logRecord in @($otelDocument.resourceLogs[0].scopeLogs[0].logRecords)) {
        foreach ($name in @('timeUnixNano', 'observedTimeUnixNano')) {
            if ($logRecord.PSObject.Properties[$name] -and $logRecord.$name -isnot [string]) {
                throw ("OpenTelemetry {0} must be a decimal string in JSON." -f $name)
            }
            if ([string]$logRecord.$name -eq '0') {
                throw ("OpenTelemetry {0} may not invent the Unix epoch." -f $name)
            }
        }
        if ($logRecord.droppedAttributesCount -isnot [int32] -and $logRecord.droppedAttributesCount -isnot [int64]) {
            throw 'OpenTelemetry droppedAttributesCount must remain a uint32 JSON number.'
        }
        foreach ($attribute in @($logRecord.attributes)) {
            if ($attribute.value.PSObject.Properties['intValue'] -and $attribute.value.intValue -isnot [string]) {
                throw 'OpenTelemetry AnyValue.intValue must be a decimal string.'
            }
        }
    }

    $stixFirst = (Export-LogVerdictStandard -Result $releaseResult -Format Stix).Document
    $stixSecond = (Export-LogVerdictStandard -Result $releaseResult -Format Stix).Document
    if ($stixFirst.PSObject.Properties['spec_version']) { throw 'STIX bundles must not carry spec_version.' }
    if ((@($stixFirst.objects | ForEach-Object id) -join '|') -ne (@($stixSecond.objects | ForEach-Object id) -join '|')) {
        throw 'STIX object identifiers must be deterministic for one signature set.'
    }
    foreach ($observed in @($stixFirst.objects | Where-Object type -eq 'observed-data')) {
        if (-not $observed.created -or -not $observed.modified -or [int64]$observed.number_observed -lt 1 -or
            @($observed.object_refs).Count -lt 1) { throw 'STIX observed-data is missing its 2.1 required fields.' }
    }
    } finally {
        if (Test-Path -LiteralPath $releaseSchemaRoot) {
            Remove-Item -LiteralPath $releaseSchemaRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
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
    Write-Verbose 'Verified SPDX 2.3, CycloneDX 1.7, and unsigned provenance records for every release asset.'
}

Write-Output ("Release gates passed for LogVerdict v{0}: {1} typed catalog entries." -f $version, $catalog.Count)
