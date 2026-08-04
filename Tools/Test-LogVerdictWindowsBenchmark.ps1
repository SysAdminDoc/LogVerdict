[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CorpusPath,
    [string]$AnnotationPath,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
if (-not $AnnotationPath) { $AnnotationPath = Join-Path $PSScriptRoot '..\Data\windows-log-benchmark.json' }

function Get-LVWindowsBenchmarkSha256 {
    param([Parameter(Mandatory)][string]$Text)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-LVWindowsBenchmarkFileSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function ConvertTo-LVWindowsBenchmarkTemplate {
    param([AllowNull()][string]$Text)

    return (([string]$Text -replace '\s+', ' ').Trim() -replace '<[^>]+>', '<*>')
}

function Test-LVWindowsBenchmarkTemplate {
    param(
        [Parameter(Mandatory)][string]$Predicted,
        [Parameter(Mandatory)][string]$Expected
    )

    $escaped = [regex]::Escape((ConvertTo-LVWindowsBenchmarkTemplate -Text $Expected))
    $escaped = $escaped.Replace([regex]::Escape('<*>'), '<[^>]+>')
    return [regex]::IsMatch((ConvertTo-LVWindowsBenchmarkTemplate -Text $Predicted), '^' + $escaped + '$')
}

if (-not (Test-Path -LiteralPath $CorpusPath -PathType Leaf)) { throw "Benchmark corpus projection not found: $CorpusPath" }
if (-not (Test-Path -LiteralPath $AnnotationPath -PathType Leaf)) { throw "Benchmark annotation manifest not found: $AnnotationPath" }

$manifest = Get-Content -LiteralPath $AnnotationPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$manifest.schemaVersion -ne 1) { throw 'Benchmark annotation schemaVersion must be 1.' }
if ([string]$manifest.annotationLicense -ne 'MIT') { throw 'Benchmark annotations must declare the MIT license.' }
if (-not $manifest.source -or [string]$manifest.source.sha256 -notmatch '^(?i:[0-9a-f]{64})$') { throw 'Benchmark source metadata must pin a SHA-256 digest.' }
if ([string]$manifest.source.file -cnotin @('Windows_2k.log_structured.csv', 'Windows/Windows_2k.log_structured.csv') -or
    [string]$manifest.source.revision -notmatch '^[0-9a-f]{40}$' -or
    [string]$manifest.source.uri -notmatch '^https://raw\.githubusercontent\.com/logpai/loghub/[0-9a-f]{40}/Windows/Windows_2k\.log_structured\.csv$') {
    throw 'Benchmark source metadata must identify the pinned Windows_2k structured projection.'
}
if (-not $manifest.budgets) { throw 'Benchmark annotation manifest must declare regression budgets.' }
$annotations = @($manifest.annotations | Where-Object { $_ })
if ($annotations.Count -lt [int]$manifest.budgets.minimumRows) { throw 'Benchmark annotation set is smaller than its minimum row budget.' }

$corpusRows = @(Import-Csv -LiteralPath $CorpusPath)
if ($corpusRows.Count -eq 0) { throw 'Benchmark corpus projection contains no rows.' }
$corpusSha256 = Get-LVWindowsBenchmarkFileSha256 -Path $CorpusPath
if ($corpusSha256 -ine [string]$manifest.source.sha256) {
    throw "Benchmark corpus hash $corpusSha256 does not match the annotation manifest pin $($manifest.source.sha256)."
}
$byLineId = @{}
foreach ($corpusRow in $corpusRows) {
    $lineId = [int]$corpusRow.LineId
    if ($byLineId.ContainsKey($lineId)) { throw "Benchmark corpus contains duplicate LineId $lineId." }
    $byLineId[$lineId] = $corpusRow
}

$root = Split-Path -Parent $PSScriptRoot
$moduleManifest = Import-PowerShellDataFile -LiteralPath (Join-Path $root 'LogVerdict.psd1')
Import-Module (Join-Path $root 'LogVerdict.psd1') -Force
$module = Get-Module LogVerdict
if ($null -eq $module) { throw 'LogVerdict module did not load.' }

$evaluationRows = New-Object System.Collections.Generic.List[object]
$seenAnnotationIds = @{}
$seenLineIds = @{}
foreach ($annotation in $annotations) {
    $annotationId = [string]$annotation.id
    $lineId = [int]$annotation.lineId
    if ($seenAnnotationIds.ContainsKey($annotationId)) { throw "Duplicate benchmark annotation id '$annotationId'." }
    if ($seenLineIds.ContainsKey($lineId)) { throw "Duplicate benchmark annotation lineId '$lineId'." }
    $seenAnnotationIds[$annotationId] = $true
    $seenLineIds[$lineId] = $true
    if (-not $byLineId.ContainsKey($lineId)) { throw "Annotation '$annotationId' refers to missing corpus line $lineId." }

    $corpusRow = $byLineId[$lineId]
    $content = [string]$corpusRow.Content
    $lineSha256 = Get-LVWindowsBenchmarkSha256 -Text $content
    if ($lineSha256 -ine [string]$annotation.lineSha256) { throw "Annotation '$annotationId' does not match the supplied corpus line hash." }
    if ([string]$corpusRow.EventId -cne [string]$annotation.eventId -or
        [string]$corpusRow.EventTemplate -cne [string]$annotation.eventTemplate -or
        [string]$corpusRow.Component -cne [string]$annotation.component -or
        [string]$corpusRow.Level -cne [string]$annotation.level) {
        throw "Annotation '$annotationId' disagrees with the corpus label fields."
    }
    $evaluationRows.Add([pscustomobject]@{
        AnnotationId = $annotationId
        LineId = $lineId
        Content = $content
        EventId = [string]$annotation.eventId
        EventTemplate = [string]$annotation.eventTemplate
        Component = [string]$annotation.component
        Level = [string]$annotation.level
        Stratum = [string]$annotation.stratum
    }) | Out-Null
}

$predictions = & $module {
    param([object[]]$InputRows)
    foreach ($inputRow in $InputRows) {
        $data = ConvertTo-LVTemplateData -Text ([string]$inputRow.Content)
        [pscustomobject]@{
            AnnotationId = [string]$inputRow.AnnotationId
            LineId = [int]$inputRow.LineId
            EventId = [string]$inputRow.EventId
            EventTemplate = [string]$inputRow.EventTemplate
            PredictedGroup = ('{0}|{1}|{2}' -f [string]$inputRow.Component, $data.TokenCount, $data.MaskedTemplate)
            PredictedTemplate = [string]$data.MaskedTemplate
            SlotCount = @($data.Slots).Count
        }
    }
} @($evaluationRows.ToArray())

$grouped = @($predictions | Group-Object PredictedGroup)
$purityNumerator = [int64]0
foreach ($group in $grouped) {
    $majority = @($group.Group | Group-Object EventId | Sort-Object Count -Descending | Select-Object -First 1)
    if ($majority.Count -eq 1) { $purityNumerator += [int64]$majority[0].Count }
}
$groupingPurity = [math]::Round($purityNumerator / [double]$predictions.Count, 4)
$parsingMatches = [int64]0
foreach ($prediction in $predictions) {
    if (Test-LVWindowsBenchmarkTemplate -Predicted $prediction.PredictedTemplate -Expected $prediction.EventTemplate) { $parsingMatches++ }
}
$parsingAccuracy = [math]::Round($parsingMatches / [double]$predictions.Count, 4)
$slotCount = ($predictions | Measure-Object -Property SlotCount -Sum).Sum
$strata = @($annotations | Group-Object stratum | ForEach-Object {
        [pscustomobject][ordered]@{ Name = $_.Name; Rows = $_.Count }
    } | Sort-Object Name)

$failures = New-Object System.Collections.Generic.List[string]
if ($predictions.Count -lt [int]$manifest.budgets.minimumRows) {
    $failures.Add(('row count {0} is below minimum {1}' -f $predictions.Count, $manifest.budgets.minimumRows)) | Out-Null
}
if ($groupingPurity -lt [double]$manifest.budgets.minimumGroupingPurity) {
    $failures.Add(('grouping purity {0:N4} is below minimum {1:N4}' -f $groupingPurity, $manifest.budgets.minimumGroupingPurity)) | Out-Null
}
if ($parsingAccuracy -lt [double]$manifest.budgets.minimumParsingAccuracy) {
    $failures.Add(('parsing accuracy {0:N4} is below minimum {1:N4}' -f $parsingAccuracy, $manifest.budgets.minimumParsingAccuracy)) | Out-Null
}

$result = [pscustomobject][ordered]@{
    SchemaVersion = 1
    Tool = 'LogVerdict'
    ToolVersion = [string]$moduleManifest.ModuleVersion
    Dataset = [string]$manifest.source.dataset
    SourceRevision = [string]$manifest.source.revision
    SourceSha256 = [string]$manifest.source.sha256
    CorpusSha256 = $corpusSha256
    Rows = [int]$predictions.Count
    PredictedGroups = [int]$grouped.Count
    GroundTruthTemplates = [int]@($annotations | Group-Object eventId).Count
    Metrics = [pscustomobject][ordered]@{
        GroupingPurity = $groupingPurity
        ParsingAccuracy = $parsingAccuracy
        ReductionRatio = [math]::Round($predictions.Count / [double]$grouped.Count, 4)
        AverageMaskedSlots = [math]::Round($slotCount / [double]$predictions.Count, 4)
    }
    Budgets = $manifest.budgets
    Strata = $strata
    Failures = @($failures.ToArray())
}

if ($OutputPath) {
    $outputParent = Split-Path -Parent $OutputPath
    if ($outputParent -and -not (Test-Path -LiteralPath $outputParent)) { New-Item -ItemType Directory -Path $outputParent -Force | Out-Null }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($OutputPath, ($result | ConvertTo-Json -Depth 12), $utf8NoBom)
}

Write-Output ('Windows benchmark: {0} rows, {1} predicted groups, grouping purity {2:N4}, parsing accuracy {3:N4}.' -f `
    $result.Rows, $result.PredictedGroups, $result.Metrics.GroupingPurity, $result.Metrics.ParsingAccuracy)
if ($failures.Count -gt 0) {
    throw ('Windows benchmark regression budget failed: {0}' -f ($failures -join '; '))
}
return $result
