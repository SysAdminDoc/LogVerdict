[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'logverdict-performance.json'),
    [string]$BudgetPath = (Join-Path $PSScriptRoot '..\Data\performance-budgets.json')
)

$ErrorActionPreference = 'Stop'

function Add-LVBenchmarkFailure {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$List,
        [Parameter(Mandatory)][string]$FixtureId,
        [Parameter(Mandatory)][string]$Reason
    )

    $List.Add(('{0}: {1}' -f $FixtureId, $Reason)) | Out-Null
}

function New-LVBenchmarkTextFixture {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$LineCount,
        [Parameter(Mandatory)][int]$ErrorEvery,
        [switch]$MalformedTimestamps
    )

    $builder = New-Object System.Text.StringBuilder
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    for ($i = 1; $i -le $LineCount; $i++) {
        if (($i % $ErrorEvery) -eq 0) {
            if ($MalformedTimestamps) {
                $line = 'not-a-timestamp, Error synthetic fixture line {0}' -f $i
            } else {
                $line = '{0}, Error synthetic fixture line {1}' -f $stamp, $i
            }
        } else {
            $line = '{0} informational synthetic fixture line {1}' -f $stamp, $i
        }
        [void]$builder.AppendLine($line)
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $builder.ToString(), $utf8NoBom)
}

function New-LVBenchmarkEvtxFixture {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$ByteCount
    )

    $bytes = New-Object byte[] $ByteCount
    for ($i = 0; $i -lt $ByteCount; $i++) { $bytes[$i] = [byte](($i + 1) % 255) }
    [System.IO.File]::WriteAllBytes($Path, $bytes)
}

function Invoke-LVBenchmarkTextFixture {
    param(
        [Parameter(Mandatory)]$Module,
        [Parameter(Mandatory)][string]$FixtureId,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$LineCount
    )

    $target = [pscustomobject]@{
        Name = $FixtureId
        Path = $Path
        Pattern = ',\s*Error\s'
        TimePattern = '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
        TimeFormat = 'yyyy-MM-dd HH:mm:ss'
        Area = 'content-free benchmark'
        Hint = 'synthetic parser fixture'
    }

    $timer = [Diagnostics.Stopwatch]::StartNew()
    $state = & $Module {
        param($Target)
        $script:LVTextLogCoverage = @()
        $budget = New-LVCollectionBudget -MaxBytes 134217728 -MaxRecords 200000 -MaxSeconds 120
        $records = @(Get-LVTextLogRecord -DaysBack 1 -MaxMatchesPerFile 200000 -Target @($Target) -CollectionBudget $budget)
        [pscustomobject]@{
            Records = $records
            Coverage = @($script:LVTextLogCoverage)
            Budget = Get-LVCollectionBudgetSnapshot -Budget $budget
        }
    } $target
    $timer.Stop()

    $records = @($state.Records)
    $coverage = @($state.Coverage)
    $observed = [int64]$records.Count
    $skipped = [int64]0
    foreach ($entry in $coverage) {
        if ($null -ne $entry.SkippedRecords) { $skipped += [int64]$entry.SkippedRecords }
    }

    return [pscustomobject][ordered]@{
        Id = $FixtureId
        SourceKind = 'text'
        Status = if ($coverage.Count -gt 0) { [string]$coverage[0].Status } else { 'unavailable' }
        ObservedRecords = $observed
        SkippedRecords = $skipped
        UndatedRecords = [int64]@($records | Where-Object { $_.Undated }).Count
        InputLines = [int64]$LineCount
        InputBytes = [int64](Get-Item -LiteralPath $Path).Length
        ElapsedMilliseconds = [int64][Math]::Round($timer.Elapsed.TotalMilliseconds, 0)
        ParserMilliseconds = if ($coverage.Count -gt 0 -and $null -ne $coverage[0].ParseMilliseconds) { [int64]$coverage[0].ParseMilliseconds } else { $null }
        BudgetStop = if ($state.Budget) { $state.Budget.StopReason } else { $null }
    }
}

function Invoke-LVBenchmarkEvtxFixture {
    param(
        [Parameter(Mandatory)][string]$FixtureId,
        [Parameter(Mandatory)][string]$Path
    )

    $timer = [Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-LogVerdictScan -EvidencePath $Path -DaysBack 1 -SkipTextLogs -SkipReliability -PerformanceTelemetry
    $timer.Stop()

    $manifest = @($result.EvidenceManifest)
    $performance = @($result.Performance | Where-Object { $_.Source -eq 'offline-evtx' })
    $observed = [int64]0
    $parserMilliseconds = $null
    $status = 'unavailable'
    if ($manifest.Count -gt 0) {
        $status = [string]$manifest[0].Status
        if ($null -ne $manifest[0].RecordCount) { $observed = [int64]$manifest[0].RecordCount }
        if ($null -ne $manifest[0].ParseMilliseconds) { $parserMilliseconds = [int64]$manifest[0].ParseMilliseconds }
    }

    $skipped = [int64]0
    if ($performance.Count -gt 0 -and $null -ne $performance[0].SkippedRecords) {
        $skipped = [int64]$performance[0].SkippedRecords
    }

    return [pscustomobject][ordered]@{
        Id = $FixtureId
        SourceKind = 'offline-evtx'
        Status = $status
        ObservedRecords = $observed
        SkippedRecords = $skipped
        UndatedRecords = 0
        InputLines = $null
        InputBytes = [int64](Get-Item -LiteralPath $Path).Length
        ElapsedMilliseconds = [int64][Math]::Round($timer.Elapsed.TotalMilliseconds, 0)
        ParserMilliseconds = $parserMilliseconds
        BudgetStop = $null
    }
}

if (-not (Test-Path -LiteralPath $BudgetPath -PathType Leaf)) {
    throw ("Performance budget file not found: {0}" -f $BudgetPath)
}

$budget = Get-Content -LiteralPath $BudgetPath -Raw | ConvertFrom-Json
if ([int]$budget.schemaVersion -ne 1) { throw 'Performance budget schemaVersion must be 1.' }
if (-not $budget.fixtures) { throw 'Performance budget must declare at least one fixture.' }

$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'LogVerdict.psd1') -Force
$module = Get-Module LogVerdict
if ($null -eq $module) { throw 'LogVerdict module did not load.' }

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('LogVerdict-performance-' + [guid]::NewGuid().ToString('N'))
$failures = New-Object System.Collections.Generic.List[string]
$results = New-Object System.Collections.Generic.List[object]
$started = [Diagnostics.Stopwatch]::StartNew()

try {
    New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null

    foreach ($definition in @($budget.fixtures)) {
        $id = [string]$definition.id
        try {
            if (-not $id) { throw 'fixture id is required' }
            if (-not $definition.sourceKind) { throw 'sourceKind is required' }
            if ([int64]$definition.maxElapsedMilliseconds -le 0) { throw 'maxElapsedMilliseconds must be positive' }
            if (-not $definition.expectedStatus) { throw 'expectedStatus is required' }

            $extension = if ([string]$definition.sourceKind -eq 'offline-evtx') { '.evtx' } else { '.log' }
            $path = Join-Path $temporaryRoot ($id + $extension)
            if ([string]$definition.sourceKind -eq 'text') {
                $lineCount = [int]$definition.lineCount
                $errorEvery = [int]$definition.errorEvery
                if ($lineCount -le 0 -or $errorEvery -le 0) { throw 'text fixture lineCount and errorEvery must be positive' }
                New-LVBenchmarkTextFixture -Path $path -LineCount $lineCount -ErrorEvery $errorEvery -MalformedTimestamps:([bool]$definition.malformedTimestamps)
                $entry = Invoke-LVBenchmarkTextFixture -Module $module -FixtureId $id -Path $path -LineCount $lineCount
            } elseif ([string]$definition.sourceKind -eq 'offline-evtx') {
                $byteCount = [int]$definition.byteCount
                if ($byteCount -le 0) { throw 'EVTX fixture byteCount must be positive' }
                New-LVBenchmarkEvtxFixture -Path $path -ByteCount $byteCount
                $entry = Invoke-LVBenchmarkEvtxFixture -FixtureId $id -Path $path
            } else {
                throw ("unsupported sourceKind '{0}'" -f $definition.sourceKind)
            }

            if ($entry.Status -ne [string]$definition.expectedStatus) {
                Add-LVBenchmarkFailure -List $failures -FixtureId $id -Reason ("expected status {0}, observed {1}" -f $definition.expectedStatus, $entry.Status)
            }
            if ($entry.ElapsedMilliseconds -gt [int64]$definition.maxElapsedMilliseconds) {
                Add-LVBenchmarkFailure -List $failures -FixtureId $id -Reason ("elapsed {0} ms exceeded budget {1} ms" -f $entry.ElapsedMilliseconds, $definition.maxElapsedMilliseconds)
            }
            if ($definition.PSObject.Properties['maxParserMilliseconds'] -and $null -ne $entry.ParserMilliseconds -and
                $entry.ParserMilliseconds -gt [int64]$definition.maxParserMilliseconds) {
                Add-LVBenchmarkFailure -List $failures -FixtureId $id -Reason ("parser elapsed {0} ms exceeded budget {1} ms" -f $entry.ParserMilliseconds, $definition.maxParserMilliseconds)
            }
            if ($definition.PSObject.Properties['minObservedRecords'] -and $entry.ObservedRecords -lt [int64]$definition.minObservedRecords) {
                Add-LVBenchmarkFailure -List $failures -FixtureId $id -Reason ("observed {0} record(s), minimum is {1}" -f $entry.ObservedRecords, $definition.minObservedRecords)
            }
            if ($definition.PSObject.Properties['expectedUndatedRecords'] -and $entry.UndatedRecords -ne [int64]$definition.expectedUndatedRecords) {
                Add-LVBenchmarkFailure -List $failures -FixtureId $id -Reason ("observed {0} undated record(s), expected {1}" -f $entry.UndatedRecords, $definition.expectedUndatedRecords)
            }
            $results.Add($entry) | Out-Null
        } catch {
            Add-LVBenchmarkFailure -List $failures -FixtureId $(if ($id) { $id } else { 'unnamed-fixture' }) -Reason 'fixture execution failed'
        }
    }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
    $started.Stop()
}

$document = [ordered]@{
    SchemaVersion = 1
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
    Runtime = $PSVersionTable.PSVersion.ToString()
    Edition = $PSVersionTable.PSEdition
    BudgetName = [string]$budget.name
    Passed = ($failures.Count -eq 0)
    Failures = @($failures.ToArray())
    Fixtures = @($results.ToArray())
    TotalElapsedMilliseconds = [int64][Math]::Round($started.Elapsed.TotalMilliseconds, 0)
}

$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$json = $document | ConvertTo-Json -Depth 8
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutputPath, $json, $utf8NoBom)

Write-Output ('Performance gate: {0} ({1} fixtures, runtime {2})' -f $(if ($document.Passed) { 'passed' } else { 'failed' }), $results.Count, $document.Runtime)
foreach ($entry in $results.ToArray()) {
    Write-Output ('  {0}: {1} - {2} ms, {3} record(s)' -f $entry.Id, $entry.Status, $entry.ElapsedMilliseconds, $entry.ObservedRecords)
}
foreach ($failure in $failures.ToArray()) { Write-Output ('  FAILURE: {0}' -f $failure) }
Write-Output ('Performance report: {0}' -f $OutputPath)
if (-not $document.Passed) { exit 1 }
