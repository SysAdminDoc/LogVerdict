#requires -Version 5.1

<#
.SYNOPSIS
Run the cross-version, locale, fixture, and platform coverage gate.

.DESCRIPTION
Validates the committed representative fixtures, exercises the module's private GUI
markup and elevation observation seams, and emits a structured coverage report. A
fixture that is deliberately malformed or a platform capability that was not present
is recorded with its explicit status; those conditions are not silently treated as a
passing test. When -DisplayEvidencePath is supplied, the gate also verifies the
placement evidence emitted by the packaged GUI launch smoke test.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path ([IO.Path]::GetTempPath()) ('LogVerdict-coverage-{0}.json' -f $PID)),
    [string]$DisplayEvidencePath
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$coverage = New-Object System.Collections.Generic.List[object]
$failures = New-Object System.Collections.Generic.List[string]

function Add-LVCoverageResult {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$Reason,
        [hashtable]$Details = @{}
    )

    $entry = [ordered]@{
        Id = $Id
        Status = $Status
        Reason = $Reason
        Runtime = $PSVersionTable.PSVersion.ToString()
        Edition = $PSVersionTable.PSEdition
        Apartment = [System.Threading.Thread]::CurrentThread.GetApartmentState().ToString()
    }
    foreach ($key in $Details.Keys) { $entry[$key] = $Details[$key] }
    $coverage.Add([pscustomobject]$entry) | Out-Null
}

function Add-LVCoverageFailure {
    param([Parameter(Mandatory)][string]$Message)

    $failures.Add($Message) | Out-Null
    Add-LVCoverageResult -Id 'gate' -Status 'unreadable' -Reason $Message
}

try {
    $fixturePath = Join-Path $repoRoot 'Data\coverage-fixtures.json'
    if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
        throw ("Coverage fixture file not found: {0}" -f $fixturePath)
    }
    $fixtureSet = Get-Content -LiteralPath $fixturePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([int]$fixtureSet.schemaVersion -ne 1) {
        throw ("Unsupported coverage fixture schema version: {0}" -f $fixtureSet.schemaVersion)
    }
    $fixtures = @($fixtureSet.fixtures | Where-Object { $_ })
    if ($fixtures.Count -lt 6) { throw 'Coverage fixture set is unexpectedly small.' }
    $duplicateIds = @($fixtures | Group-Object id | Where-Object Count -gt 1)
    if ($duplicateIds.Count -gt 0) { throw ('Duplicate coverage fixture IDs: {0}' -f (($duplicateIds.Name) -join ', ')) }

    $requiredKinds = @('event', 'textlog', 'offline-evtx', 'elevation', 'gui', 'display')
    foreach ($kind in $requiredKinds) {
        if (@($fixtures | Where-Object kind -eq $kind).Count -eq 0) {
            throw ("Coverage fixture kind '{0}' is missing." -f $kind)
        }
    }
    Add-LVCoverageResult -Id 'fixture-manifest' -Status 'readable' `
        -Reason 'The versioned coverage fixture manifest parsed and contains all required source kinds.' `
        -Details @{ FixtureCount = $fixtures.Count; Path = $fixturePath }

    $eventFixtures = @($fixtures | Where-Object kind -eq 'event')
    $versions = @($eventFixtures | ForEach-Object { [int]$_.record.Version } | Sort-Object -Unique)
    foreach ($fixture in $eventFixtures) {
        foreach ($property in @('ProviderName', 'ProviderId', 'Id', 'Version', 'Task', 'Opcode', 'Level', 'Message')) {
            if (-not $fixture.record.PSObject.Properties[$property]) {
                throw ("Event fixture '{0}' is missing {1}." -f $fixture.id, $property)
            }
        }
    }
    if ($versions.Count -lt 2) { throw 'Provider fixtures must cover at least two event schema versions.' }
    Add-LVCoverageResult -Id 'provider-schema' -Status 'readable' `
        -Reason 'Representative provider records retain identity and old/new version metadata.' `
        -Details @{ Versions = @($versions); EventFixtureCount = $eventFixtures.Count }

    $localeFixture = $eventFixtures | Where-Object { $_.locale -and $_.locale -ne 'en-US' } | Select-Object -First 1
    if ($null -eq $localeFixture -or [string]::IsNullOrWhiteSpace([string]$localeFixture.record.Message)) {
        throw 'A non-English provider fixture with a preserved message is required.'
    }
    Add-LVCoverageResult -Id 'locale-message' -Status 'readable' `
        -Reason 'A non-English provider message is retained as evidence; matching is represented by structured fields.' `
        -Details @{ Locale = [string]$localeFixture.locale; MessageLength = ([string]$localeFixture.record.Message).Length }

    $modulePath = Join-Path $repoRoot 'LogVerdict.psd1'
    Import-Module $modulePath -Force
    $module = Get-Module LogVerdict
    if (-not (Test-LogVerdictDatabase -Quiet)) { throw 'The shipped verdict database failed its coverage gate.' }
    Add-LVCoverageResult -Id 'catalog-and-database' -Status 'readable' `
        -Reason 'The module imported and the shipped database trust gate passed.' `
        -Details @{ RuleCount = @((Get-LogVerdictDatabase).rules).Count }

    $textFixture = $fixtures | Where-Object kind -eq 'textlog' | Select-Object -First 1
    $malformed = $fixtures | Where-Object kind -eq 'offline-evtx' | Select-Object -First 1
    if ([string]$malformed.expectedStatus -ne 'unreadable') {
        throw ("Malformed EVTX fixture '{0}' must declare the expected parser status as unreadable." -f $malformed.id)
    }

    # Exercise the event collector itself. The fixture function is installed only in
    # the module scope for this invocation, then the original command is restored;
    # this keeps the gate deterministic without replacing the production collector.
    $eventFixtureMap = @{}
    foreach ($fixture in $eventFixtures) {
        $eventFixtureMap[[string]$fixture.channel] = @($fixture.record)
    }
    try {
        $eventCollection = & $module {
            param($fixtureMap, $channels)

            $previousFunction = Get-Command Get-WinEvent -CommandType Function -ErrorAction SilentlyContinue
            $previousDefinition = if ($previousFunction) { $previousFunction.ScriptBlock.ToString() } else { $null }
            $script:LVCoverageFixtureEvents = $fixtureMap
            $fixtureReader = {
                [CmdletBinding()]
                param(
                    [hashtable]$FilterHashtable,
                    [int]$MaxEvents,
                    [string]$LogName,
                    [switch]$Oldest
                )

                $null = $Oldest
                $channel = if ($FilterHashtable) { [string]$FilterHashtable.LogName } else { [string]$LogName }
                if (-not $channel -or -not $script:LVCoverageFixtureEvents.ContainsKey($channel)) {
                    throw ("Coverage fixture has no event channel '{0}'." -f $channel)
                }
                $items = @($script:LVCoverageFixtureEvents[$channel])
                if ($MaxEvents -gt 0) { return @($items | Select-Object -First $MaxEvents) }
                return $items
            }
            Set-Item Function:\Get-WinEvent -Value $fixtureReader

            try {
                $records = @(Get-LVEventRecord -Channel $channels -DaysBack 1 -MaxPerChannel 10)
                return [pscustomobject]@{
                    Records  = $records
                    Coverage = @($script:LVEventCoverage)
                }
            } finally {
                Remove-Item Function:\Get-WinEvent -ErrorAction SilentlyContinue
                if ($previousDefinition) {
                    Set-Item Function:\Get-WinEvent -Value ([scriptblock]::Create($previousDefinition))
                }
                Remove-Variable LVCoverageFixtureEvents -Scope Script -ErrorAction SilentlyContinue
            }
        } $eventFixtureMap @($eventFixtures | ForEach-Object { [string]$_.channel })

        foreach ($fixture in $eventFixtures) {
            $observed = @($eventCollection.Coverage | Where-Object { [string]$_.Name -eq [string]$fixture.channel } | Select-Object -Last 1)
            if ($observed.Count -ne 1) {
                throw ("Get-LVEventRecord emitted no coverage record for fixture '{0}'." -f $fixture.id)
            }
            $observedStatus = [string]$observed[0].Status
            $observedRecords = @($eventCollection.Records | Where-Object { [string]$_.Channel -eq [string]$fixture.channel }).Count
            Add-LVCoverageResult -Id ([string]$fixture.id) -Status $observedStatus `
                -Reason 'Get-LVEventRecord observed and normalized the fixture through the scoped Get-WinEvent seam.' `
                -Details @{
                    Locale = [string]$fixture.locale
                    Version = [int]$fixture.record.Version
                    ObservedRecords = $observedRecords
                    CollectorStatus = $observedStatus
                }
            if ($observedStatus -ne 'readable' -or $observedRecords -lt 1) {
                Add-LVCoverageFailure ("Event fixture '{0}' was not readable through Get-LVEventRecord: status={1}, records={2}." -f `
                    $fixture.id, $observedStatus, $observedRecords)
            }
        }
    } catch {
        Add-LVCoverageFailure ("Event collector fixture coverage failed: {0}" -f $_.Exception.Message)
    }

    $fixtureWorkDir = Join-Path ([IO.Path]::GetTempPath()) ('LogVerdictCoverage-{0}' -f [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($fixtureWorkDir) | Out-Null
    try {
        # A real temporary file prevents the gate from proving only that two fixture
        # fields match. The status below comes from Get-LVTextLogRecord's coverage.
        $textPath = Join-Path $fixtureWorkDir 'fixture-text.log'
        Set-Content -LiteralPath $textPath -Value ([string]$textFixture.target.Line) -Encoding UTF8
        $textTarget = [pscustomobject]@{
            Name = [string]$textFixture.target.Name
            Path = $textPath
            Pattern = [string]$textFixture.target.Pattern
            Area = [string]$textFixture.target.Area
            Hint = [string]$textFixture.target.Hint
        }
        try {
            $textCollection = & $module {
                param($target)
                $records = @(Get-LVTextLogRecord -DaysBack 1 -Target @($target))
                [pscustomobject]@{ Records = $records; Coverage = @($script:LVTextLogCoverage) }
            } $textTarget
            $observed = @($textCollection.Coverage | Where-Object { [string]$_.Name -eq [string]$textFixture.target.Name } | Select-Object -Last 1)
            if ($observed.Count -ne 1) { throw 'Get-LVTextLogRecord emitted no fixture coverage record.' }
            $observedStatus = [string]$observed[0].Status
            $observedRecords = @($textCollection.Records).Count
            Add-LVCoverageResult -Id ([string]$textFixture.id) -Status $observedStatus `
                -Reason 'Get-LVTextLogRecord parsed a temporary fixture file and supplied the observed coverage status.' `
                -Details @{
                    Locale = [string]$textFixture.locale
                    Name = [string]$textFixture.target.Name
                    ObservedRecords = $observedRecords
                    CollectorStatus = $observedStatus
                }
            if ($observedStatus -ne 'readable' -or $observedRecords -lt 1) {
                Add-LVCoverageFailure ("Text-log fixture '{0}' was not readable through Get-LVTextLogRecord: status={1}, records={2}." -f `
                    $textFixture.id, $observedStatus, $observedRecords)
            }
        } catch {
            Add-LVCoverageFailure ("Text-log collector fixture coverage failed: {0}" -f $_.Exception.Message)
        }

        # Feed malformed bytes to the offline parser and retain the status it emits;
        # expectedStatus is metadata for the fixture, never the source of the result.
        $malformedPath = Join-Path $fixtureWorkDir ([string]$malformed.name)
        [IO.File]::WriteAllText($malformedPath, 'not an EVTX file')
        try {
            $offlineResult = & $module {
                param($path)
                Invoke-LVOfflineScan -EvidencePath $path -DaysBack 1 -SkipTextLogs -SkipReliability
            } $malformedPath
            $observed = @($offlineResult.Coverage | Where-Object {
                [string]$_.Source -eq 'offline-evtx' -and [string]$_.Name -eq [string]$malformed.name
            } | Select-Object -First 1)
            if ($observed.Count -ne 1) { throw 'Invoke-LVOfflineScan emitted no malformed-EVTX coverage record.' }
            $observedStatus = [string]$observed[0].Status
            Add-LVCoverageResult -Id ([string]$malformed.id) -Status $observedStatus `
                -Reason 'Invoke-LVOfflineScan parsed a temporary malformed EVTX source and supplied the observed status.' `
                -Details @{
                    ExpectedStatus = [string]$malformed.expectedStatus
                    ObservedStatus = $observedStatus
                    ObservedRecords = [int]$observed[0].ObservedRecords
                }
            if ($observedStatus -ne 'unreadable') {
                Add-LVCoverageFailure ("Malformed EVTX fixture '{0}' produced unexpected observed status '{1}'." -f `
                    $malformed.id, $observedStatus)
            }
        } catch {
            Add-LVCoverageFailure ("Offline EVTX collector fixture coverage failed: {0}" -f $_.Exception.Message)
        }
    } finally {
        if (Test-Path -LiteralPath $fixtureWorkDir) { [IO.Directory]::Delete($fixtureWorkDir, $true) }
    }

    $elevationFixture = $fixtures | Where-Object kind -eq 'elevation' | Select-Object -First 1
    try {
        $isElevated = [bool](& $module { Test-LVElevated })
        Add-LVCoverageResult -Id $elevationFixture.id -Status 'readable' `
            -Reason 'The current Windows token elevation state was observed; elevated is not required for this gate.' `
            -Details @{ Elevated = $isElevated; OSDependent = [bool]$elevationFixture.osDependent }
    } catch {
        Add-LVCoverageFailure ("Elevation state could not be observed: {0}" -f $_.Exception.Message)
    }

    $guiFixture = $fixtures | Where-Object kind -eq 'gui' | Select-Object -First 1
    try {
        $xaml = [string](& $module { Get-LVGuiXaml })
        [xml]$null = $xaml
        $missing = @($guiFixture.requiredNames | Where-Object { $xaml -notmatch ('x:Name="{0}"' -f [regex]::Escape([string]$_)) })
        if ($missing.Count -gt 0) { throw ('GUI markup is missing required names: {0}' -f ($missing -join ', ')) }
        Add-LVCoverageResult -Id 'gui-markup' -Status 'readable' `
            -Reason 'GUI markup parsed and representative automation targets are present.' `
            -Details @{ RequiredNameCount = @($guiFixture.requiredNames).Count }
    } catch {
        Add-LVCoverageFailure ("GUI markup coverage failed: {0}" -f $_.Exception.Message)
    }

    $previousHighContrast = $env:LOGVERDICT_TEST_HIGH_CONTRAST
    try {
        $env:LOGVERDICT_TEST_HIGH_CONTRAST = [string]$guiFixture.highContrastOverride
        $highContrast = [bool](& $module { Test-LVGuiHighContrast })
        if (-not $highContrast) { throw 'The high-contrast test override was not observed.' }
        Add-LVCoverageResult -Id 'gui-high-contrast' -Status 'readable' `
            -Reason 'The high-contrast theme path was exercised through the non-global test override.'
    } catch {
        Add-LVCoverageFailure ("High-contrast coverage failed: {0}" -f $_.Exception.Message)
    } finally {
        if ($null -eq $previousHighContrast) { Remove-Item Env:LOGVERDICT_TEST_HIGH_CONTRAST -ErrorAction SilentlyContinue }
        else { $env:LOGVERDICT_TEST_HIGH_CONTRAST = $previousHighContrast }
    }

    $apartment = [System.Threading.Thread]::CurrentThread.GetApartmentState()
    if ($apartment -ne [System.Threading.ApartmentState]::STA) {
        Add-LVCoverageFailure 'The coverage gate must run in an STA so the accessibility/UIA suite is not silently skipped.'
    } else {
        Add-LVCoverageResult -Id 'sta-runtime' -Status 'readable' `
            -Reason 'The selected runtime executed the gate in a single-threaded apartment.'
    }

    $displayFixture = $fixtures | Where-Object kind -eq 'display' | Select-Object -First 1
    if ($DisplayEvidencePath) {
        if (-not (Test-Path -LiteralPath $DisplayEvidencePath -PathType Leaf)) {
            Add-LVCoverageFailure ("GUI display evidence was not found: {0}" -f $DisplayEvidencePath)
        } else {
            try {
                $displayEvidence = Get-Content -LiteralPath $DisplayEvidencePath -Raw -Encoding UTF8 | ConvertFrom-Json
                if ([int]$displayEvidence.schemaVersion -ne 1 -or -not $displayEvidence.passed -or
                    -not $displayEvidence.placement.fullyInsideWorkingArea) {
                    throw 'GUI evidence did not report a passing launch or in-bounds placement.'
                }
                Add-LVCoverageResult -Id $displayFixture.id -Status 'readable' `
                    -Reason 'The packaged GUI launch smoke test reported a real window inside its working area.' `
                    -Details @{ EvidencePath = $DisplayEvidencePath; ProcessId = $displayEvidence.processId; Screen = $displayEvidence.placement.screen }
            } catch {
                Add-LVCoverageFailure ("GUI display evidence failed validation: {0}" -f $_.Exception.Message)
            }
        }
    } elseif ($env:LOGVERDICT_ISOLATED_DISPLAY -eq '1') {
        Add-LVCoverageResult -Id $displayFixture.id -Status 'readable' `
            -Reason 'An explicit isolated-display runner reported availability.'
    } else {
        Add-LVCoverageResult -Id $displayFixture.id -Status 'not-observed' `
            -Reason ([string]$displayFixture.expected) `
            -Details @{ OSDependent = [bool]$displayFixture.osDependent }
    }
} catch {
    Add-LVCoverageFailure $_.Exception.Message
}

$document = [ordered]@{
    SchemaVersion = 1
    Generated = (Get-Date).ToUniversalTime().ToString('o')
    Runtime = $PSVersionTable.PSVersion.ToString()
    Edition = $PSVersionTable.PSEdition
    Apartment = [System.Threading.Thread]::CurrentThread.GetApartmentState().ToString()
    Passed = ($failures.Count -eq 0)
    Failures = @($failures.ToArray())
    Coverage = @($coverage.ToArray())
}
$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$document | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8

Write-Output ('Coverage gate: {0} ({1} records, runtime {2}, {3})' -f $(if ($document.Passed) { 'passed' } else { 'failed' }), $coverage.Count, $document.Runtime, $document.Apartment)
foreach ($entry in $coverage.ToArray()) {
    Write-Output ('  {0}: {1} - {2}' -f $entry.Id, $entry.Status, $entry.Reason)
}
Write-Output ('Coverage report: {0}' -f $OutputPath)
if (-not $document.Passed) { exit 1 }
