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

    $textFixture = $fixtures | Where-Object kind -eq 'textlog' | Select-Object -First 1
    if (-not [regex]::IsMatch([string]$textFixture.target.Line, [string]$textFixture.target.Pattern)) {
        throw ("Text fixture '{0}' does not match its collector pattern." -f $textFixture.id)
    }
    Add-LVCoverageResult -Id 'textlog-fixture' -Status 'readable' `
        -Reason 'The representative text-log line matches the declared collector pattern.' `
        -Details @{ Locale = [string]$textFixture.locale; Name = [string]$textFixture.target.Name }

    $malformed = $fixtures | Where-Object kind -eq 'offline-evtx' | Select-Object -First 1
    if ([string]$malformed.expectedStatus -ne 'unreadable') {
        throw ("Malformed EVTX fixture '{0}' must expect unreadable status." -f $malformed.id)
    }
    Add-LVCoverageResult -Id 'offline-evtx-malformed' -Status 'unreadable' `
        -Reason ([string]$malformed.reason) -Details @{ ExpectedStatus = [string]$malformed.expectedStatus }

    $modulePath = Join-Path $repoRoot 'LogVerdict.psd1'
    Import-Module $modulePath -Force
    $module = Get-Module LogVerdict
    if (-not (Test-LogVerdictDatabase -Quiet)) { throw 'The shipped verdict database failed its coverage gate.' }
    Add-LVCoverageResult -Id 'catalog-and-database' -Status 'readable' `
        -Reason 'The module imported and the shipped database trust gate passed.' `
        -Details @{ RuleCount = @((Get-LogVerdictDatabase).rules).Count }

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
