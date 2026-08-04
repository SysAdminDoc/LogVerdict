<#
    .SYNOPSIS
    LogVerdict - scan this PC's logs and rule on what is actually wrong, in plain English.

    .DESCRIPTION
    One-shot entry point. Imports the module beside it, runs a scan, prints the
    findings and writes text / JSON / HTML reports.

    Read-only: nothing on the machine is modified beyond the report folder.

    .PARAMETER DaysBack
    How far back to look, from 1 through 3650 days. Default 30.

    .PARAMETER AllChannels
    Sweep every populated event channel instead of just System and Application.

    .PARAMETER DiagnosticChannels
    Scan System and Application plus six focused operational channels for storage,
    code integrity, device setup, packaged apps, memory pressure, and boot security.

    .PARAMETER PerformanceTelemetry
    Opt in to content-free source timing and bounded-count records. Telemetry contains
    no messages, paths, identifiers or signature data.

    .PARAMETER IncludeBenign
    Show signatures the database rules as harmless. Off by default.

    .PARAMETER IncludeLowConfidence
    Show curated low-confidence rulings. Off by default; unknown signatures remain visible.

    .PARAMETER SuppressionPath
    Optional operator-owned suppression expectation JSON. Defaults to the per-user
    LogVerdict suppression file when present.

    .PARAMETER SuppressedOnly
    Print the validated suppression set without scanning logs.

    .PARAMETER OutputDir
    Report destination. Defaults to a timestamped folder on the Desktop.

    .PARAMETER EvidencePath
    Analyze a LogVerdict evidence bundle, JSON report, one .evtx file, or an .evtx
    directory without reading this PC.

    .PARAMETER ExplainUnknown
    Ask a local Ollama model for separately labelled, non-remedial draft explanations
    of unknown signatures only. Off by default.

    .PARAMETER PromoteToRule
    Write safe model candidates to the local verdict database as inactive review
    drafts. Implies ExplainUnknown; a human must enable each rule deliberately.

    .PARAMETER LocalRulePath
    Override the local draft-rule destination.

    .PARAMETER HistoryPath
    Opt-in local JSON history for bounded per-signature trend analysis. It never changes
    a curated verdict and is not written during offline evidence analysis.

    .PARAMETER HistoryWindowDays
    Number of days of prior local history eligible for comparison. Default 30.

    .PARAMETER AdvisoryPath
    Optional offline dependency/tool advisory cache JSON.

    .PARAMETER AdvisoryPackage
    Package name to match in the optional advisory cache.

    .PARAMETER AdvisoryVersion
    Package version to test against the optional advisory cache's affected ranges.

    .PARAMETER CaseProfilePath
    Optional validated case profile to attach for collection and handoff attribution.

    .PARAMETER ProviderPath
    Optional local provider manifest or directory. Provider execution is opt-in and
    requires -AllowUntrustedProvider.

    .PARAMETER AllowUntrustedProvider
    Explicitly approve the pinned provider entrypoints named by ProviderPath.

    .PARAMETER MaxCollectionBytes
    Shared byte budget for live and offline collection. Incomplete sources are reported
    as truncated rather than treated as clean.

    .PARAMETER MaxCollectionRecords
    Shared normalized-record budget for collection.

    .PARAMETER MaxCollectionSeconds
    Shared elapsed-time budget for collection.

    .PARAMETER NoReport
    Console only; write nothing to disk.

    .PARAMETER Intune
    Emit a UTF-8, no-BOM remediation digest under 2,048 characters and exit 1 for
    any non-benign verdict, or 0 when the result is benign. Reports are not written.

    .PARAMETER Redact
    Mask captured identifiers in written reports and, when model explanations are
    enabled, in the prompt-specific finding copy sent to the local Ollama endpoint.

    .PARAMETER AllowRawEvidence
    Explicitly authorize a forensic raw evidence bundle when -IncludeEvidence is used
    without -Redact. Raw bundles are never described as sanitized.

    .EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-LogVerdict.ps1

    .EXAMPLE
    .\Invoke-LogVerdict.ps1 -DaysBack 7 -AllChannels

    .EXAMPLE
    .\Invoke-LogVerdict.ps1 -DaysBack 7 -DiagnosticChannels

    .NOTES
    Runs without admin. Elevation unlocks the Security channel and some text logs;
    a non-elevated run states exactly what it could not read.

    Exit codes: 0 nothing notable, 1 investigate/unknown, 2 actionable, 3 critical,
    4 the scan itself failed.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 3650)][int]$DaysBack = 30,
    [string[]]$Channel,
    [switch]$AllChannels,
    [switch]$DiagnosticChannels,
    [switch]$SkipTextLogs,
    [switch]$SkipReliability,
    [switch]$PerformanceTelemetry,
    [switch]$IncludeBenign,
    [switch]$IncludeLowConfidence,
    [string]$SuppressionPath,
    [switch]$SuppressedOnly,
    [string]$OutputDir,
    [switch]$NoReport,
    [switch]$Intune,
    [switch]$Redact,
    [switch]$IncludeEvidence,
    [switch]$AllowRawEvidence,
    [ValidateSet('Text', 'Json', 'Csv', 'Html', 'Markdown', 'TicketText', 'TicketHtml', 'All')][string[]]$Format = @('All'),
    [string]$EvidencePath,
    [switch]$ExplainUnknown,
    [string]$OllamaModel = 'llama3.2',
    [string]$OllamaEndpoint = 'http://127.0.0.1:11434',
    [switch]$PromoteToRule,
    [string]$LocalRulePath,
    [string]$HistoryPath,
    [ValidateRange(1, 3650)][int]$HistoryWindowDays = 30,
    [string]$AdvisoryPath,
    [string]$AdvisoryPackage,
    [string]$AdvisoryVersion,
    [string]$CaseProfilePath,
    [string[]]$ProviderPath,
    [switch]$AllowUntrustedProvider,
    [ValidateRange(1, 8589934592)][long]$MaxCollectionBytes = 536870912,
    [ValidateRange(1, 10000000)][int]$MaxCollectionRecords = 100000,
    [ValidateRange(1, 86400)][int]$MaxCollectionSeconds = 600,
    [switch]$Pause,
    [switch]$NoPause
)

$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'LogVerdict.psd1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    Write-Host ('[x] LogVerdict.psd1 not found beside this script ({0}).' -f $PSScriptRoot) -ForegroundColor Red
    exit 4
}

Import-Module $modulePath -Force -ErrorAction Stop

function Test-LVLaunchedInteractively {
    <#
        .SYNOPSIS
        Whether this process owns the console window it is printing to.

        .DESCRIPTION
        A double-clicked executable gets a console window of its own, which Windows
        destroys the instant the process exits. The tool then appears never to have run
        at all, even though it worked and wrote its reports.

        The check is deliberately conservative in the other direction: pausing inside a
        script, a scheduled task or a CI job would hang it forever. So it requires BOTH
        that output is attached to a real console AND that the parent is Explorer.
    #>
    if ([Console]::IsOutputRedirected -or [Console]::IsInputRedirected) { return $false }

    try {
        $parentId = (Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $PID) -ErrorAction Stop).ParentProcessId
        if (-not $parentId) { return $false }
        return ((Get-Process -Id $parentId -ErrorAction Stop).ProcessName -eq 'explorer')
    } catch {
        # Parent may already be gone, or CIM may be unavailable. Not knowing is a
        # reason to keep going, never a reason to block on a keypress.
        return $false
    }
}

if ($SuppressedOnly) {
    try {
        $set = Get-LogVerdictSuppression -Path $SuppressionPath
        $set.entries | ConvertTo-Json -Depth 20
        exit 0
    } catch {
        Write-Host ('[x] Suppression set failed validation: {0}' -f $_.Exception.Message) -ForegroundColor Red
        exit 4
    }
}

try {
    $scanArgs = @{
        IncludeBenign   = $IncludeBenign
        SkipTextLogs    = $SkipTextLogs
        SkipReliability = $SkipReliability
        PerformanceTelemetry = $PerformanceTelemetry
        AllChannels     = $AllChannels
        DiagnosticChannels = $DiagnosticChannels
        IncludeLowConfidence = $IncludeLowConfidence
        SuppressionPath = $SuppressionPath
        Redact          = $Redact
        ExplainUnknown  = $ExplainUnknown
        OllamaModel     = $OllamaModel
        OllamaEndpoint  = $OllamaEndpoint
        PromoteToRule   = $PromoteToRule
        LocalRulePath   = $LocalRulePath
        HistoryPath     = $HistoryPath
        HistoryWindowDays = $HistoryWindowDays
        AdvisoryPath    = $AdvisoryPath
        AdvisoryPackage = $AdvisoryPackage
        AdvisoryVersion = $AdvisoryVersion
        CaseProfilePath = $CaseProfilePath
        ProviderPath = $ProviderPath
        AllowUntrustedProvider = $AllowUntrustedProvider
        MaxCollectionBytes = $MaxCollectionBytes
        MaxCollectionRecords = $MaxCollectionRecords
        MaxCollectionSeconds = $MaxCollectionSeconds
    }
    if (-not $EvidencePath -or $PSBoundParameters.ContainsKey('DaysBack')) { $scanArgs['DaysBack'] = $DaysBack }
    if ($EvidencePath) { $scanArgs['EvidencePath'] = $EvidencePath }
    if ($Channel) {
        # powershell.exe -File hands "-Channel System,Application" over as ONE string
        # rather than binding it to the [string[]] parameter, so split it back out.
        $scanArgs['Channel'] = @($Channel | ForEach-Object { $_ -split ',' } | Where-Object { $_ -ne '' } | ForEach-Object { $_.Trim() })
    }

    if ($Intune) {
        # Intune consumes stdout as the remediation signal. Suppress the normal
        # informational host stream and emit only the bounded digest below.
        $result = Invoke-LogVerdictScan @scanArgs 6>$null
        $digest = Get-LogVerdictIntuneDigest -Result $result
        try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false) } catch { }
        [Console]::Out.WriteLine($digest.Text)
        exit $digest.ExitCode
    }

    $result = Invoke-LogVerdictScan @scanArgs
    Show-LogVerdictReport -Result $result

    if (-not $NoReport) {
        $exportArgs = @{ Result = $result; Redact = $Redact; IncludeEvidence = $IncludeEvidence; AllowRawEvidence = $AllowRawEvidence; Format = $Format }
        if ($OutputDir) { $exportArgs['OutputDir'] = $OutputDir }
        $out = Export-LogVerdictReport @exportArgs
        Write-Host ''
        Write-Host '  Full report saved to:' -ForegroundColor Cyan
        Write-Host ('    {0}' -f $out.OutputDir) -ForegroundColor White
        Write-Host '  Open LogVerdict-Report.html in that folder for the readable version.' -ForegroundColor DarkGray
    }
} catch {
    Write-Host ('[x] Scan failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    if (-not $NoPause -and (Test-LVLaunchedInteractively)) {
        Write-Host ''
        Write-Host 'Press Enter to close...' -ForegroundColor Yellow
        $null = Read-Host
    }
    exit 4
}

# A double-clicked console app loses its window the instant it exits, so the whole
# run looks like it never happened. Hold the window open when this process owns it -
# but never when output is redirected or the parent is not Explorer, because pausing
# inside a script or a scheduled task would hang it forever.
if ($Pause -or (-not $NoPause -and (Test-LVLaunchedInteractively))) {
    Write-Host ''
    Write-Host 'Press Enter to close...' -ForegroundColor Yellow
    $null = Read-Host
}

exit $result.ExitCode
