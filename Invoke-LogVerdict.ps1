<#
    .SYNOPSIS
    LogVerdict - scan this PC's logs and rule on what is actually wrong, in plain English.

    .DESCRIPTION
    One-shot entry point. Imports the module beside it, runs a scan, prints the
    findings and writes text / JSON / HTML reports.

    Read-only: nothing on the machine is modified beyond the report folder.

    .PARAMETER DaysBack
    How far back to look. Default 30.

    .PARAMETER AllChannels
    Sweep every populated event channel instead of just System and Application.

    .PARAMETER IncludeBenign
    Show signatures the database rules as harmless. Off by default.

    .PARAMETER OutputDir
    Report destination. Defaults to a timestamped folder on the Desktop.

    .PARAMETER EvidencePath
    Analyze a LogVerdict evidence bundle or JSON report without reading this PC.

    .PARAMETER NoReport
    Console only; write nothing to disk.

    .EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-LogVerdict.ps1

    .EXAMPLE
    .\Invoke-LogVerdict.ps1 -DaysBack 7 -AllChannels

    .NOTES
    Runs without admin. Elevation unlocks the Security channel and some text logs;
    a non-elevated run states exactly what it could not read.

    Exit codes: 0 nothing notable, 1 investigate/unknown, 2 actionable, 3 critical,
    4 the scan itself failed.
#>
[CmdletBinding()]
param(
    [int]$DaysBack = 30,
    [string[]]$Channel,
    [switch]$AllChannels,
    [switch]$SkipTextLogs,
    [switch]$SkipReliability,
    [switch]$IncludeBenign,
    [string]$OutputDir,
    [switch]$NoReport,
    [switch]$Redact,
    [switch]$IncludeEvidence,
    [string]$EvidencePath,
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

try {
    $scanArgs = @{
        IncludeBenign   = $IncludeBenign
        SkipTextLogs    = $SkipTextLogs
        SkipReliability = $SkipReliability
        AllChannels     = $AllChannels
    }
    if (-not $EvidencePath -or $PSBoundParameters.ContainsKey('DaysBack')) { $scanArgs['DaysBack'] = $DaysBack }
    if ($EvidencePath) { $scanArgs['EvidencePath'] = $EvidencePath }
    if ($Channel) {
        # powershell.exe -File hands "-Channel System,Application" over as ONE string
        # rather than binding it to the [string[]] parameter, so split it back out.
        $scanArgs['Channel'] = @($Channel | ForEach-Object { $_ -split ',' } | Where-Object { $_ -ne '' } | ForEach-Object { $_.Trim() })
    }

    $result = Invoke-LogVerdictScan @scanArgs
    Show-LogVerdictReport -Result $result

    if (-not $NoReport) {
        $exportArgs = @{ Result = $result; Redact = $Redact; IncludeEvidence = $IncludeEvidence }
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
