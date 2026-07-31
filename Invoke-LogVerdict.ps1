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
    [switch]$IncludeBenign,
    [string]$OutputDir,
    [switch]$NoReport
)

$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'LogVerdict.psd1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    Write-Host ('[x] LogVerdict.psd1 not found beside this script ({0}).' -f $PSScriptRoot) -ForegroundColor Red
    exit 4
}

Import-Module $modulePath -Force -ErrorAction Stop

try {
    $scanArgs = @{
        DaysBack      = $DaysBack
        IncludeBenign = $IncludeBenign
        SkipTextLogs  = $SkipTextLogs
        AllChannels   = $AllChannels
    }
    if ($Channel) { $scanArgs['Channel'] = $Channel }

    $result = Invoke-LogVerdictScan @scanArgs
    Show-LogVerdictReport -Result $result

    if (-not $NoReport) {
        $exportArgs = @{ Result = $result }
        if ($OutputDir) { $exportArgs['OutputDir'] = $OutputDir }
        $out = Export-LogVerdictReport @exportArgs
        Write-Host ''
        Write-Host ('Reports: {0}' -f $out.OutputDir) -ForegroundColor Cyan
    }
} catch {
    Write-Host ('[x] Scan failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    exit 4
}

exit $result.ExitCode
