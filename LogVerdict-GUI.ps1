<#
    .SYNOPSIS
    LogVerdict - the window. Scan this PC's logs and read the rulings.

    .DESCRIPTION
    Opens the LogVerdict front end. Imports the module beside it, then hands over to
    Show-LogVerdictGui. The scan itself is the same one Invoke-LogVerdict.ps1 runs.

    Diagnostic sources are read-only. The window remembers its scan options and size
    under the current user's local app-data folder; Save report writes only when asked.

    .PARAMETER DaysBack
    Explicitly pre-fills the look-back window. Without it, the last saved value is
    used, falling back to 30 on a first launch.

    .PARAMETER AutoScan
    Start scanning as soon as the window appears.

    .PARAMETER AdvisoryPath
    Optional offline dependency/tool advisory cache JSON.

    .PARAMETER AdvisoryPackage
    Package name to match in the optional advisory cache.

    .PARAMETER AdvisoryVersion
    Package version to test against the optional advisory cache's affected ranges.

    .PARAMETER CaseProfilePath
    Optional validated case profile to attach for collection and handoff attribution.

    .PARAMETER ScreenshotPath
    Optional explicit documentation screenshot path used only by the release smoke test.

    .PARAMETER ScreenshotDirectory
    Caller-owned directory that contains ScreenshotPath.

    .EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\LogVerdict-GUI.ps1

    .EXAMPLE
    .\LogVerdict-GUI.ps1 -DaysBack 7 -AutoScan

    .NOTES
    Runs without admin. Elevation unlocks the Security channel and some text logs;
    the window says plainly what it could not read, and offers to restart elevated.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 3650)][int]$DaysBack = 30,
    [string]$AdvisoryPath,
    [string]$AdvisoryPackage,
    [string]$AdvisoryVersion,
    [string]$CaseProfilePath,
    [string]$ScreenshotPath,
    [string]$ScreenshotDirectory,
    [switch]$AutoScan
)

$ErrorActionPreference = 'Stop'

# WPF will not start on a multi-threaded apartment. Windows PowerShell is STA by
# default but pwsh is MTA, and there is no way to change a thread's apartment after
# it starts - so relaunch through powershell.exe -STA carrying the same arguments.
# The compiled build never reaches this: it is linked STA and the build strips
# everything above the module import.
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $relaunch = @(
        '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $PSCommandPath)
    )
    if ($PSBoundParameters.ContainsKey('DaysBack')) { $relaunch += @('-DaysBack', $DaysBack) }
    if ($AdvisoryPath) { $relaunch += @('-AdvisoryPath', $AdvisoryPath) }
    if ($AdvisoryPackage) { $relaunch += @('-AdvisoryPackage', $AdvisoryPackage) }
    if ($AdvisoryVersion) { $relaunch += @('-AdvisoryVersion', $AdvisoryVersion) }
    if ($CaseProfilePath) { $relaunch += @('-CaseProfilePath', $CaseProfilePath) }
    if ($ScreenshotPath) { $relaunch += @('-ScreenshotPath', $ScreenshotPath) }
    if ($ScreenshotDirectory) { $relaunch += @('-ScreenshotDirectory', $ScreenshotDirectory) }
    if ($AutoScan) { $relaunch += '-AutoScan' }
    Start-Process -FilePath 'powershell.exe' -ArgumentList $relaunch
    exit 0
}

$modulePath = Join-Path $PSScriptRoot 'LogVerdict.psd1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    Write-Host ('[x] LogVerdict.psd1 not found beside this script ({0}).' -f $PSScriptRoot) -ForegroundColor Red
    exit 4
}

Import-Module $modulePath -Force -ErrorAction Stop

try {
    $guiArgs = @{ AutoScan = $AutoScan }
    if ($PSBoundParameters.ContainsKey('DaysBack')) { $guiArgs['DaysBack'] = $DaysBack }
    if ($AdvisoryPath) { $guiArgs['AdvisoryPath'] = $AdvisoryPath }
    if ($AdvisoryPackage) { $guiArgs['AdvisoryPackage'] = $AdvisoryPackage }
    if ($AdvisoryVersion) { $guiArgs['AdvisoryVersion'] = $AdvisoryVersion }
    if ($CaseProfilePath) { $guiArgs['CaseProfilePath'] = $CaseProfilePath }
    if ($ScreenshotPath) { $guiArgs['ScreenshotPath'] = $ScreenshotPath }
    if ($ScreenshotDirectory) { $guiArgs['ScreenshotDirectory'] = $ScreenshotDirectory }
    Show-LogVerdictGui @guiArgs
    exit 0
} catch {
    # A GUI that dies before it can paint has nowhere to show an error, so the detail
    # goes to a crash log first and a message box second. Never fail silently: a
    # window that simply does not appear is the least debuggable outcome there is.
    $detail = @(
        ('LogVerdict failed to start at {0:yyyy-MM-dd HH:mm:ss}' -f (Get-Date)),
        ('Message : {0}' -f $_.Exception.Message),
        ('Type    : {0}' -f $_.Exception.GetType().FullName),
        '',
        $_.ScriptStackTrace
    ) -join [Environment]::NewLine

    $crashPath = $null
    try {
        $crashDir = Join-Path $env:LOCALAPPDATA 'LogVerdict'
        if (-not (Test-Path -LiteralPath $crashDir)) {
            New-Item -ItemType Directory -Path $crashDir -Force | Out-Null
        }
        $crashPath = Join-Path $crashDir ('crash-{0:yyyyMMdd-HHmmss}.log' -f (Get-Date))
        [System.IO.File]::WriteAllText($crashPath, $detail, (New-Object System.Text.UTF8Encoding($false)))
    } catch {
        Write-Host ('[x] Could not write a crash log: {0}' -f $_.Exception.Message) -ForegroundColor Red
    }

    $shown = $detail
    if ($crashPath) { $shown = $detail + [Environment]::NewLine + [Environment]::NewLine + ('Saved to {0}' -f $crashPath) }

    try {
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
        [void][System.Windows.MessageBox]::Show($shown, 'LogVerdict', 'OK', 'Error')
    } catch {
        Write-Host $shown -ForegroundColor Red
    }

    exit 4
}
