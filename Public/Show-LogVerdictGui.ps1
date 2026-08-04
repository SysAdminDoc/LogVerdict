function Show-LogVerdictGui {
    <#
        .SYNOPSIS
        Open the LogVerdict window: scan this PC's logs and read the rulings.

        .DESCRIPTION
        A front end over Invoke-LogVerdictScan, not a second implementation of it. The
        scan runs unchanged on a background runspace and this window renders what comes
        back, so the GUI and the console tool can never disagree about a verdict.

        Diagnostic sources are read-only. The window remembers its scan options and
        size under the current user's local app-data folder. Save report writes to a
        folder on the Desktop only when asked.

        .PARAMETER DaysBack
        Explicitly pre-fills the look-back window. Without it, the last saved value is
        used, falling back to 30 on a first launch.

        .PARAMETER AutoScan
        Start scanning as soon as the window opens instead of waiting for Run scan.

        .PARAMETER PassThru
        After the window closes, return the last scan result object.

        .PARAMETER AdvisoryPath
        Optional offline dependency/tool advisory cache JSON.

        .PARAMETER AdvisoryPackage
        Package name to match in the optional advisory cache.

        .PARAMETER AdvisoryVersion
        Package version to test against the optional advisory cache's affected ranges.

        .PARAMETER CaseProfilePath
        Optional validated case profile to attach for collection and handoff attribution.

        .PARAMETER ScreenshotPath
        Optional explicit documentation screenshot path. It is accepted only together
        with ScreenshotDirectory and must remain inside that caller-owned directory.

        .PARAMETER ScreenshotDirectory
        Caller-owned directory that contains ScreenshotPath when documentation capture
        is explicitly requested.

        .EXAMPLE
        Show-LogVerdictGui

        .EXAMPLE
        Show-LogVerdictGui -DaysBack 7 -AutoScan

        .NOTES
        WPF requires a single-threaded apartment. Windows PowerShell 5.1 is STA by
        default; pwsh is not, so LogVerdict-GUI.ps1 relaunches itself when needed.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = 'WPF routed-event delegates have a fixed two-parameter signature. A handler must declare both even when it reads only one, so an unused one here is the contract, not an oversight.')]
    [CmdletBinding()]
    param(
        [ValidateRange(1, 3650)][int]$DaysBack = 30,
        [string]$AdvisoryPath,
        [string]$AdvisoryPackage,
        [string]$AdvisoryVersion,
        [string]$CaseProfilePath,
        [string]$ScreenshotPath,
        [string]$ScreenshotDirectory,
        [switch]$AutoScan,
        [switch]$PassThru
    )

    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        throw 'The LogVerdict window needs a single-threaded apartment. Start PowerShell with -STA, or run LogVerdict-GUI.ps1 which handles this for you.'
    }

    $documentationScreenshotPath = Resolve-LVGuiScreenshotPath -ScreenshotPath $ScreenshotPath -ScreenshotDirectory $ScreenshotDirectory
    $daysBackExplicit = [bool]$PSBoundParameters.ContainsKey('DaysBack')
    $context = New-LVGuiSession -DaysBack $DaysBack -DaysBackExplicit $daysBackExplicit `
        -DocumentationScreenshotPath $documentationScreenshotPath
    $context.Actions = New-LVGuiActions -Context $context
    Initialize-LVGuiControls -Context $context
    Register-LVGuiOptionHandlers -Context $context
    Register-LVGuiInteractionHandlers -Context $context
    Register-LVGuiScanHandlers -Context $context -AdvisoryPath $AdvisoryPath -AdvisoryPackage $AdvisoryPackage `
        -AdvisoryVersion $AdvisoryVersion -CaseProfilePath $CaseProfilePath
    Register-LVGuiPumpHandlers -Context $context -AutoScan:$AutoScan

    & $context.Actions.ShowPage 'Overview'
    $null = $context.Window.ShowDialog()

    if ($PassThru) { return $context.State.Result }
}
