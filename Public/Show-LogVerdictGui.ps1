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
        [switch]$AutoScan,
        [switch]$PassThru
    )

    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        throw 'The LogVerdict window needs a single-threaded apartment. Start PowerShell with -STA, or run LogVerdict-GUI.ps1 which handles this for you.'
    }

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

    $savedSettings = Get-LVGuiSetting
    $initialDays = $DaysBack
    if (-not $PSBoundParameters.ContainsKey('DaysBack') -and $savedSettings) {
        $initialDays = $savedSettings.DaysBack
    }
    $initialAllChannels = $(if ($savedSettings) { $savedSettings.AllChannels } else { $false })
    $initialSkipText = $(if ($savedSettings) { $savedSettings.SkipTextLogs } else { $false })
    $initialIncludeBenign = $(if ($savedSettings) { $savedSettings.IncludeBenign } else { $false })

    $window = [Windows.Markup.XamlReader]::Parse((Get-LVGuiXaml))
    if ($savedSettings) {
        $window.Width = $savedSettings.WindowWidth
        $window.Height = $savedSettings.WindowHeight
    }

    # Resolve every named element once. A missing name means the markup and this file
    # have drifted apart, and saying so here beats a null reference three interactions
    # deep into a scan.
    $ui = @{}
    foreach ($name in $script:LVGuiElement) {
        $element = $window.FindName($name)
        if ($null -eq $element) {
            throw ("LogVerdict markup is missing the element '{0}'." -f $name)
        }
        $ui[$name] = $element
    }

    $themeSnapshot = Get-LVGuiThemeSnapshot -Window $window
    $null = Sync-LVGuiTheme -Window $window -Snapshot $themeSnapshot

    # All mutable state lives on one object. Assigning to a plain variable inside an
    # event handler would create a handler-local copy and silently lose the write;
    # mutating a hashtable's keys does not have that problem.
    $state = @{
        Result     = $null
        Rows       = $null
        View       = $null
        Job        = $null
        Timer      = $null
        Sink       = $null
        Search     = ''
        ReportDir  = $null
        HtmlPath   = $null
        SortKey    = $null
        SortAsc    = $false
        Chips      = @{}
        Scanning   = $false
        CurrentPage = 'Overview'
        ActivityLines = (New-Object System.Collections.Generic.List[string])
    }
    foreach ($v in $script:LVVerdictDisplayOrder) { $state.Chips[$v] = $true }

    $chipControl = @{
        'critical'      = $ui.FltCritical
        'actionable'    = $ui.FltActionable
        'investigate'   = $ui.FltInvestigate
        'unknown'       = $ui.FltUnknown
        'informational' = $ui.FltInformational
        'benign'        = $ui.FltBenign
    }

    $pageControl = @{
        'Overview' = $ui.PageOverview
        'Findings' = $ui.PageFindings
        'Coverage' = $ui.PageCoverage
        'Activity' = $ui.PageActivity
    }
    $navControl = @{
        'Overview' = $ui.NavOverview
        'Findings' = $ui.NavFindings
        'Coverage' = $ui.NavCoverage
        'Activity' = $ui.NavActivity
    }

    # ---------------------------------------------------------------- helpers ----

    $setStatus = {
        param([string]$Message)
        $ui.TxtStatus.Text = $Message
    }

    $showPage = {
        param([string]$Name)
        if (-not $pageControl.ContainsKey($Name)) { return }
        foreach ($key in $pageControl.Keys) {
            $pageControl[$key].Visibility = $(if ($key -eq $Name) { 'Visible' } else { 'Collapsed' })
            $navControl[$key].IsChecked = ($key -eq $Name)
        }
        $state.CurrentPage = $Name
    }

    $chipContent = {
        param([string]$Label, $Count)
        $dock = New-Object System.Windows.Controls.DockPanel
        $number = New-Object System.Windows.Controls.TextBlock
        $number.Text = [string]$Count
        $number.FontWeight = 'SemiBold'
        $number.Margin = New-Object System.Windows.Thickness(7, 0, 0, 0)
        [System.Windows.Controls.DockPanel]::SetDock($number, [System.Windows.Controls.Dock]::Right)
        $caption = New-Object System.Windows.Controls.TextBlock
        $caption.Text = $Label
        $null = $dock.Children.Add($number)
        $null = $dock.Children.Add($caption)
        return $dock
    }

    $applyFilter = {
        if ($null -eq $state.View) { return }
        $state.View.Refresh()

        $shown = @($state.View).Count
        $total = 0
        if ($state.Rows) { $total = $state.Rows.Count }

        if ($shown -eq $total) {
            $ui.TxtShown.Text = ('{0} finding(s)' -f $total)
        } else {
            $ui.TxtShown.Text = ('{0} of {1}' -f $shown, $total)
        }

        if ($shown -eq 0 -and $total -gt 0) {
            $ui.TxtEmptyTitle.Text = 'Nothing matches the filter'
            $ui.TxtEmptyBody.Text = 'All ' + $total + ' finding(s) are hidden. Clear the search box, or switch a verdict back on in the left panel.'
            $ui.PnlEmpty.Visibility = 'Visible'
        } elseif ($shown -eq 0) {
            $ui.PnlEmpty.Visibility = 'Visible'
        } else {
            $ui.PnlEmpty.Visibility = 'Collapsed'
        }
    }

    $showDetail = {
        param($Row)

        if ($null -eq $Row) {
            $ui.ScrDetail.Visibility = 'Collapsed'
            $ui.TxtNoSelection.Visibility = 'Visible'
            $ui.BtnCopy.IsEnabled = $false
            return
        }

        $detail = ConvertTo-LVGuiDetail -Finding $Row.Finding

        $ui.TxtNoSelection.Visibility = 'Collapsed'
        $ui.ScrDetail.Visibility = 'Visible'
        $ui.BtnCopy.IsEnabled = $true

        $ui.TxtDetailVerdict.Text = $detail.VerdictLabel
        $ui.PillDetail.Background = $detail.VerdictFill
        $ui.TxtDetailVerdict.Foreground = $detail.VerdictInk
        $ui.TxtDetailTitle.Text = $detail.Title
        $ui.TxtDetailMeta.Text = $detail.Meta
        $ui.TxtPlain.Text  = $detail.Plain
        $ui.TxtWhy.Text    = $detail.Why
        $ui.TxtAction.Text = $detail.Action

        if ($detail.FalsePositive.Count -gt 0) {
            $ui.LstFalsePositives.ItemsSource = [string[]]$detail.FalsePositive
            $ui.PnlFalsePositives.Visibility = 'Visible'
        } else {
            $ui.PnlFalsePositives.Visibility = 'Collapsed'
        }

        if ($detail.Reference.Count -gt 0) {
            $ui.LstRefs.ItemsSource = [string[]]$detail.Reference
            $ui.PnlRefs.Visibility = 'Visible'
        } else {
            $ui.PnlRefs.Visibility = 'Collapsed'
        }

        $ui.TxtSample.Text = $detail.SampleText
        $ui.TxtProvenance.Text = $detail.Provenance
    }

    $appendLog = {
        param([string]$Level, [string]$Stamp, [string]$Message)

        $marks = @{ info = '[ ]'; ok = '[+]'; warn = '[!]'; error = '[x]'; step = '===' }
        $mark = $marks[$Level]
        if (-not $mark) { $mark = '[ ]' }

        # The scan ran in a worker runspace, so the module's own transcript is empty in
        # this one. Rebuilding it here is what stops the exported LogVerdict-Run.log
        # from being a blank file whenever the report came from the window.
        $transcriptLine = '{0} {1} {2}' -f $Stamp, $mark, $Message
        $null = $script:LVLogLines.Add($transcriptLine)

        $clock = $Stamp
        if ($Stamp.Length -ge 19) { $clock = $Stamp.Substring(11, 8) }
        $panelLine = '{0}  {1} {2}{3}' -f $clock, $mark, $Message, [Environment]::NewLine

        $ui.TxtLog.AppendText($panelLine)
        $ui.TxtLog.ScrollToEnd()
        $state.ActivityLines.Add($panelLine.TrimEnd()) | Out-Null
        $activityFilter = $ui.TxtActivitySearch.Text.Trim()
        if (-not $activityFilter -or $panelLine -like ('*{0}*' -f $activityFilter)) {
            $ui.TxtActivityLog.AppendText($panelLine)
            $ui.TxtActivityLog.ScrollToEnd()
        }
        $ui.TxtActivityLastLine.Text = $Message
        $ui.TxtLastLine.Text = $Message
        $ui.TxtStatus.Text = $Message
    }

    $drainLog = {
        if ($null -eq $state.Sink) { return }
        $item = $null
        while ($state.Sink.TryDequeue([ref]$item)) {
            # Cap the split at 3 so a message carrying its own pipe characters survives.
            $split = ([string]$item).Split(@('|'), 3, [System.StringSplitOptions]::None)
            if ($split.Count -eq 3) {
                & $appendLog $split[0] $split[1] $split[2]
            } else {
                & $appendLog 'info' ('{0:yyyy-MM-dd HH:mm:ss}' -f (Get-Date)) ([string]$item)
            }
        }
    }

    $setScanning = {
        param([bool]$On)
        $state.Scanning = $On
        $ui.BtnScan.IsEnabled = -not $On
        $ui.BtnCancel.Visibility = $(if ($On) { 'Visible' } else { 'Collapsed' })
        $ui.BtnOverviewScan.IsEnabled = -not $On
        $ui.BtnOverviewCancel.Visibility = $(if ($On) { 'Visible' } else { 'Collapsed' })
        $ui.BtnActivityRunAgain.IsEnabled = -not $On
        $ui.PbScan.Visibility = $(if ($On) { 'Visible' } else { 'Collapsed' })
        $ui.PbScan.IsIndeterminate = $On
        foreach ($n in @('TxtDays', 'ChkAllChannels', 'ChkSkipText', 'ChkIncludeBenign', 'BtnElevate')) {
            $ui[$n].IsEnabled = -not $On
        }
        foreach ($n in @('TxtOverviewDays', 'ChkOverviewAllChannels', 'ChkOverviewIncludeText',
                'ChkOverviewDiagnosticChannels', 'ChkOverviewIncludeBenign', 'TxtOverviewChannels',
                'TxtOverviewDatabase', 'BtnOverviewBrowseDatabase', 'ChkOverviewSkipReliability',
                'TxtOverviewOutputDir', 'BtnOverviewBrowseOutput', 'ChkOverviewRedact',
                'ChkOverviewEvidence', 'BtnCoverageElevate', 'BtnSideElevate')) {
            $ui[$n].IsEnabled = -not $On
        }
        if ($On) { $ui.BtnScan.Content = 'Scanning...' } else { $ui.BtnScan.Content = 'Run scan' }
        if ($On) {
            $ui.BtnOverviewScan.Content = 'Scanning...'
            $ui.TxtActivityState.Text = 'Scanning...'
            $ui.TxtActivityHeadline.Text = 'Collecting and reducing diagnostic records'
        } else {
            $ui.BtnOverviewScan.Content = 'Run scan'
        }
    }

    $renderResult = {
        param($Result)

        $state.Result = $Result
        $rows = ConvertTo-LVGuiRow -Finding @($Result.Findings)

        $observable = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
        foreach ($r in $rows) { $observable.Add($r) }
        $state.Rows = $observable

        $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($observable)
        $view.Filter = [Predicate[object]] {
            param($Item)
            return Test-LVGuiFindingVisible -Row $Item -EnabledVerdict $state.Chips -Search $state.Search
        }
        $state.View = $view
        $ui.LvFindings.ItemsSource = $view
        $priority = @($rows | Select-Object -First 3)
        $ui.LvPriority.ItemsSource = [object[]]$priority

        # Counts are of everything found, not of what the filter is showing, so
        # switching a chip off never makes its own number change under the cursor.
        $counts = Get-LVGuiVerdictCount -Finding @($Result.Findings)
        foreach ($v in $script:LVVerdictDisplayOrder) {
            $style = Get-LVVerdictStyle -Verdict $v
            $chip = $chipControl[$v]
            $chip.Content = & $chipContent $style.Label $counts[$v]
            # The chip's visible content is a panel of two text blocks, which gives a
            # screen reader nothing useful and never says what the control does. The
            # toggle state itself is exposed separately by the toggle pattern.
            [System.Windows.Automation.AutomationProperties]::SetName(
                $chip, ('Show {0} findings, {1} found' -f $style.Label.ToLowerInvariant(), $counts[$v]))
            # A verdict with nothing in it is dimmed but still clickable, so the reader
            # can see that the category was considered and came back empty.
            $chip.Opacity = $(if ($counts[$v] -eq 0) { 0.45 } else { 1.0 })
        }

        $ui.TxtOverviewCritical.Text    = [string]$counts['critical']
        $ui.TxtOverviewActionable.Text  = [string]$counts['actionable']
        $ui.TxtOverviewInvestigate.Text = [string]$counts['investigate']
        $ui.TxtOverviewUnknown.Text     = [string]$counts['unknown']
        $ui.TxtOverviewInfo.Text        = [string]$counts['informational']
        $ui.TxtOverviewBenign.Text      = [string]$counts['benign']

        $ui.TxtRecords.Text    = '{0:N0}' -f $Result.Reduction.RecordCount
        $ui.TxtSignatures.Text = '{0:N0}' -f $Result.Reduction.SignatureCount
        $ui.TxtReduction.Text  = '{0}:1' -f $Result.Reduction.Ratio
        $ui.TxtRules.Text      = '{0:N0}' -f $Result.RuleCount
        $ui.PnlSummary.Visibility = 'Visible'

        $ui.TxtOverviewRecords.Text    = '{0:N0}' -f $Result.Reduction.RecordCount
        $ui.TxtOverviewSignatures.Text = '{0:N0}' -f $Result.Reduction.SignatureCount
        $ui.TxtOverviewReduction.Text  = '{0}x' -f $Result.Reduction.Ratio
        $ui.TxtOverviewRules.Text      = '{0:N0}' -f $Result.RuleCount
        $ui.PnlOverviewSummary.Visibility = 'Visible'

        $worst = Get-LVVerdictStyle -Verdict $Result.WorstVerdict
        $overviewVerdict = switch ([string]$Result.WorstVerdict) {
            'critical'      { 'Critical finding' }
            'actionable'    { 'Action required' }
            'investigate'   { 'Needs investigation' }
            'unknown'       { 'Unrecognized activity' }
            'informational' { 'Informational only' }
            default         { 'No action required' }
        }
        $ui.TxtOverviewLastVerdict.Text = $(if (@($Result.Findings).Count -eq 0) { 'No action required' } else { $overviewVerdict })
        $ui.TxtOverviewLastVerdict.Foreground = $worst.Accent
        $ui.TxtOverviewFindingCount.Text = '{0:N0}' -f @($Result.Findings).Count
        $ui.TxtOverviewScanTime.Text = 'Completed {0:yyyy-MM-dd HH:mm} in {1:N1}s' -f $Result.ScanTime, $Result.Duration.TotalSeconds

        $coverageNotes = @($Result.CoverageNotes | Where-Object { $_ })
        $notes = @($coverageNotes)
        if ($Result.HorizonWarning) { $notes = @($notes) + @($Result.HorizonWarning) }
        if ($notes.Count -gt 0) {
            $ui.LstCoverage.ItemsSource = [string[]]$notes
            $ui.PnlCoverage.Visibility = 'Visible'
        } else {
            $ui.PnlCoverage.Visibility = 'Collapsed'
        }
        if ($coverageNotes.Count -gt 0) {
            $ui.LstCoveragePage.ItemsSource = [string[]]$coverageNotes
            $ui.TxtCoverageNone.Visibility = 'Collapsed'
        } else {
            $ui.LstCoveragePage.ItemsSource = [string[]]@()
            $ui.TxtCoverageNone.Visibility = 'Visible'
        }

        $channelLines = New-Object System.Collections.Generic.List[string]
        $readable = 0
        $totalChannels = 0
        if ($Result.ChannelStatus) {
            foreach ($name in @($Result.ChannelStatus.Keys | Sort-Object)) {
                $entry = $Result.ChannelStatus[$name]
                $totalChannels++
                if ($entry.Access -eq 'readable') { $readable++ }
                $availability = [string]$entry.Access
                if ($entry.Oldest) { $availability = 'oldest {0:yyyy-MM-dd HH:mm}' -f $entry.Oldest }
                $channelLines.Add(('{0,-36} {1,-11} {2}' -f $name, ([string]$entry.Access).ToUpperInvariant(), $availability)) | Out-Null
            }
        }
        if ($Result.PSObject.Properties['SetupDiag'] -and $Result.SetupDiag) {
            $channelLines.Add(('SetupDiag                            {0,-11} {1}' -f ([string]$Result.SetupDiag.Status).ToUpperInvariant(), $Result.SetupDiag.Message)) | Out-Null
        }
        foreach ($health in @($Result.HealthProfiles | Where-Object { $_ })) {
            $healthDetail = if ($health.ObservedConfiguration) { [string]$health.ObservedConfiguration } elseif ($health.Reason) { [string]$health.Reason } else { '' }
            $channelLines.Add(('{0,-36} {1,-11} {2}' -f ([string]$health.Name).Substring(0, [Math]::Min(36, ([string]$health.Name).Length)), ([string]$health.Status).ToUpperInvariant(), $healthDetail)) | Out-Null
        }
        if ($Result.PSObject.Properties['AdvisoryStatus'] -and $Result.AdvisoryStatus -ne 'not-requested') {
            $channelLines.Add('') | Out-Null
            $channelLines.Add('DEPENDENCY ADVISORIES (SEPARATE FROM EVENT FINDINGS)') | Out-Null
            $channelLines.Add(('Status: {0}; knowledge records are not Windows event verdicts.' -f $Result.AdvisoryStatus)) | Out-Null
            foreach ($advisory in @($Result.Advisories | Where-Object { $_ })) {
                $state = if ($advisory.Matched) { 'AFFECTED' } else { 'CACHE ENTRY' }
                $channelLines.Add(('[{0}] {1} - {2} {3}; CVSS {4}; fixed {5}' -f `
                    $state, $advisory.Id, $advisory.Package, $advisory.Version, $advisory.CVSS, $advisory.FixedVersion)) | Out-Null
            }
        }
        if ($Result.PSObject.Properties['CaseProfile'] -and $Result.CaseProfile) {
            $channelLines.Add('') | Out-Null
            $channelLines.Add('CASE PROFILE / HANDOFF') | Out-Null
            $channelLines.Add(('Profile: {0}; sources: {1}; redacted: {2}' -f `
                $Result.CaseProfile.profileId, @($Result.CaseProfile.sources).Count, $Result.CaseProfile.redaction.requested)) | Out-Null
            $channelLines.Add('The profile records collection scope, hashes, notes, and operator choices; it is not a verdict.') | Out-Null
            foreach ($note in @($Result.CaseProfile.notes | Where-Object { $_ })) {
                $channelLines.Add(('Note: ' + [string]$note)) | Out-Null
            }
        }
        if ($channelLines.Count -eq 0) { $channelLines.Add('No event-channel status was returned.') | Out-Null }
        $ui.LstChannelCoverage.ItemsSource = [string[]]$channelLines.ToArray()

        $coverageGaps = $notes.Count
        $coveragePercent = 0
        if ($totalChannels -gt 0) { $coveragePercent = [Math]::Round(100 * $readable / $totalChannels) }
        $ui.TxtCoverageReadable.Text = [string]$readable
        $ui.TxtCoverageGaps.Text = [string]$coverageGaps
        $ui.TxtCoverageWindow.Text = '{0}-day' -f $Result.DaysBack
        $ui.TxtCoverageRatio.Text = '{0} of {1} requested channels readable' -f $readable, $totalChannels
        $ui.PbCoverage.Value = $coveragePercent
        if ($notes.Count -gt 0) {
            $ui.TxtCoverageState.Text = 'Partial coverage'
            $ui.TxtCoverageSummary.Text = 'The scan completed, but some requested diagnostic history was unavailable.'
            $ui.TxtOverviewCoverage.Text = '{0} coverage note(s) need review. {1} of {2} requested event channels were readable.' -f $notes.Count, $readable, $totalChannels
        } else {
            $ui.TxtCoverageState.Text = 'Requested sources readable'
            $ui.TxtCoverageSummary.Text = 'No access, truncation, or history gaps were reported for the requested sources.'
            $ui.TxtOverviewCoverage.Text = 'All {0} requested event channels were readable and no coverage gaps were reported.' -f $totalChannels
        }
        if ($Result.PSObject.Properties['AdvisoryStatus'] -and $Result.AdvisoryStatus -ne 'not-requested') {
            $ui.TxtCoverageSummary.Text += ' Dependency advisories are shown separately below and never change event verdicts.'
        }
        $ui.TxtHorizonPage.Text = $(if ($Result.HorizonWarning) { [string]$Result.HorizonWarning } else { 'The requested event history window was available for the channels that reported an oldest record.' })

        $ui.TxtEmptyTitle.Text = 'Nothing to report'
        $ui.TxtEmptyBody.Text = 'The scan completed and found no signature worth raising in the last ' + $Result.DaysBack + ' day(s). Check the panel on the left for anything the scan was not allowed to read.'

        # Crash evidence the console report has always shown and the window used to drop.
        $crash = Format-LVCrashArtifact -Artifact @($Result.CrashArtifacts)
        if ($crash.Count -gt 0) {
            $ui.LstCrash.ItemsSource = [string[]]$crash
            $ui.LstCrashPage.ItemsSource = [string[]]$crash
            $ui.TxtCrashNone.Visibility = 'Collapsed'
            $ui.PnlCrash.Visibility = 'Visible'
        } else {
            $ui.PnlCrash.Visibility = 'Collapsed'
            $ui.LstCrashPage.ItemsSource = [string[]]@()
            $ui.TxtCrashNone.Visibility = 'Visible'
        }

        # Correlated findings. Filtered rather than merely wrapped: a result with no
        # Correlations property yields a one-element array holding null.
        $together = Format-LVCorrelation -Correlation @($Result.Correlations | Where-Object { $_ })
        if ($together.Count -gt 0) {
            $ui.LstCorrelation.ItemsSource = [string[]]$together
            $ui.LstCorrelationPage.ItemsSource = [string[]]$together
            $ui.TxtCorrelationNone.Visibility = 'Collapsed'
            $ui.PnlCorrelation.Visibility = 'Visible'
        } else {
            $ui.PnlCorrelation.Visibility = 'Collapsed'
            $ui.LstCorrelationPage.ItemsSource = [string[]]@()
            $ui.TxtCorrelationNone.Visibility = 'Visible'
        }

        $ui.BtnSaveReport.IsEnabled = $true
        $ui.BtnFindingsSave.IsEnabled = $true
        $ui.BtnActivitySave.IsEnabled = $true
        $ui.TxtActivityReportState.Text = 'Ready to save'

        $ui.TxtActivitySubtitle.Text = 'Latest scan - {0:yyyy-MM-dd HH:mm}' -f $Result.ScanTime
        $ui.TxtActivityState.Text = 'Completed in {0:N1}s' -f $Result.Duration.TotalSeconds
        if ($Result.Reduction.PSObject.Properties['InitialSignatureCount']) {
            $ui.TxtActivityHeadline.Text = '{0:N0} records -> {1:N0} masked -> {2:N0} after slot pass' -f `
                $Result.Reduction.RecordCount, $Result.Reduction.InitialSignatureCount, $Result.Reduction.SignatureCount
        } else {
            $ui.TxtActivityHeadline.Text = '{0:N0} records reduced to {1:N0} signatures' -f $Result.Reduction.RecordCount, $Result.Reduction.SignatureCount
        }
        $ui.BtnActivityRunAgain.Content = 'Run again'
        $ui.TxtActivityDuration.Text = '{0:N1}s' -f $Result.Duration.TotalSeconds
        $ui.TxtActivityRecords.Text = '{0:N0}' -f $Result.Reduction.RecordCount
        $ui.TxtActivitySignatures.Text = '{0:N0}' -f $Result.Reduction.SignatureCount
        $ui.TxtActivityRules.Text = '{0:N0}' -f $Result.RuleCount

        $ui.TxtSideDbTitle.Text = 'Database up to date'
        $ui.TxtSideDbMeta.Text = 'v{0} - {1} rules' -f $script:LVVersion, $Result.RuleCount
        $ui.TxtSideDbUpdated.Text = $(if ($Result.DatabaseDate) { 'Updated {0}' -f $Result.DatabaseDate } else { 'Bundled verdict database' })

        # Database age belongs on screen, not only in the text report. A curated ruling
        # is only as good as the day it was last checked.
        $footer = '{0} - {1} rule(s)' -f $Result.DatabaseName, $Result.RuleCount
        if ($Result.DatabaseDate) { $footer += ' - updated {0}' -f $Result.DatabaseDate }
        $footer += ' - scanned in {0:N1}s' -f $Result.Duration.TotalSeconds

        $stale = Get-LVStaleRuleCount -Finding @($Result.Findings)
        if ($stale -gt 0) {
            $footer += ' - {0} ruling(s) not re-checked in over {1} months' -f $stale, $script:LVVerificationMaxAgeMonths
            $ui.TxtFooter.Foreground = $ui.PillDetail.FindResource('Yellow')
        } else {
            $ui.TxtFooter.Foreground = $ui.PillDetail.FindResource('TextMuted')
        }
        $ui.TxtFooter.Text = $footer

        & $showDetail $null
        & $applyFilter

        $summary = 'Scan complete. {0} finding(s), worst is {1}. {2:N0} record(s) reduced to {3:N0} signature(s).' -f `
            @($Result.Findings).Count, $worst.Label, $Result.Reduction.RecordCount, $Result.Reduction.SignatureCount
        & $setStatus $summary
    }

    # ----------------------------------------------------------------- events ----

    $ui.TxtVersion.Text = 'v{0}' -f $script:LVVersion
    $ui.TxtMachine.Text = $env:COMPUTERNAME
    $ui.TxtDays.Text = [string]$initialDays
    $ui.ChkAllChannels.IsChecked = $initialAllChannels
    $ui.ChkSkipText.IsChecked = $initialSkipText
    $ui.ChkIncludeBenign.IsChecked = $initialIncludeBenign
    $ui.TxtSideMachine.Text = $env:COMPUTERNAME
    $ui.TxtOverviewDays.Text = [string]$initialDays
    $ui.ChkOverviewAllChannels.IsChecked = $initialAllChannels
    $ui.ChkOverviewIncludeText.IsChecked = -not $initialSkipText
    $ui.ChkOverviewIncludeBenign.IsChecked = $initialIncludeBenign
    $ui.BtnFindingsSave.IsEnabled = $false
    $ui.BtnFindingsOpen.IsEnabled = $false
    $ui.BtnActivitySave.IsEnabled = $false
    $ui.BtnActivityOpen.IsEnabled = $false

    if (Test-LVElevated) {
        $ui.TxtElevation.Text = 'Administrator'
        $ui.TxtElevation.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Green')
        $ui.TxtSideElevation.Text = 'Administrator access'
        $ui.TxtSideElevation.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Green')
        $ui.BtnCoverageElevate.Visibility = 'Collapsed'
    } else {
        $ui.TxtElevation.Text = 'Standard user'
        $ui.TxtSideElevation.Text = 'Standard access'
        $ui.PnlElevate.Visibility = 'Visible'
        $ui.BtnSideElevate.Visibility = 'Visible'
    }

    $window.Add_SourceInitialized({ Enable-LVDarkTitleBar -Window $window })

    $systemThemeChanged = [System.ComponentModel.PropertyChangedEventHandler] {
        param($SenderObject, $ThemeEventArgs)
        if ($ThemeEventArgs.PropertyName -ne 'HighContrast') { return }

        $null = Sync-LVGuiTheme -Window $window -Snapshot $themeSnapshot
        Enable-LVDarkTitleBar -Window $window

        # Verdict colours are projected into bound row objects rather than resource
        # references, so rebuild those objects when the system palette changes.
        if ($state.Result) { & $renderResult $state.Result }
    }
    [System.Windows.SystemParameters]::add_StaticPropertyChanged($systemThemeChanged)

    # Checked, not Click: TogglePattern is how assistive automation activates a
    # ToggleButton. Mouse, keyboard and UI Automation must all navigate identically.
    $ui.NavOverview.Add_Checked({ & $showPage 'Overview' })
    $ui.NavFindings.Add_Checked({ & $showPage 'Findings' })
    $ui.NavCoverage.Add_Checked({ & $showPage 'Coverage' })
    $ui.NavActivity.Add_Checked({ & $showPage 'Activity' })

    $syncOverviewOptions = {
        $ui.TxtDays.Text = $ui.TxtOverviewDays.Text
        $ui.ChkAllChannels.IsChecked = [bool]$ui.ChkOverviewAllChannels.IsChecked
        $ui.ChkSkipText.IsChecked = -not [bool]$ui.ChkOverviewIncludeText.IsChecked
        $ui.ChkIncludeBenign.IsChecked = [bool]$ui.ChkOverviewIncludeBenign.IsChecked
    }

    $ui.BtnOverviewScan.Add_Click({
        & $syncOverviewOptions
        & $showPage 'Activity'
        $ui.BtnScan.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    })
    $ui.BtnActivityRunAgain.Add_Click({
        & $syncOverviewOptions
        & $showPage 'Activity'
        $ui.BtnScan.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    })

    $ui.ChkOverviewAllChannels.Add_Checked({
        $ui.ChkOverviewDiagnosticChannels.IsChecked = $false
    })
    $ui.ChkOverviewDiagnosticChannels.Add_Checked({
        $ui.ChkOverviewAllChannels.IsChecked = $false
    })
    $ui.TxtOverviewChannels.Add_TextChanged({
        if ($ui.TxtOverviewChannels.Text.Trim()) {
            $ui.ChkOverviewAllChannels.IsChecked = $false
            $ui.ChkOverviewDiagnosticChannels.IsChecked = $false
        }
    })

    $ui.BtnOverviewBrowseDatabase.Add_Click({
        $dialog = New-Object Microsoft.Win32.OpenFileDialog
        $dialog.Title = 'Choose a LogVerdict rule database'
        $dialog.Filter = 'JSON rule database (*.json)|*.json|All files (*.*)|*.*'
        $dialog.CheckFileExists = $true
        $current = $ui.TxtOverviewDatabase.Text.Trim()
        if ($current -and (Test-Path -LiteralPath $current -PathType Leaf)) {
            $dialog.InitialDirectory = Split-Path -Parent $current
            $dialog.FileName = Split-Path -Leaf $current
        }
        if ($dialog.ShowDialog($window)) { $ui.TxtOverviewDatabase.Text = $dialog.FileName }
    })

    $ui.BtnOverviewBrowseOutput.Add_Click({
        $folder = Select-LVGuiFolder -Window $window -InitialDirectory $ui.TxtOverviewOutputDir.Text.Trim()
        if ($folder) { $ui.TxtOverviewOutputDir.Text = $folder }
    })
    $ui.BtnOverviewCancel.Add_Click({
        $ui.BtnCancel.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    })
    $ui.BtnViewFindings.Add_Click({ & $showPage 'Findings' })
    $ui.BtnViewCoverage.Add_Click({ & $showPage 'Coverage' })
    $ui.BtnCoverageElevate.Add_Click({
        $ui.BtnElevate.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    })
    $ui.BtnSideElevate.Add_Click({
        $ui.BtnElevate.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    })

    $ui.BtnFindingsSave.Add_Click({
        $ui.BtnSaveReport.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    })
    $ui.BtnActivitySave.Add_Click({
        $ui.BtnSaveReport.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    })
    $ui.BtnFindingsOpen.Add_Click({
        $ui.BtnOpenReport.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    })
    $ui.BtnActivityOpen.Add_Click({
        $ui.BtnOpenReport.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    })

    $ui.BtnActivityClear.Add_Click({
        $state.ActivityLines.Clear()
        $ui.TxtActivityLog.Clear()
        $ui.TxtActivityLastLine.Text = ''
    })

    $ui.TxtActivitySearch.Add_TextChanged({
        $needle = $ui.TxtActivitySearch.Text.Trim()
        $ui.TxtActivitySearchHint.Visibility = $(if ($needle) { 'Collapsed' } else { 'Visible' })
        $visibleLines = @($state.ActivityLines | Where-Object { -not $needle -or $_ -like ('*{0}*' -f $needle) })
        $ui.TxtActivityLog.Text = $visibleLines -join [Environment]::NewLine
        $ui.TxtActivityLog.ScrollToEnd()
    })

    $ui.TxtSearch.Add_TextChanged({
        $text = $ui.TxtSearch.Text
        $ui.TxtSearchHint.Visibility = $(if ($text) { 'Collapsed' } else { 'Visible' })
        $state.Search = $text.Trim().ToLowerInvariant()
        & $applyFilter
    })

    foreach ($verdict in $script:LVVerdictDisplayOrder) {
        $chip = $chipControl[$verdict]
        # The verdict is stashed on the control so one handler serves all six chips;
        # capturing $verdict in the closure would leave every handler on the last value.
        $chip.DataContext = $verdict
        # Named before the first scan too: the chips are visible from launch, and an
        # unnamed toggle announces as a bare "button".
        [System.Windows.Automation.AutomationProperties]::SetName(
            $chip, ('Show {0} findings' -f (Get-LVVerdictStyle -Verdict $verdict).Label.ToLowerInvariant()))
        $handler = {
            param($Chip)
            $state.Chips[[string]$Chip.DataContext] = [bool]$Chip.IsChecked
            & $applyFilter
        }
        $chip.Add_Checked($handler)
        $chip.Add_Unchecked($handler)
    }

    $ui.LvFindings.Add_SelectionChanged({
        & $showDetail $ui.LvFindings.SelectedItem
    })

    $ui.LvPriority.Add_SelectionChanged({
        if ($null -eq $ui.LvPriority.SelectedItem) { return }
        & $showPage 'Findings'
        $ui.LvFindings.SelectedItem = $ui.LvPriority.SelectedItem
        $ui.LvFindings.ScrollIntoView($ui.LvPriority.SelectedItem)
    })

    $ui.LvFindings.AddHandler(
        [System.Windows.Controls.GridViewColumnHeader]::ClickEvent,
        [System.Windows.RoutedEventHandler] {
            param($SenderControl, $RoutedArgs)
            $header = $RoutedArgs.OriginalSource -as [System.Windows.Controls.GridViewColumnHeader]
            if ($null -eq $header -or $null -eq $header.Column) { return }
            $key = $script:LVGuiSortKey[[string]$header.Content]
            if (-not $key -or $null -eq $state.View) { return }

            if ($state.SortKey -eq $key) { $state.SortAsc = -not $state.SortAsc } else { $state.SortAsc = $true }
            $state.SortKey = $key

            $direction = [System.ComponentModel.ListSortDirection]::Ascending
            if (-not $state.SortAsc) { $direction = [System.ComponentModel.ListSortDirection]::Descending }

            $state.View.SortDescriptions.Clear()
            $state.View.SortDescriptions.Add((New-Object System.ComponentModel.SortDescription($key, $direction)))
            $state.View.Refresh()
        }
    )

    $window.AddHandler(
        [System.Windows.Documents.Hyperlink]::RequestNavigateEvent,
        [System.Windows.Navigation.RequestNavigateEventHandler] {
            param($SenderControl, $NavigateArgs)
            $uri = [string]$NavigateArgs.Uri.AbsoluteUri
            try {
                Start-Process $uri
                & $setStatus ('Opened {0}' -f $uri)
            } catch {
                & $setStatus ('Could not open {0}: {1}' -f $uri, $_.Exception.Message)
            }
            $NavigateArgs.Handled = $true
        }
    )

    $ui.BtnToggleLog.Add_Click({
        if ($ui.RowLog.Height.Value -gt 0) {
            $ui.RowLog.Height = New-Object System.Windows.GridLength(0)
            $ui.BtnToggleLog.Content = 'Show activity log'
            $ui.TxtLastLine.Visibility = 'Visible'
        } else {
            $ui.RowLog.Height = New-Object System.Windows.GridLength(170)
            $ui.BtnToggleLog.Content = 'Hide activity log'
            $ui.TxtLastLine.Visibility = 'Collapsed'
            $ui.TxtLog.ScrollToEnd()
        }
    })

    $ui.BtnElevate.Add_Click({
        $target = Get-LVGuiRelaunchTarget
        if ($null -eq $target) {
            & $setStatus 'Could not work out how to restart this build elevated. Right-click LogVerdict and choose Run as administrator.'
            return
        }
        try {
            if (@($target.Arguments).Count -gt 0) {
                Start-Process -FilePath $target.FilePath -ArgumentList $target.Arguments -Verb RunAs
            } else {
                Start-Process -FilePath $target.FilePath -Verb RunAs
            }
            $window.Close()
        } catch {
            # The overwhelmingly common cause is the user declining the UAC prompt,
            # which is a decision, not an error worth a dialog.
            & $setStatus ('Elevation was not granted. Still running as a standard user.')
        }
    })

    $ui.BtnScan.Add_Click({
        if ($state.Scanning) { return }

        $days = 0
        if (-not [int]::TryParse($ui.TxtOverviewDays.Text.Trim(), [ref]$days) -or $days -lt 1 -or $days -gt 3650) {
            $days = 30
            $ui.TxtDays.Text = '30'
            $ui.TxtOverviewDays.Text = '30'
            & $setStatus 'Look-back must be a whole number of days between 1 and 3650. Reset to 30.'
        }

        $ui.TxtLog.Clear()
        $ui.TxtActivityLog.Clear()
        $state.ActivityLines.Clear()
        $ui.TxtActivitySearch.Clear()
        $ui.TxtActivityLastLine.Text = ''
        # Each report carries its own scan's transcript, not everything since launch.
        $script:LVLogLines.Clear()
        $state.Sink = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
        $state.ReportDir = $null
        $state.HtmlPath = $null
        $ui.BtnOpenReport.IsEnabled = $false
        $ui.BtnSaveReport.IsEnabled = $false
        $ui.BtnFindingsOpen.IsEnabled = $false
        $ui.BtnFindingsSave.IsEnabled = $false
        $ui.BtnActivityOpen.IsEnabled = $false
        $ui.BtnActivitySave.IsEnabled = $false
        $ui.TxtActivityReportState.Text = 'Not saved yet'
        $ui.PnlEmpty.Visibility = 'Collapsed'

        $scanArgs = @{
            DaysBack      = $days
            SkipTextLogs  = -not [bool]$ui.ChkOverviewIncludeText.IsChecked
            SkipReliability = [bool]$ui.ChkOverviewSkipReliability.IsChecked
            IncludeBenign = [bool]$ui.ChkOverviewIncludeBenign.IsChecked
        }
        if ($AdvisoryPath) { $scanArgs['AdvisoryPath'] = $AdvisoryPath }
        if ($AdvisoryPackage) { $scanArgs['AdvisoryPackage'] = $AdvisoryPackage }
        if ($AdvisoryVersion) { $scanArgs['AdvisoryVersion'] = $AdvisoryVersion }
        if ($CaseProfilePath) { $scanArgs['CaseProfilePath'] = $CaseProfilePath }

        $namedChannels = @(Get-LVGuiNamedChannel -Text $ui.TxtOverviewChannels.Text)
        if ($namedChannels.Count -gt 0) {
            $scanArgs['Channel'] = $namedChannels
        } elseif ([bool]$ui.ChkOverviewAllChannels.IsChecked) {
            $scanArgs['AllChannels'] = $true
        } elseif ([bool]$ui.ChkOverviewDiagnosticChannels.IsChecked) {
            $scanArgs['DiagnosticChannels'] = $true
        }

        $databasePath = $ui.TxtOverviewDatabase.Text.Trim()
        if ($databasePath) {
            if (-not (Test-Path -LiteralPath $databasePath -PathType Leaf)) {
                & $setStatus ('Rule database not found: {0}' -f $databasePath)
                & $showPage 'Overview'
                return
            }
            $scanArgs['DatabasePath'] = $databasePath
        }

        try {
            $state.Job = Start-LVScanJob -ScanArgs $scanArgs -LogSink $state.Sink
        } catch {
            & $setStatus ('Could not start the scan: {0}' -f $_.Exception.Message)
            return
        }

        & $setScanning $true
        & $setStatus 'Scanning...'
        & $showPage 'Activity'
        $state.Timer.Start()
    })

    $ui.BtnCancel.Add_Click({
        if (-not $state.Scanning) { return }
        $state.Timer.Stop()
        Stop-LVScanJob -Job $state.Job -Confirm:$false
        $state.Job = $null
        & $setScanning $false
        & $setStatus 'Scan cancelled. Nothing on this machine was changed.'
        $ui.TxtActivityState.Text = 'Cancelled'
        $ui.TxtActivityHeadline.Text = 'The scan was cancelled. Nothing was changed.'
    })

    $ui.BtnSaveReport.Add_Click({
        if ($null -eq $state.Result) { return }
        try {
            $exportArgs = @{
                Result          = $state.Result
                Redact          = [bool]$ui.ChkOverviewRedact.IsChecked
                IncludeEvidence = [bool]$ui.ChkOverviewEvidence.IsChecked
                # Checking the evidence box is the GUI's explicit raw-evidence choice
                # when redaction is off; the public command still requires its switch.
                AllowRawEvidence = [bool]($ui.ChkOverviewEvidence.IsChecked -and -not $ui.ChkOverviewRedact.IsChecked)
            }
            $outputDir = $ui.TxtOverviewOutputDir.Text.Trim()
            if ($outputDir) { $exportArgs['OutputDir'] = $outputDir }
            $out = Export-LogVerdictReport @exportArgs
            $state.ReportDir = $out.OutputDir
            $state.HtmlPath = ($out.Files | Where-Object { $_ -like '*.html' } | Select-Object -First 1)
            $ui.BtnOpenReport.IsEnabled = $true
            $ui.BtnFindingsOpen.IsEnabled = $true
            $ui.BtnActivityOpen.IsEnabled = $true
            $ui.TxtActivityReportState.Text = 'Saved to {0}' -f $out.OutputDir
            & $setStatus ('Report written to {0}' -f $out.OutputDir)
        } catch {
            & $setStatus ('Could not write the report: {0}' -f $_.Exception.Message)
        }
    })

    $ui.BtnOpenReport.Add_Click({
        $target = $state.HtmlPath
        if (-not $target) { $target = $state.ReportDir }
        if (-not $target) { return }
        try {
            Start-Process $target
            & $setStatus ('Opened {0}' -f $target)
        } catch {
            & $setStatus ('Could not open {0}: {1}' -f $target, $_.Exception.Message)
        }
    })

    $ui.BtnCopy.Add_Click({
        $row = $ui.LvFindings.SelectedItem
        if ($null -eq $row) { return }
        $f = $row.Finding

        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add(('[{0}] {1}' -f ([string]$f.Verdict).ToUpperInvariant(), $f.Title))
        $lines.Add(('Signature : {0}' -f $f.Key))
        $lines.Add(('Seen      : {0} time(s), {1}/day, last {2}' -f $f.Count, $f.PerDay, (Format-LVGuiWhen -When $f.LastSeen)))
        if ($f.RuleId) { $lines.Add(('Rule      : {0}' -f $f.RuleId)) }
        $lines.Add('')
        $lines.Add(('Plain English : {0}' -f $f.Plain))
        $lines.Add(('Why           : {0}' -f $f.Why))
        $lines.Add(('What to do    : {0}' -f $f.Action))
        foreach ($r in @($f.References | Where-Object { $_ })) { $lines.Add(('Source        : {0}' -f $r)) }
        $lines.Add('')
        $lines.Add('Raw evidence:')
        $lines.Add([string]$f.SampleMessage)

        try {
            [System.Windows.Clipboard]::SetText(($lines -join [Environment]::NewLine))
            & $setStatus 'Finding copied to the clipboard.'
        } catch {
            & $setStatus ('Could not reach the clipboard: {0}' -f $_.Exception.Message)
        }
    })

    # ------------------------------------------------------------------ pump -----

    # 120ms is fast enough that the log reads as live and slow enough that a chatty
    # scan cannot starve the UI thread with its own progress.
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(120)
    $timer.Add_Tick({
        & $drainLog

        if ($null -eq $state.Job) { $timer.Stop(); return }
        if (-not $state.Job.Async.IsCompleted) { return }

        $timer.Stop()
        $job = $state.Job
        $state.Job = $null

        try {
            $result = Complete-LVScanJob -Job $job
            # The worker can enqueue between the last drain and its final return, so
            # drain once more before the queue is dropped.
            & $drainLog
            & $setScanning $false
            & $renderResult $result
        } catch {
            & $drainLog
            & $setScanning $false
            & $appendLog 'error' ('{0:yyyy-MM-dd HH:mm:ss}' -f (Get-Date)) ([string]$_.Exception.Message)
            & $setStatus ('Scan failed: {0}' -f $_.Exception.Message)
            $ui.TxtActivityState.Text = 'Failed'
            $ui.TxtActivityHeadline.Text = 'The scan did not finish'
            $ui.TxtEmptyTitle.Text = 'The scan did not finish'
            $ui.TxtEmptyBody.Text = 'Open Activity for the full diagnostic message.'
            $ui.PnlEmpty.Visibility = 'Visible'
        }
    })
    $state.Timer = $timer

    $window.Add_Closing({
        $timer.Stop()
        [System.Windows.SystemParameters]::remove_StaticPropertyChanged($systemThemeChanged)

        $savedDays = 0
        if (-not [int]::TryParse($ui.TxtOverviewDays.Text.Trim(), [ref]$savedDays) -or
            $savedDays -lt 1 -or $savedDays -gt 3650) {
            $savedDays = $initialDays
        }
        $bounds = $window.RestoreBounds
        $null = Save-LVGuiSetting -Settings ([pscustomobject]@{
            DaysBack      = $savedDays
            AllChannels   = [bool]$ui.ChkOverviewAllChannels.IsChecked
            SkipTextLogs  = -not [bool]$ui.ChkOverviewIncludeText.IsChecked
            IncludeBenign = [bool]$ui.ChkOverviewIncludeBenign.IsChecked
            WindowWidth   = $bounds.Width
            WindowHeight  = $bounds.Height
        })

        if ($state.Job) {
            Stop-LVScanJob -Job $state.Job -Confirm:$false
            $state.Job = $null
        }
    })

    if ($AutoScan) {
        $window.Add_ContentRendered({ $ui.BtnScan.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))) })
    }

    & $showPage 'Overview'
    $null = $window.ShowDialog()

    if ($PassThru) { return $state.Result }
}
