function Initialize-LVGuiControls {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'The initializer wires the complete set of GUI controls.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $ui = $Context.Ui
    $state = $Context.State
    $window = $Context.Window
    $themeSnapshot = $Context.ThemeSnapshot
    $renderResult = $Context.Actions.RenderResult
    $showPage = $Context.Actions.ShowPage
    $initialDays = $Context.InitialDays

    # ----------------------------------------------------------------- events ----

    $ui.TxtVersion.Text = 'v{0}' -f $script:LVVersion
    $ui.TxtSideMachine.Text = $env:COMPUTERNAME
    $ui.TxtOverviewDays.Text = [string]$initialDays
    $ui.TxtOverviewTimingHint.Text = Get-LVGuiScanTimingHint -DaysBack $initialDays
    $ui.ChkOverviewAllChannels.IsChecked = $Context.InitialAllChannels
    $ui.ChkOverviewDiagnosticChannels.IsChecked = $Context.InitialDiagnosticChannels
    $ui.ChkOverviewIncludeText.IsChecked = -not $Context.InitialSkipText
    $ui.ChkOverviewIncludeBenign.IsChecked = $Context.InitialIncludeBenign
    $ui.ChkOverviewIncludeLowConfidence.IsChecked = $Context.InitialIncludeLowConfidence
    $ui.TxtOverviewChannels.Text = $Context.InitialNamedChannels
    $ui.TxtOverviewDatabase.Text = $Context.InitialDatabasePath
    $ui.TxtOverviewSuppression.Text = $Context.InitialSuppressionPath
    $ui.ChkOverviewSkipReliability.IsChecked = $Context.InitialSkipReliability
    $ui.TxtOverviewOutputDir.Text = $Context.InitialOutputDirectory
    $ui.ChkOverviewRedact.IsChecked = $Context.InitialRedact
    $ui.ChkOverviewEvidence.IsChecked = $Context.InitialIncludeEvidence
    $ui.BtnFindingsSave.IsEnabled = $false
    $ui.BtnFindingsOpen.IsEnabled = $false
    $ui.BtnCopySummary.IsEnabled = $false
    $ui.BtnActivitySave.IsEnabled = $false
    $ui.BtnActivityOpen.IsEnabled = $false

    if (Test-LVElevated) {
        $ui.TxtSideElevation.Text = 'Administrator access'
        $ui.TxtSideElevation.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Green')
        $ui.BtnCoverageElevate.Visibility = 'Collapsed'
    } else {
        $ui.TxtSideElevation.Text = 'Standard access'
        $ui.PnlElevate.Visibility = 'Visible'
        $ui.BtnSideElevate.Visibility = 'Visible'
    }

    $window.Add_SourceInitialized({ Enable-LVDarkTitleBar -Window $window }.GetNewClosure())

    $systemThemeChanged = {
        param($SenderObject, $ThemeEventArgs)
        $null = $SenderObject
        if ($ThemeEventArgs.PropertyName -ne 'HighContrast') { return }

        $null = Sync-LVGuiTheme -Window $window -Snapshot $themeSnapshot
        Enable-LVDarkTitleBar -Window $window

        # Verdict colours are projected into bound row objects rather than resource
        # references, so rebuild those objects when the system palette changes.
        if ($state.Result) { & $renderResult $state.Result }
    }.GetNewClosure()
    $systemThemeChanged = [System.ComponentModel.PropertyChangedEventHandler]$systemThemeChanged
    [System.Windows.SystemParameters]::add_StaticPropertyChanged($systemThemeChanged)

    # Checked, not Click: TogglePattern is how assistive automation activates a
    # ToggleButton. Mouse, keyboard and UI Automation must all navigate identically.
    $ui.NavOverview.Add_Checked({ & $showPage 'Overview' }.GetNewClosure())
    $ui.NavFindings.Add_Checked({ & $showPage 'Findings' }.GetNewClosure())
    $ui.NavCoverage.Add_Checked({ & $showPage 'Coverage' }.GetNewClosure())
    $ui.NavActivity.Add_Checked({ & $showPage 'Activity' }.GetNewClosure())

    $Context.SystemThemeChanged = $systemThemeChanged
}

function Register-LVGuiOptionHandlers {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'The function registers the complete set of option handlers.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '',
        Justification = 'The option synchronizer is captured by routed-event closures.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $ui = $Context.Ui
    $window = $Context.Window
    $showPage = $Context.Actions.ShowPage
    $syncOverviewOptions = $Context.Actions.SyncOverviewOptions
    $resetOverviewOptions = $Context.Actions.ResetOverviewOptions

    $ui.BtnActivityRunAgain.Add_Click({
        $ui.BtnOverviewScan.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    }.GetNewClosure())

    $ui.ChkOverviewAllChannels.Add_Checked({
        $ui.ChkOverviewDiagnosticChannels.IsChecked = $false
    }.GetNewClosure())
    $ui.ChkOverviewDiagnosticChannels.Add_Checked({
        $ui.ChkOverviewAllChannels.IsChecked = $false
    }.GetNewClosure())
    $ui.TxtOverviewChannels.Add_TextChanged({
        if ($ui.TxtOverviewChannels.Text.Trim()) {
            $ui.ChkOverviewAllChannels.IsChecked = $false
            $ui.ChkOverviewDiagnosticChannels.IsChecked = $false
        }
    }.GetNewClosure())

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
    }.GetNewClosure())

    $ui.BtnOverviewBrowseSuppression.Add_Click({
        $dialog = New-Object Microsoft.Win32.OpenFileDialog
        $dialog.Title = 'Choose suppression expectations'
        $dialog.Filter = 'JSON suppression set (*.json)|*.json|All files (*.*)|*.*'
        $dialog.CheckFileExists = $true
        $current = $ui.TxtOverviewSuppression.Text.Trim()
        if ($current -and (Test-Path -LiteralPath $current -PathType Leaf)) {
            $dialog.InitialDirectory = Split-Path -Parent $current
            $dialog.FileName = Split-Path -Leaf $current
        }
        if ($dialog.ShowDialog($window)) { $ui.TxtOverviewSuppression.Text = $dialog.FileName }
    }.GetNewClosure())

    $ui.BtnOverviewBrowseOutput.Add_Click({
        $folder = Select-LVGuiFolder -Window $window -InitialDirectory $ui.TxtOverviewOutputDir.Text.Trim()
        if ($folder) { $ui.TxtOverviewOutputDir.Text = $folder }
    }.GetNewClosure())
    $ui.BtnResetSettings.Add_Click({
        & $resetOverviewOptions
        if (Reset-LVGuiSetting) {
            $ui.TxtSettingsStatus.Text = 'Saved settings reset; safe defaults are active.'
            $ui.TxtSettingsStatus.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Green')
        } else {
            $ui.TxtSettingsStatus.Text = 'Defaults are active for this session; the saved file could not be updated.'
            $ui.TxtSettingsStatus.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Yellow')
        }
    }.GetNewClosure())
    $ui.BtnViewFindings.Add_Click({ & $showPage 'Findings' }.GetNewClosure())
    $ui.BtnViewCoverage.Add_Click({ & $showPage 'Coverage' }.GetNewClosure())
    $ui.BtnCoverageElevate.Add_Click({
        $ui.BtnElevate.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    }.GetNewClosure())
    $ui.BtnSideElevate.Add_Click({
        $ui.BtnElevate.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    }.GetNewClosure())

}

function Register-LVGuiInteractionHandlers {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'The function registers the complete set of interaction handlers.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $ui = $Context.Ui
    $window = $Context.Window
    $state = $Context.State
    $chipControl = $Context.ChipControl
    $structuredFilterControl = $Context.StructuredFilterControl
    $showPage = $Context.Actions.ShowPage
    $showDetail = $Context.Actions.ShowDetail
    $applyFilter = $Context.Actions.ApplyFilter
    $revealPriorityFinding = $Context.Actions.RevealPriorityFinding
    $setStatus = $Context.Actions.SetStatus
    $renderActivity = $Context.Actions.RenderActivity

    $ui.BtnFindingsSave.Add_Click({
        $ui.BtnSaveReport.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    }.GetNewClosure())
    $ui.BtnActivitySave.Add_Click({
        $ui.BtnSaveReport.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    }.GetNewClosure())
    $ui.BtnFindingsOpen.Add_Click({
        $ui.BtnOpenReport.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    }.GetNewClosure())
    $ui.BtnActivityOpen.Add_Click({
        $ui.BtnOpenReport.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
    }.GetNewClosure())

    $ui.BtnActivityClear.Add_Click({
        $state.ActivityLines.Clear()
        $state.ActivityCharacters = 0
        $state.ActivityDropped = 0
        $ui.TxtActivityLog.Clear()
        $ui.TxtActivityLastLine.Text = ''
    }.GetNewClosure())

    $ui.TxtActivitySearch.Add_TextChanged({
        & $renderActivity
    }.GetNewClosure())

    $ui.TxtSearch.Add_TextChanged({
        $text = $ui.TxtSearch.Text
        $ui.TxtSearchHint.Visibility = $(if ($text) { 'Collapsed' } else { 'Visible' })
        $state.Search = $text.Trim().ToLowerInvariant()
        & $applyFilter
    }.GetNewClosure())

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
        }.GetNewClosure()
        $chip.Add_Checked($handler)
        $chip.Add_Unchecked($handler)
    }

    foreach ($filterKind in $structuredFilterControl.Keys) {
        $control = $structuredFilterControl[$filterKind]
        $control.Tag = $filterKind
        $control.Add_SelectionChanged({
            param($SenderControl, $SelectionArgs)
            $null = $SelectionArgs
            $kind = [string]$SenderControl.Tag
            $value = $SenderControl.SelectedValue
            if ($null -eq $value) { $value = '' }
            $state.StructuredFilters[$kind] = [string]$value
            & $applyFilter
        }.GetNewClosure())
    }

    $ui.LvFindings.Add_SelectionChanged({
        & $showDetail $ui.LvFindings.SelectedItem
    }.GetNewClosure())

    $ui.LvPriority.Add_SelectionChanged({
        $priorityRow = $ui.LvPriority.SelectedItem
        if ($null -eq $priorityRow) { return }
        & $showPage 'Findings'
        $null = & $revealPriorityFinding $priorityRow
        $ui.LvFindings.SelectedItem = $priorityRow
        $ui.LvFindings.ScrollIntoView($priorityRow)
    }.GetNewClosure())

    $ui.LvFindings.AddHandler(
        [System.Windows.Controls.GridViewColumnHeader]::ClickEvent,
        [System.Windows.RoutedEventHandler] {
            param($SenderControl, $RoutedArgs)
            $null = $SenderControl
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
        }.GetNewClosure()
    )

    $window.AddHandler(
        [System.Windows.Documents.Hyperlink]::RequestNavigateEvent,
        [System.Windows.Navigation.RequestNavigateEventHandler] {
            param($SenderControl, $NavigateArgs)
            $null = $SenderControl
            $uri = [string]$NavigateArgs.Uri.AbsoluteUri
            $uriProblem = Get-LVAllowedUriProblem -Uri $uri
            if ($uriProblem) {
                & $setStatus ('Blocked link: {0}' -f $uriProblem)
                $NavigateArgs.Handled = $true
                return
            }
            try {
                Start-Process -FilePath $uri
                & $setStatus ('Opened {0}' -f $uri)
            } catch {
                & $setStatus ('Could not open {0}: {1}' -f $uri, $_.Exception.Message)
            }
            $NavigateArgs.Handled = $true
        }.GetNewClosure()
    )

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
    }.GetNewClosure())

}

function Register-LVGuiScanHandlers {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'The function registers the complete set of scan handlers.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = 'Scan settings are captured by the asynchronous scan click closure.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '',
        Justification = 'Scan actions and window references are captured by asynchronous event closures.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [string]$AdvisoryPath, [string]$AdvisoryPackage, [string]$AdvisoryVersion, [string]$CaseProfilePath
    )
    $ui = $Context.Ui
    $state = $Context.State
    $showPage = $Context.Actions.ShowPage
    $setStatus = $Context.Actions.SetStatus
    $setScanning = $Context.Actions.SetScanning
    $drainLog = $Context.Actions.DrainLog
    $appendLog = $Context.Actions.AppendLog
    $syncOverviewOptions = $Context.Actions.SyncOverviewOptions
    $renderResult = $Context.Actions.RenderResult
    $resolveFinding = $Context.Actions.ResolveFinding
    $window = $Context.Window

    $ui.BtnOverviewScan.Add_Click({
        if ($state.Scanning) { return }

        & $syncOverviewOptions
        & $showPage 'Activity'

        $days = 0
        if (-not [int]::TryParse($ui.TxtOverviewDays.Text.Trim(), [ref]$days) -or $days -lt 1 -or $days -gt 3650) {
            $days = 30
            $ui.TxtOverviewDays.Text = '30'
            & $setStatus 'Look-back must be a whole number of days between 1 and 3650. Reset to 30.'
        }

        $ui.TxtActivityLog.Clear()
        $state.ActivityLines.Clear()
        $state.ActivityCharacters = 0
        $state.ActivityDropped = 0
        $ui.TxtActivitySearch.Clear()
        $ui.TxtActivityLastLine.Text = ''
        # Each report carries its own scan's transcript, not everything since launch.
        $script:LVLogLines.Clear()
        $script:LVLogLinesTruncated = $false
        $state.Sink = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
        $state.ReportDir = $null
        $state.HtmlPath = $null
        $ui.BtnOpenReport.IsEnabled = $false
        $ui.BtnSaveReport.IsEnabled = $false
        $ui.BtnFindingsOpen.IsEnabled = $false
        $ui.BtnFindingsSave.IsEnabled = $false
        $ui.BtnCopySummary.IsEnabled = $false
        $ui.BtnActivityOpen.IsEnabled = $false
        $ui.BtnActivitySave.IsEnabled = $false
        $ui.TxtActivityReportState.Text = 'Not saved yet'
        $ui.PnlEmpty.Visibility = 'Collapsed'
        $state.Result = $null
        $state.ScanStartedAt = $null

        $databasePath = $ui.TxtOverviewDatabase.Text.Trim()
        if ($databasePath) {
            if (-not (Test-Path -LiteralPath $databasePath -PathType Leaf)) {
                & $setStatus ('Rule database not found: {0}' -f $databasePath)
                & $showPage 'Overview'
                return
            }
        }

        $suppressionPath = $ui.TxtOverviewSuppression.Text.Trim()
        if ($suppressionPath) {
            if (-not (Test-Path -LiteralPath $suppressionPath -PathType Leaf)) {
                & $setStatus ('Suppression expectations not found: {0}' -f $suppressionPath)
                & $showPage 'Overview'
                return
            }
        }

        $scanArgs = Get-LVGuiScanArguments -DaysBack $days `
            -IncludeTextLogs ([bool]$ui.ChkOverviewIncludeText.IsChecked) `
            -SkipReliability ([bool]$ui.ChkOverviewSkipReliability.IsChecked) `
            -IncludeBenign ([bool]$ui.ChkOverviewIncludeBenign.IsChecked) `
            -IncludeLowConfidence ([bool]$ui.ChkOverviewIncludeLowConfidence.IsChecked) `
            -NamedChannels $ui.TxtOverviewChannels.Text `
            -AllChannels ([bool]$ui.ChkOverviewAllChannels.IsChecked) `
            -DiagnosticChannels ([bool]$ui.ChkOverviewDiagnosticChannels.IsChecked) `
            -DatabasePath $databasePath -SuppressionPath $suppressionPath `
            -AdvisoryPath $AdvisoryPath -AdvisoryPackage $AdvisoryPackage `
            -AdvisoryVersion $AdvisoryVersion -CaseProfilePath $CaseProfilePath

        try {
            $state.Job = Start-LVScanJob -ScanArgs $scanArgs -LogSink $state.Sink
            $state.ScanStartedAt = Get-Date
            $state.SmokeHoldUntil = $null
            $holdMilliseconds = 0
            if ([int]::TryParse([string]$env:LOGVERDICT_GUI_SMOKE_HOLD_MS, [ref]$holdMilliseconds) -and $holdMilliseconds -gt 0) {
                # A bounded test-only hold makes the packaged cancellation path
                # deterministic without slowing ordinary launches or changing scan
                # collection semantics.
                $state.SmokeHoldUntil = (Get-Date).AddMilliseconds([Math]::Min(30000, $holdMilliseconds))
            }
        } catch {
            $state.ScanStartedAt = $null
            & $setStatus ('Could not start the scan: {0}' -f $_.Exception.Message)
            return
        }

        & $setScanning $true
        & $setStatus 'Scanning...'
        & $showPage 'Activity'
        $state.Timer.Start()
    }.GetNewClosure())

    $ui.BtnOverviewCancel.Add_Click({
        if (-not $state.Scanning) { return }
        $elapsed = if ($state.ScanStartedAt) { ((Get-Date) - $state.ScanStartedAt).TotalSeconds } else { 0 }
        $state.Timer.Stop()
        Stop-LVScanJob -Job $state.Job -Confirm:$false
        $state.Job = $null
        $state.ScanStartedAt = $null
        & $drainLog
        & $setScanning $false
        & $appendLog 'warn' ('{0:yyyy-MM-dd HH:mm:ss}' -f (Get-Date)) ('Scan cancelled after {0:N1}s; coverage is partial and no report was saved.' -f $elapsed)
        & $setStatus 'Scan cancelled. Partial coverage is shown in Activity; nothing on this machine was changed.'
        $ui.TxtActivityState.Text = 'Cancelled - partial coverage'
        $ui.TxtActivityHeadline.Text = 'The scan was cancelled before completion. Partial coverage is shown; nothing was changed.'
        $ui.TxtActivityDuration.Text = '{0:N1}s (cancelled)' -f $elapsed
        $ui.TxtOverviewScanTime.Text = 'Cancelled after {0:N1}s; partial coverage' -f $elapsed
        $ui.TxtOverviewCoverage.Text = 'Partial coverage - cancelled before completion; no report was saved.'
        $ui.TxtActivityReportState.Text = 'Not saved - scan cancelled'
    }.GetNewClosure())

    $ui.BtnSaveReport.Add_Click({
        if ($null -eq $state.Result) { return }
        try {
            $outputDir = $ui.TxtOverviewOutputDir.Text.Trim()
            $exportArgs = Get-LVGuiExportArguments -Result $state.Result `
                -Redact ([bool]$ui.ChkOverviewRedact.IsChecked) `
                -IncludeEvidence ([bool]$ui.ChkOverviewEvidence.IsChecked) `
                -OutputDirectory $outputDir
            $out = Export-LogVerdictReport @exportArgs
            $state.ReportDir = $out.OutputDir
            $state.HtmlPath = ($out.Files | Where-Object { $_ -like '*.html' } | Select-Object -First 1)
            $ui.BtnOpenReport.IsEnabled = $true
            $ui.BtnFindingsOpen.IsEnabled = $true
            $ui.BtnActivityOpen.IsEnabled = $true
            $ui.TxtActivityReportState.Text = 'Saved to {0}' -f $out.OutputDir
            $manifestNote = if ($out.EvidenceBundleManifest) { '; evidence manifest: {0}' -f $out.EvidenceBundleManifest } else { '' }
            & $setStatus ('Report written to {0}{1}' -f $out.OutputDir, $manifestNote)
        } catch {
            & $setStatus ('Could not write the report: {0}' -f $_.Exception.Message)
        }
    }.GetNewClosure())

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
    }.GetNewClosure())

    $ui.BtnCopy.Add_Click({
        $row = $ui.LvFindings.SelectedItem
        if ($null -eq $row) { return }
        $f = & $resolveFinding $row
        if ($null -eq $f) { return }

        try {
            $clipboard = ConvertTo-LVGuiClipboardText -Finding $f `
                -Redact:([bool]$ui.ChkOverviewRedact.IsChecked) `
                -MachineName $state.Result.MachineName -UserName $env:USERNAME
            [System.Windows.Clipboard]::SetText($clipboard.Text)
            & $setStatus $clipboard.Status
        } catch {
            & $setStatus ('Could not reach the clipboard: {0}' -f $_.Exception.Message)
        }
    }.GetNewClosure())

    $ui.BtnCopySummary.Add_Click({
        if ($null -eq $state.Result) { return }
        try {
            $summary = ConvertTo-LVTicketSummary -Result $state.Result `
                -Redact:([bool]$ui.ChkOverviewRedact.IsChecked) `
                -MachineName $state.Result.MachineName -UserName $env:USERNAME
            [System.Windows.Clipboard]::SetText($summary)
            & $setStatus 'Ticket summary copied to the clipboard.'
        } catch {
            & $setStatus ('Could not reach the clipboard: {0}' -f $_.Exception.Message)
        }
    }.GetNewClosure())

}

function Register-LVGuiPumpHandlers {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'The function registers the dispatcher and window-lifecycle handlers.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context, [switch]$AutoScan)
    $ui = $Context.Ui
    $state = $Context.State
    $window = $Context.Window
    $timer = $null
    $systemThemeChanged = $Context.SystemThemeChanged
    $initialDays = $Context.InitialDays
    $documentationScreenshotPath = $Context.DocumentationScreenshotPath
    $drainLog = $Context.Actions.DrainLog
    $setScanning = $Context.Actions.SetScanning
    $appendLog = $Context.Actions.AppendLog
    $renderResult = $Context.Actions.RenderResult
    $setStatus = $Context.Actions.SetStatus

    # ------------------------------------------------------------------ pump -----

    # 120ms is fast enough that the log reads as live and slow enough that a chatty
    # scan cannot starve the UI thread with its own progress.
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(120)
    $timer.Add_Tick({
        & $drainLog

        if ($state.Scanning -and $state.ScanStartedAt) {
            $elapsed = ((Get-Date) - $state.ScanStartedAt).TotalSeconds
            $ui.TxtActivityDuration.Text = '{0:N1}s (running)' -f $elapsed
            $ui.TxtOverviewScanTime.Text = 'Running for {0:N1}s...' -f $elapsed
        }
        if ($null -eq $state.Job) { $timer.Stop(); return }
        if (-not $state.Job.Async.IsCompleted) { return }
        if ($state.SmokeHoldUntil -and (Get-Date) -lt $state.SmokeHoldUntil) { return }

        $timer.Stop()
        $job = $state.Job
        $state.Job = $null
        $state.SmokeHoldUntil = $null

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
            $state.ScanStartedAt = $null
            & $setStatus ('Scan failed: {0}' -f $_.Exception.Message)
            $ui.TxtActivityState.Text = 'Failed'
            $ui.TxtActivityHeadline.Text = 'The scan did not finish'
            $ui.TxtEmptyTitle.Text = 'The scan did not finish'
            $ui.TxtEmptyBody.Text = 'Open Activity for the full diagnostic message.'
            $ui.PnlEmpty.Visibility = 'Visible'
        }
    }.GetNewClosure())
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
            DiagnosticChannels = [bool]$ui.ChkOverviewDiagnosticChannels.IsChecked
            SkipTextLogs  = -not [bool]$ui.ChkOverviewIncludeText.IsChecked
            SkipReliability = [bool]$ui.ChkOverviewSkipReliability.IsChecked
            IncludeBenign = [bool]$ui.ChkOverviewIncludeBenign.IsChecked
            IncludeLowConfidence = [bool]$ui.ChkOverviewIncludeLowConfidence.IsChecked
            NamedChannels = $ui.TxtOverviewChannels.Text
            DatabasePath = $ui.TxtOverviewDatabase.Text
            SuppressionPath = $ui.TxtOverviewSuppression.Text
            OutputDirectory = $ui.TxtOverviewOutputDir.Text
            Redact = [bool]$ui.ChkOverviewRedact.IsChecked
            IncludeEvidence = [bool]$ui.ChkOverviewEvidence.IsChecked
            WindowWidth   = $bounds.Width
            WindowHeight  = $bounds.Height
        }.GetNewClosure())

        if ($state.Job) {
            Stop-LVScanJob -Job $state.Job -Confirm:$false
            $state.Job = $null
        }
        $state.ScanStartedAt = $null
    }.GetNewClosure())

    if ($AutoScan) {
        $window.Add_ContentRendered({ $ui.BtnOverviewScan.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))) })
    }

    # Release QA can request a deterministic screenshot from WPF's own visual tree.
    # That avoids compositor and remote-desktop capture differences while ensuring the
    # documentation image is rendered by the exact packaged GUI being tested. The path
    # is explicit and bounded to the caller-owned ScreenshotDirectory above; no ambient
    # environment variable can cause the shipped GUI to write a file.
    if ($documentationScreenshotPath) {
        $window.Add_ContentRendered({
            $target = $documentationScreenshotPath
            $width = [Math]::Max(1, [int][Math]::Ceiling($window.ActualWidth))
            $height = [Math]::Max(1, [int][Math]::Ceiling($window.ActualHeight))
            $directory = [IO.Path]::GetDirectoryName($target)
            if ($directory) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
            $bitmap = New-Object System.Windows.Media.Imaging.RenderTargetBitmap(
                $width, $height, 96, 96, [System.Windows.Media.PixelFormats]::Pbgra32)
            $bitmap.Render($window)
            $encoder = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
            $encoder.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
            $stream = $null
            try {
                $stream = [IO.File]::Open($target, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::Read)
                $encoder.Save($stream)
                Write-LVLog -Level info -Message ("GUI screenshot written to {0}" -f $target)
            } catch {
                Write-LVLog -Level error -Message ("GUI screenshot could not be written to {0}: {1}" -f $target, $_.Exception.Message)
                throw
            } finally { if ($stream) { $stream.Dispose() } }
        }.GetNewClosure())
    }

    $Context.Timer = $timer
}
