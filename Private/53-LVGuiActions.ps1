function New-LVGuiActions {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'This constructor returns the set of GUI actions used by the window.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $ui = $Context.Ui
    $state = $Context.State
    $window = $Context.Window
    $structuredFilterControl = $Context.StructuredFilterControl
    $chipControl = $Context.ChipControl
    $pageControl = $Context.PageControl
    $navControl = $Context.NavControl
    $activityMaxLines = $Context.ActivityMaxLines
    $activityMaxCharacters = $Context.ActivityMaxCharacters
    $testFindingVisible = ${function:Test-LVGuiFindingVisible}

    $setStatus = {
        param([string]$Message)
        $ui.TxtStatus.Text = $Message
    }.GetNewClosure()

    $showPage = {
        param([string]$Name)
        if (-not $pageControl.ContainsKey($Name)) { return }
        foreach ($key in $pageControl.Keys) {
            $pageControl[$key].Visibility = $(if ($key -eq $Name) { 'Visible' } else { 'Collapsed' })
            $navControl[$key].IsChecked = ($key -eq $Name)
        }
        $state.CurrentPage = $Name
    }.GetNewClosure()

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
    }.GetNewClosure()

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
            $ui.TxtEmptyBody.Text = 'All ' + $total + ' finding(s) are hidden. Clear the search box, reset a structured filter, or switch a verdict back on in the left panel.'
            $ui.PnlEmpty.Visibility = 'Visible'
        } elseif ($shown -eq 0) {
            $ui.PnlEmpty.Visibility = 'Visible'
        } else {
            $ui.PnlEmpty.Visibility = 'Collapsed'
        }
    }.GetNewClosure()

    $revealPriorityFinding = {
        param($Row)
        if ($null -eq $Row) { return $false }
        $visible = & $testFindingVisible -Row $Row -EnabledVerdict $state.Chips `
            -Search $state.Search -StructuredFilter $state.StructuredFilters
        if ($visible) { return $false }

        $state.Search = ''
        $ui.TxtSearch.Text = ''
        $ui.TxtSearchHint.Visibility = 'Visible'
        foreach ($verdict in @($state.Chips.Keys)) {
            $state.Chips[$verdict] = $true
            if ($chipControl.ContainsKey($verdict)) { $chipControl[$verdict].IsChecked = $true }
        }
        foreach ($kind in @($state.StructuredFilters.Keys)) {
            $state.StructuredFilters[$kind] = ''
            if ($structuredFilterControl.ContainsKey($kind)) { $structuredFilterControl[$kind].SelectedIndex = 0 }
        }
        & $applyFilter
        $title = if ($Row.PSObject.Properties['Title'] -and $Row.Title) { [string]$Row.Title } else { 'This finding' }
        & $setStatus ('{0} was hidden by active filters; filters were cleared so it can be selected.' -f $title)
        return $true
    }.GetNewClosure()

    $resolveFinding = {
        param($Row)
        if ($null -eq $Row -or $null -eq $state.FindingStore) { return $null }
        $index = -1
        if ($Row.PSObject.Properties['FindingIndex']) { $index = [int]$Row.FindingIndex }
        if ($index -lt 0 -or $index -ge $state.FindingStore.Count) { return $null }
        return $state.FindingStore[$index]
    }.GetNewClosure()

    $showDetail = {
        param($Row)

        if ($null -eq $Row) {
            $ui.ScrDetail.Visibility = 'Collapsed'
            $ui.TxtNoSelection.Visibility = 'Visible'
            $ui.BtnCopy.IsEnabled = $false
            return
        }

        $finding = & $resolveFinding $Row
        if ($null -eq $finding) {
            $ui.ScrDetail.Visibility = 'Collapsed'
            $ui.TxtNoSelection.Visibility = 'Visible'
            $ui.BtnCopy.IsEnabled = $false
            return
        }
        $detail = ConvertTo-LVGuiDetail -Finding $finding

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

        $referenceBuckets = Get-LVGuiReferenceBucket -Reference $detail.Reference
        $ui.LstRefs.ItemsSource = [string[]]$referenceBuckets.Allowed
        $ui.LstUnsafeRefs.ItemsSource = [string[]]$referenceBuckets.Blocked
        if (@($referenceBuckets.Allowed).Count -gt 0 -or @($referenceBuckets.Blocked).Count -gt 0) {
            $ui.PnlRefs.Visibility = 'Visible'
        } else {
            $ui.PnlRefs.Visibility = 'Collapsed'
        }

        $ui.TxtSample.Text = $detail.SampleText
        $ui.TxtProvenance.Text = $detail.Provenance
    }.GetNewClosure()

    $renderActivity = {
        $projection = Get-LVGuiActivityProjection -Lines ([string[]]$state.ActivityLines) `
            -Search $ui.TxtActivitySearch.Text -Dropped $state.ActivityDropped `
            -MaxLines $activityMaxLines -MaxCharacters $activityMaxCharacters
        $ui.TxtActivitySearchHint.Visibility = $(if ($projection.Search) { 'Collapsed' } else { 'Visible' })
        $ui.TxtActivityLog.Text = $projection.Text
        $ui.TxtActivityLog.ScrollToEnd()
    }.GetNewClosure()

    $appendLog = {
        param([string]$Level, [string]$Stamp, [string]$Message)

        $marks = @{ info = '[ ]'; ok = '[+]'; warn = '[!]'; error = '[x]'; step = '===' }
        $mark = $marks[$Level]
        if (-not $mark) { $mark = '[ ]' }

        # The scan ran in a worker runspace, so the module's own transcript is empty in
        # this one. Rebuilding it here is what stops the exported LogVerdict-Run.log
        # from being a blank file whenever the report came from the window.
        $transcriptLine = '{0} {1} {2}' -f $Stamp, $mark, $Message
        Add-LVLogLine -List $script:LVLogLines -Line $transcriptLine

        $clock = $Stamp
        if ($Stamp.Length -ge 19) { $clock = $Stamp.Substring(11, 8) }
        $panelLine = '{0}  {1} {2}{3}' -f $clock, $mark, $Message, [Environment]::NewLine

        Add-LVGuiActivityLine -Lines $state.ActivityLines -Line $panelLine `
            -Characters ([ref]$state.ActivityCharacters) -Dropped ([ref]$state.ActivityDropped) `
            -MaxLines $activityMaxLines -MaxCharacters $activityMaxCharacters | Out-Null
        & $renderActivity
        $ui.TxtActivityLastLine.Text = $Message
        $ui.TxtStatus.Text = $Message
    }.GetNewClosure()

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
    }.GetNewClosure()

    $setScanning = {
        param([bool]$On)
        $state.Scanning = $On
        $ui.BtnOverviewScan.IsEnabled = -not $On
        $ui.BtnOverviewCancel.Visibility = $(if ($On) { 'Visible' } else { 'Collapsed' })
        $ui.BtnActivityRunAgain.IsEnabled = -not $On
        $ui.PbScan.Visibility = $(if ($On) { 'Visible' } else { 'Collapsed' })
        $ui.PbScan.IsIndeterminate = $On
        if ($On) {
            $ui.BtnCopySummary.IsEnabled = $false
        } elseif ($state.Result) {
            $ui.BtnCopySummary.IsEnabled = $true
        }
        foreach ($n in @('BtnElevate')) {
            $ui[$n].IsEnabled = -not $On
        }
        foreach ($n in @('TxtOverviewDays', 'ChkOverviewAllChannels', 'ChkOverviewIncludeText',
                'ChkOverviewDiagnosticChannels', 'ChkOverviewIncludeBenign', 'ChkOverviewIncludeLowConfidence', 'TxtOverviewChannels',
                'TxtOverviewDatabase', 'BtnOverviewBrowseDatabase', 'TxtOverviewSuppression', 'BtnOverviewBrowseSuppression', 'ChkOverviewSkipReliability',
                'TxtOverviewOutputDir', 'BtnOverviewBrowseOutput', 'ChkOverviewRedact',
                'ChkOverviewEvidence', 'BtnResetSettings', 'BtnCoverageElevate', 'BtnSideElevate')) {
            $ui[$n].IsEnabled = -not $On
        }
        if ($On) {
            $ui.BtnOverviewScan.Content = 'Scanning...'
            $ui.TxtActivityState.Text = 'Scanning...'
            $ui.TxtActivityHeadline.Text = 'Collecting and reducing diagnostic records'
        } else {
            $ui.BtnOverviewScan.Content = 'Run scan'
        }
    }.GetNewClosure()

    $syncOverviewOptions = {
        $hintDays = 30
        if ([int]::TryParse($ui.TxtOverviewDays.Text.Trim(), [ref]$hintDays) -and $hintDays -ge 1 -and $hintDays -le 3650) {
            $ui.TxtOverviewTimingHint.Text = Get-LVGuiScanTimingHint -DaysBack $hintDays
        }
    }.GetNewClosure()

    $resetOverviewOptions = {
        $ui.TxtOverviewDays.Text = '30'
        $ui.TxtOverviewTimingHint.Text = Get-LVGuiScanTimingHint -DaysBack 30
        $ui.ChkOverviewAllChannels.IsChecked = $false
        $ui.ChkOverviewIncludeText.IsChecked = $true
        $ui.ChkOverviewDiagnosticChannels.IsChecked = $false
        $ui.ChkOverviewIncludeBenign.IsChecked = $false
        $ui.ChkOverviewIncludeLowConfidence.IsChecked = $false
        $ui.TxtOverviewChannels.Text = ''
        $ui.TxtOverviewDatabase.Text = ''
        $ui.TxtOverviewSuppression.Text = ''
        $ui.ChkOverviewSkipReliability.IsChecked = $false
        $ui.TxtOverviewOutputDir.Text = ''
        $ui.ChkOverviewRedact.IsChecked = $false
        $ui.ChkOverviewEvidence.IsChecked = $false
        & $syncOverviewOptions
        $window.WindowState = 'Normal'
        $window.Width = 1440
        $window.Height = 800
    }.GetNewClosure()


    $renderResult = {
        param($Result)
        Set-LVGuiResultView -Context $Context -Result $Result
    }.GetNewClosure()

    return [ordered]@{
        SetStatus = $setStatus
        ShowPage = $showPage
        ChipContent = $chipContent
        ApplyFilter = $applyFilter
        ResolveFinding = $resolveFinding
        ShowDetail = $showDetail
        RevealPriorityFinding = $revealPriorityFinding
        RenderActivity = $renderActivity
        AppendLog = $appendLog
        DrainLog = $drainLog
        SetScanning = $setScanning
        RenderResult = $renderResult
        SyncOverviewOptions = $syncOverviewOptions
        ResetOverviewOptions = $resetOverviewOptions
    }
}
