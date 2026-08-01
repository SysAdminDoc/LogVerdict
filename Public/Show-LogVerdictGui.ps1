function Show-LogVerdictGui {
    <#
        .SYNOPSIS
        Open the LogVerdict window: scan this PC's logs and read the rulings.

        .DESCRIPTION
        A front end over Invoke-LogVerdictScan, not a second implementation of it. The
        scan runs unchanged on a background runspace and this window renders what comes
        back, so the GUI and the console tool can never disagree about a verdict.

        Read-only. Nothing on the machine is modified unless you press Save report,
        which writes to a folder on the Desktop.

        .PARAMETER DaysBack
        Pre-fills the look-back window. Default 30.

        .PARAMETER AutoScan
        Start scanning as soon as the window opens instead of waiting for Run scan.

        .PARAMETER PassThru
        After the window closes, return the last scan result object.

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
        [switch]$AutoScan,
        [switch]$PassThru
    )

    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        throw 'The LogVerdict window needs a single-threaded apartment. Start PowerShell with -STA, or run LogVerdict-GUI.ps1 which handles this for you.'
    }

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

    $window = [Windows.Markup.XamlReader]::Parse((Get-LVGuiXaml))

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
    }
    foreach ($v in $script:LVVerdictDisplayOrder) { $state.Chips[$v] = $true }

    $chipControl = @{
        'critical'      = $ui.ChipCritical
        'actionable'    = $ui.ChipActionable
        'investigate'   = $ui.ChipInvestigate
        'unknown'       = $ui.ChipUnknown
        'informational' = $ui.ChipInformational
        'benign'        = $ui.ChipBenign
    }

    # ---------------------------------------------------------------- helpers ----

    $setStatus = {
        param([string]$Message)
        $ui.TxtStatus.Text = $Message
    }

    $chipContent = {
        param([string]$Label, $Count)
        $dock = New-Object System.Windows.Controls.DockPanel
        $number = New-Object System.Windows.Controls.TextBlock
        $number.Text = [string]$Count
        $number.FontWeight = 'SemiBold'
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

        $f = $Row.Finding
        $style = Get-LVVerdictStyle -Verdict $f.Verdict

        $ui.TxtNoSelection.Visibility = 'Collapsed'
        $ui.ScrDetail.Visibility = 'Visible'
        $ui.BtnCopy.IsEnabled = $true

        $ui.TxtDetailVerdict.Text = $style.Label
        $ui.PillDetail.Background = $style.Fill
        $ui.TxtDetailVerdict.Foreground = $style.Ink
        $ui.TxtDetailTitle.Text = [string]$f.Title

        # Built as a list and joined: '-f' inside a method call's parentheses treats
        # the comma as an argument separator and starves the format operator.
        $meta = New-Object System.Collections.Generic.List[string]
        $meta.Add(('{0} occurrence(s)' -f $f.Count))
        $meta.Add(('{0}/day' -f $f.PerDay))
        if ($f.Source -eq 'event') {
            $meta.Add(('{0} event {1}' -f $f.Provider, $f.Id))
            $meta.Add(('{0} channel' -f $f.Channel))
        } else {
            $meta.Add(('{0} log' -f $f.Channel))
        }
        $meta.Add(('last seen {0}' -f (Format-LVGuiWhen -When $f.LastSeen)))
        if ($f.UndatedCount -gt 0) {
            $meta.Add(('{0} line(s) carried no timestamp' -f $f.UndatedCount))
        }
        $ui.TxtDetailMeta.Text = ($meta -join '  |  ')

        $ui.TxtPlain.Text  = [string]$f.Plain
        $ui.TxtWhy.Text    = [string]$f.Why
        $ui.TxtAction.Text = [string]$f.Action

        # The @() goes around the WHOLE pipeline, and the assignment re-wraps. A string
        # is itself IEnumerable, so an ItemsSource that received one bare string would
        # bind to its characters and render a rule's caveat one letter per line - which
        # is exactly what a single-element filter result produces without this.
        $fps = @($f.FalsePositives | Where-Object { $_ })
        if ($fps.Count -gt 0) {
            $ui.LstFalsePositives.ItemsSource = [string[]]$fps
            $ui.PnlFalsePositives.Visibility = 'Visible'
        } else {
            $ui.PnlFalsePositives.Visibility = 'Collapsed'
        }

        # Source URIs join the reference list so they are clickable; the licence and
        # author go on the provenance line, because a hyperlink whose text carries a
        # credit is no longer a usable URI.
        $refs = @(@(@($f.References) + @($f.Sources | ForEach-Object { $_.uri })) |
            Where-Object { $_ } | Select-Object -Unique)
        if ($refs.Count -gt 0) {
            $ui.LstRefs.ItemsSource = [string[]]$refs
            $ui.PnlRefs.Visibility = 'Visible'
        } else {
            $ui.PnlRefs.Visibility = 'Collapsed'
        }

        $samples = @($f.Samples | Where-Object { $_ })
        if ($samples.Count -eq 0) { $samples = @([string]$f.SampleMessage) }
        $ui.TxtSample.Text = (($samples | Select-Object -Unique) -join ([Environment]::NewLine * 2))

        if ($f.RuleId) {
            $prov = New-Object System.Collections.Generic.List[string]
            $prov.Add(('Rule {0}' -f $f.RuleId))
            if ($f.Status)     { $prov.Add([string]$f.Status) }
            if ($f.Confidence) { $prov.Add(('{0} confidence' -f $f.Confidence)) }
            if ($f.Verified)   { $prov.Add(('last verified {0}' -f $f.Verified)) }
            $line = ($prov -join ' - ') + '.'

            # CC-BY requires attribution and an indication of changes; DRL requires the
            # author be shown wherever the rule matches. Rendering it here is what makes
            # deriving from those corpora legal, not just the field in the database.
            $credits = New-Object System.Collections.Generic.List[string]
            foreach ($src in @($f.Sources)) {
                $parts = @($src.author, $src.licence) | Where-Object { $_ }
                if ($parts.Count -eq 0) { continue }
                $credit = $parts -join ', '
                if ($src.modified) { $credit += ', adapted' }
                if (-not $credits.Contains($credit)) { $credits.Add($credit) }
            }
            if ($credits.Count -gt 0) { $line += ' Derived from ' + ($credits -join '; ') + '.' }

            $ui.TxtProvenance.Text = $line
        } else {
            $ui.TxtProvenance.Text = 'No rule in the verdict database covers this signature. LogVerdict reports it as unrecognized rather than guessing at a cause.'
        }
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
        $ui.PbScan.Visibility = $(if ($On) { 'Visible' } else { 'Collapsed' })
        $ui.PbScan.IsIndeterminate = $On
        foreach ($n in @('TxtDays', 'ChkAllChannels', 'ChkSkipText', 'ChkIncludeBenign', 'BtnElevate')) {
            $ui[$n].IsEnabled = -not $On
        }
        if ($On) { $ui.BtnScan.Content = 'Scanning...' } else { $ui.BtnScan.Content = 'Run scan' }
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
            if (-not $state.Chips[$Item.Verdict]) { return $false }
            if ($state.Search -and $Item.Haystack -notlike ('*{0}*' -f $state.Search)) { return $false }
            return $true
        }
        $state.View = $view
        $ui.LvFindings.ItemsSource = $view

        # Counts are of everything found, not of what the filter is showing, so
        # switching a chip off never makes its own number change under the cursor.
        $counts = @{}
        foreach ($v in $script:LVVerdictDisplayOrder) { $counts[$v] = 0 }
        foreach ($f in @($Result.Findings)) {
            $key = [string]$f.Verdict
            if ($counts.ContainsKey($key)) { $counts[$key]++ } else { $counts['unknown']++ }
        }
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

        $ui.TxtRecords.Text    = '{0:N0}' -f $Result.Reduction.RecordCount
        $ui.TxtSignatures.Text = '{0:N0}' -f $Result.Reduction.SignatureCount
        $ui.TxtReduction.Text  = '{0}:1' -f $Result.Reduction.Ratio
        $ui.TxtRules.Text      = '{0:N0}' -f $Result.RuleCount
        $ui.PnlSummary.Visibility = 'Visible'

        $notes = @($Result.CoverageNotes | Where-Object { $_ })
        if ($Result.HorizonWarning) { $notes = @($notes) + @($Result.HorizonWarning) }
        if ($notes.Count -gt 0) {
            $ui.LstCoverage.ItemsSource = [string[]]$notes
            $ui.PnlCoverage.Visibility = 'Visible'
        } else {
            $ui.PnlCoverage.Visibility = 'Collapsed'
        }

        $ui.TxtEmptyTitle.Text = 'Nothing to report'
        $ui.TxtEmptyBody.Text = 'The scan completed and found no signature worth raising in the last ' + $Result.DaysBack + ' day(s). Check the panel on the left for anything the scan was not allowed to read.'

        # Crash evidence the console report has always shown and the window used to drop.
        $crash = Format-LVCrashArtifact -Artifact @($Result.CrashArtifacts)
        if ($crash.Count -gt 0) {
            $ui.LstCrash.ItemsSource = [string[]]$crash
            $ui.PnlCrash.Visibility = 'Visible'
        } else {
            $ui.PnlCrash.Visibility = 'Collapsed'
        }

        # Correlated findings. Filtered rather than merely wrapped: a result with no
        # Correlations property yields a one-element array holding null.
        $together = Format-LVCorrelation -Correlation @($Result.Correlations | Where-Object { $_ })
        if ($together.Count -gt 0) {
            $ui.LstCorrelation.ItemsSource = [string[]]$together
            $ui.PnlCorrelation.Visibility = 'Visible'
        } else {
            $ui.PnlCorrelation.Visibility = 'Collapsed'
        }

        $ui.BtnSaveReport.IsEnabled = $true

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

        $worst = Get-LVVerdictStyle -Verdict $Result.WorstVerdict
        $summary = 'Scan complete. {0} finding(s), worst is {1}. {2:N0} record(s) reduced to {3:N0} signature(s).' -f `
            @($Result.Findings).Count, $worst.Label, $Result.Reduction.RecordCount, $Result.Reduction.SignatureCount
        & $setStatus $summary
    }

    # ----------------------------------------------------------------- events ----

    $ui.TxtVersion.Text = 'v{0}' -f $script:LVVersion
    $ui.TxtMachine.Text = $env:COMPUTERNAME
    $ui.TxtDays.Text = [string]$DaysBack

    if (Test-LVElevated) {
        $ui.TxtElevation.Text = 'Administrator'
        $ui.TxtElevation.Foreground = '#a6e3a1'
    } else {
        $ui.TxtElevation.Text = 'Standard user'
        $ui.PnlElevate.Visibility = 'Visible'
    }

    $window.Add_SourceInitialized({ Enable-LVDarkTitleBar -Window $window })

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
        if (-not [int]::TryParse($ui.TxtDays.Text.Trim(), [ref]$days) -or $days -lt 1 -or $days -gt 3650) {
            $days = 30
            $ui.TxtDays.Text = '30'
            & $setStatus 'Look-back must be a whole number of days between 1 and 3650. Reset to 30.'
        }

        $ui.TxtLog.Clear()
        # Each report carries its own scan's transcript, not everything since launch.
        $script:LVLogLines.Clear()
        $state.Sink = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
        $state.ReportDir = $null
        $state.HtmlPath = $null
        $ui.BtnOpenReport.IsEnabled = $false
        $ui.BtnSaveReport.IsEnabled = $false
        $ui.PnlEmpty.Visibility = 'Collapsed'

        $scanArgs = @{
            DaysBack      = $days
            AllChannels   = [bool]$ui.ChkAllChannels.IsChecked
            SkipTextLogs  = [bool]$ui.ChkSkipText.IsChecked
            IncludeBenign = [bool]$ui.ChkIncludeBenign.IsChecked
        }

        try {
            $state.Job = Start-LVScanJob -ScanArgs $scanArgs -LogSink $state.Sink
        } catch {
            & $setStatus ('Could not start the scan: {0}' -f $_.Exception.Message)
            return
        }

        & $setScanning $true
        & $setStatus 'Scanning...'
        $state.Timer.Start()
    })

    $ui.BtnCancel.Add_Click({
        if (-not $state.Scanning) { return }
        $state.Timer.Stop()
        Stop-LVScanJob -Job $state.Job -Confirm:$false
        $state.Job = $null
        & $setScanning $false
        & $setStatus 'Scan cancelled. Nothing on this machine was changed.'
    })

    $ui.BtnSaveReport.Add_Click({
        if ($null -eq $state.Result) { return }
        try {
            $out = Export-LogVerdictReport -Result $state.Result
            $state.ReportDir = $out.OutputDir
            $state.HtmlPath = ($out.Files | Where-Object { $_ -like '*.html' } | Select-Object -First 1)
            $ui.BtnOpenReport.IsEnabled = $true
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
            $ui.TxtEmptyTitle.Text = 'The scan did not finish'
            $ui.TxtEmptyBody.Text = 'Open the activity log at the bottom of the window for the detail.'
            $ui.PnlEmpty.Visibility = 'Visible'
        }
    })
    $state.Timer = $timer

    $window.Add_Closing({
        $timer.Stop()
        if ($state.Job) {
            Stop-LVScanJob -Job $state.Job -Confirm:$false
            $state.Job = $null
        }
    })

    if ($AutoScan) {
        $window.Add_ContentRendered({ $ui.BtnScan.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))) })
    }

    $null = $window.ShowDialog()

    if ($PassThru) { return $state.Result }
}
