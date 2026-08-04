function Get-LVGuiRenderProjection {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result)

    $findingStore = @(Get-LVReportIncident -Result $Result)
    $correlationIdsByKey = @{}
    foreach ($correlation in @($Result.Correlations | Where-Object { $_ })) {
        $correlationId = [string]$correlation.Id
        if (-not $correlationId) { continue }
        foreach ($key in @($correlation.InvolvedKeys | Where-Object { $_ })) {
            $keyText = [string]$key
            if (-not $correlationIdsByKey.ContainsKey($keyText)) { $correlationIdsByKey[$keyText] = @() }
            $correlationIdsByKey[$keyText] = @($correlationIdsByKey[$keyText] + $correlationId | Select-Object -Unique)
        }
    }
    $rows = @(ConvertTo-LVGuiRow -Finding $findingStore -StartIndex 0 -CorrelationIdsByKey $correlationIdsByKey)
    return [pscustomobject][ordered]@{
        FindingStore = $findingStore
        CorrelationIdsByKey = $correlationIdsByKey
        Rows = $rows
        VerdictCounts = Get-LVGuiVerdictCount -Finding $findingStore
    }
}

function Set-LVGuiResultView {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Result)

    $ui = $Context.Ui
    $state = $Context.State
    $structuredFilterControl = $Context.StructuredFilterControl
    $chipControl = $Context.ChipControl
    $chipContent = $Context.Actions.ChipContent
    $showDetail = $Context.Actions.ShowDetail
    $applyFilter = $Context.Actions.ApplyFilter
    $setStatus = $Context.Actions.SetStatus

        $projection = Get-LVGuiRenderProjection -Result $Result
        $state.Result = $Result
        $state.ScanStartedAt = $null
        $state.FindingStore = @($projection.FindingStore)
        $ui.BtnCopySummary.IsEnabled = $true
        $rows = @($projection.Rows)
        $observable = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
        foreach ($r in $rows) { $observable.Add($r) }
        $state.Rows = $observable

        foreach ($kind in $structuredFilterControl.Keys) {
            $control = $structuredFilterControl[$kind]
            $options = @(Get-LVGuiFilterOption -Row @($rows) -Kind $kind)
            $control.ItemsSource = [object[]]$options
            $selected = [string]$state.StructuredFilters[$kind]
            $selectedOption = @($options | Where-Object { [string]$_.Value -eq $selected } | Select-Object -First 1)
            if ($selectedOption.Count -gt 0) {
                $control.SelectedValue = $selectedOption[0].Value
            } else {
                $control.SelectedIndex = 0
                $state.StructuredFilters[$kind] = ''
            }
        }

        $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($observable)
        $view.Filter = [Predicate[object]] {
            param($Item)
            return Test-LVGuiFindingVisible -Row $Item -EnabledVerdict $state.Chips -Search $state.Search -StructuredFilter $state.StructuredFilters
        }
        $state.View = $view
        $ui.LvFindings.ItemsSource = $view
        $priority = @($rows | Select-Object -First 3)
        $ui.LvPriority.ItemsSource = [object[]]$priority

        # Counts are of everything found, not of what the filter is showing, so
        # switching a chip off never makes its own number change under the cursor.
        $counts = $projection.VerdictCounts
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
        $ui.TxtOverviewLastVerdict.Text = $(if (@($state.FindingStore).Count -eq 0) { 'No action required' } else { $overviewVerdict })
        $ui.TxtOverviewLastVerdict.Foreground = $worst.Accent
        $ui.TxtOverviewFindingCount.Text = '{0:N0}' -f @($state.FindingStore).Count
        $ui.TxtOverviewScanTime.Text = 'Completed {0:yyyy-MM-dd HH:mm} in {1:N1}s' -f $Result.ScanTime, $Result.Duration.TotalSeconds

        $coverageNotes = @($Result.CoverageNotes | Where-Object { $_ })
        $notes = @($coverageNotes)
        if ($Result.HorizonWarning) { $notes = @($notes) + @($Result.HorizonWarning) }
        if ($coverageNotes.Count -gt 0) {
            $ui.LstCoveragePage.ItemsSource = [string[]]$coverageNotes
            $ui.TxtCoverageNone.Visibility = 'Collapsed'
        } else {
            $ui.LstCoveragePage.ItemsSource = [string[]]@()
            $ui.TxtCoverageNone.Visibility = 'Visible'
        }

        $staleRules = @()
        if ($Result.PSObject.Properties['DatabaseFreshness'] -and $Result.DatabaseFreshness) {
            $staleRules = @($Result.DatabaseFreshness.StaleRules | Where-Object { $_ })
        } else {
            $staleRules = @($Result.Findings | Where-Object { $_.PSObject.Properties['RuleStale'] -and $_.RuleStale } |
                ForEach-Object { [pscustomobject]@{ RuleId = $_.RuleId; Verified = $_.Verified; StaleAfterDays = $_.RuleFreshness.StaleAfterDays } })
        }
        $staleLines = @($staleRules | Select-Object -First 20 | ForEach-Object {
            '{0}  last verified {1}; stale after {2} day(s)' -f $_.RuleId, $_.Verified, $_.StaleAfterDays
        })
        $ui.LstStaleRulesPage.ItemsSource = [string[]]$staleLines
        if ($staleRules.Count -gt 0) {
            $defaultStaleDays = if ($Result.DatabaseFreshness.DefaultStaleAfterDays) { $Result.DatabaseFreshness.DefaultStaleAfterDays } else { $script:LVDefaultStaleAfterDays }
            $ui.TxtCoverageStaleSummary.Text = '{0} active rule(s) are past the {1}-day freshness threshold. They still match, but their guidance needs re-verification.' -f $staleRules.Count, $defaultStaleDays
            $ui.TxtStaleNone.Visibility = 'Collapsed'
        } else {
            $ui.TxtCoverageStaleSummary.Text = 'No active rule is past the declared freshness threshold.'
            $ui.TxtStaleNone.Visibility = 'Visible'
        }

        $channelLines = New-Object System.Collections.Generic.List[string]
        $readable = 0
        $totalChannels = 0
        if ($Result.ChannelStatus) {
            foreach ($name in @($Result.ChannelStatus.Keys | Sort-Object)) {
                $entry = $Result.ChannelStatus[$name]
                $totalChannels++
                $disabled = $entry.PSObject.Properties['IsEnabled'] -and $entry.IsEnabled -eq $false
                if ($entry.Access -eq 'readable' -and -not $disabled) { $readable++ }
                $statusLabel = if ($disabled) { 'disabled' } else { [string]$entry.Access }
                $availability = if ($disabled) { 'event logging is disabled' } else { [string]$entry.Access }
                if (-not $disabled -and $entry.Oldest) { $availability = 'oldest {0:yyyy-MM-dd HH:mm}' -f $entry.Oldest }
                $channelLines.Add(('{0,-36} {1,-11} {2}' -f $name, $statusLabel.ToUpperInvariant(), $availability)) | Out-Null
            }
        }
        if ($Result.PSObject.Properties['SetupDiag'] -and $Result.SetupDiag) {
            $channelLines.Add(('SetupDiag                            {0,-11} {1}' -f ([string]$Result.SetupDiag.Status).ToUpperInvariant(), $Result.SetupDiag.Message)) | Out-Null
        }
        foreach ($coverage in @($Result.Coverage | Where-Object { $_ -and [string]$_.Source -notin @('event', 'SetupDiag') })) {
            $label = '{0}/{1} {2}' -f $coverage.Source, $coverage.Kind, $coverage.Name
            $label = $label.Substring(0, [Math]::Min(36, $label.Length))
            $detail = if ($coverage.Reason) { [string]$coverage.Reason } else { '{0} observed' -f $coverage.ObservedRecords }
            $channelLines.Add(('{0,-36} {1,-11} {2}' -f $label, ([string]$coverage.Status).ToUpperInvariant(), $detail)) | Out-Null
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
                $advisoryState = if ($advisory.Matched) { 'AFFECTED' } else { 'CACHE ENTRY' }
                $channelLines.Add(('[{0}] {1} - {2} {3}; CVSS {4}; fixed {5}' -f `
                    $advisoryState, $advisory.Id, $advisory.Package, $advisory.Version, $advisory.CVSS, $advisory.FixedVersion)) | Out-Null
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
        $ui.TxtEmptyBody.Text = 'The scan completed and found no signature worth raising in the last ' + $Result.DaysBack + ' day(s). Review Coverage for anything the scan was not allowed to read.'

        # Crash evidence the console report has always shown and the window used to drop.
        $crash = Format-LVCrashArtifact -Artifact @($Result.CrashArtifacts)
        if ($crash.Count -gt 0) {
            $ui.LstCrashPage.ItemsSource = [string[]]$crash
            $ui.TxtCrashNone.Visibility = 'Collapsed'
        } else {
            $ui.LstCrashPage.ItemsSource = [string[]]@()
            $ui.TxtCrashNone.Visibility = 'Visible'
        }

        # Correlated findings. Filtered rather than merely wrapped: a result with no
        # Correlations property yields a one-element array holding null.
        $together = Format-LVCorrelation -Correlation @($Result.Correlations | Where-Object { $_ })
        if ($together.Count -gt 0) {
            $ui.LstCorrelationPage.ItemsSource = [string[]]$together
            $ui.TxtCorrelationNone.Visibility = 'Collapsed'
        } else {
            $ui.LstCorrelationPage.ItemsSource = [string[]]@()
            $ui.TxtCorrelationNone.Visibility = 'Visible'
        }

        $ui.BtnSaveReport.IsEnabled = $true
        $ui.BtnFindingsSave.IsEnabled = $true
        $ui.BtnActivitySave.IsEnabled = $true
        $ui.TxtActivityReportState.Text = 'Ready to save'

        $ui.TxtActivitySubtitle.Text = 'Latest scan - {0:yyyy-MM-dd HH:mm}' -f $Result.ScanTime
        $ui.TxtActivityState.Text = 'Completed in {0:N1}s' -f $Result.Duration.TotalSeconds
        $incidentSummary = Get-LVReportIncidentSummary -Result $Result
        $suppressionStatus = Get-LVReportSuppressionStatus -Result $Result
        if ($Result.Reduction.PSObject.Properties['InitialSignatureCount']) {
            $ui.TxtActivityHeadline.Text = '{0:N0} records -> {1:N0} masked -> {2:N0} signatures -> {3:N0} incidents ({4:P0} suppression)' -f `
                $Result.Reduction.RecordCount, $Result.Reduction.InitialSignatureCount, $Result.Reduction.SignatureCount,
                $incidentSummary.IncidentCount, $incidentSummary.SuppressionRatio
        } else {
            $ui.TxtActivityHeadline.Text = '{0:N0} records reduced to {1:N0} signatures -> {2:N0} incidents ({3:P0} suppression)' -f `
                $Result.Reduction.RecordCount, $Result.Reduction.SignatureCount, $incidentSummary.IncidentCount, $incidentSummary.SuppressionRatio
        }
        if ($suppressionStatus.SuppressedFindingCount -gt 0 -or $suppressionStatus.UnmatchedCount -gt 0 -or $suppressionStatus.ExpiredCount -gt 0) {
            $ui.TxtActivityHeadline.Text += ' - expectations: {0} suppressed, {1} unmatched, {2} due' -f `
                $suppressionStatus.SuppressedFindingCount, $suppressionStatus.UnmatchedCount, $suppressionStatus.ExpiredCount
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
        if ($suppressionStatus.SuppressedFindingCount -gt 0) {
            $footer += ' - {0} suppression expectation(s) matched' -f $suppressionStatus.SuppressedFindingCount
        }

        $stale = if ($Result.PSObject.Properties['DatabaseFreshness'] -and $Result.DatabaseFreshness) {
            [int]$Result.DatabaseFreshness.StaleRuleCount
        } else {
            Get-LVStaleRuleCount -Finding @($Result.Findings)
        }
        if ($stale -gt 0) {
            $staleDays = if ($Result.DatabaseFreshness.DefaultStaleAfterDays) { $Result.DatabaseFreshness.DefaultStaleAfterDays } else { $script:LVDefaultStaleAfterDays }
            $footer += ' - {0} active ruling(s) past the {1}-day freshness threshold' -f $stale, $staleDays
            $ui.TxtFooter.Foreground = $ui.PillDetail.FindResource('Yellow')
        } else {
            $ui.TxtFooter.Foreground = $ui.PillDetail.FindResource('TextMuted')
        }
        $ui.TxtFooter.Text = $footer

        & $showDetail $null
        & $applyFilter

        $summary = 'Scan complete. {0} incident(s), worst is {1}. {2:N0} record(s) reduced to {3:N0} signature(s) ({4:P0} incident suppression).' -f `
            @($state.FindingStore).Count, $worst.Label, $Result.Reduction.RecordCount, $Result.Reduction.SignatureCount, $incidentSummary.SuppressionRatio
        if ($suppressionStatus.UnmatchedCount -gt 0 -or $suppressionStatus.ExpiredCount -gt 0) {
            $summary += ' {0} suppression expectation(s) need review.' -f ($suppressionStatus.UnmatchedCount + $suppressionStatus.ExpiredCount)
        }
        & $setStatus $summary
}
