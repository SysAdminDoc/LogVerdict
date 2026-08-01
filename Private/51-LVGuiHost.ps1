# GUI plumbing: the verdict palette, the background scan runspace, and the two bits
# of Win32 the window needs. Kept separate from Public/Show-LogVerdictGui.ps1 so the
# window logic there reads as wiring rather than infrastructure.

# Pill colours. Each verdict is painted as its accent with near-black ink; measured
# against #06101e every pair clears 8:1, so the smallest labels in the product are
# still well past the 4.5:1 WCAG AA floor for body text.
$script:LVVerdictPalette = @{
    'critical'      = @{ Label = 'CRITICAL';    Fill = '#ff6b6b'; Ink = '#06101e'; Accent = '#ff6b6b' }
    'actionable'    = @{ Label = 'ACTIONABLE';  Fill = '#ffaa64'; Ink = '#06101e'; Accent = '#ffaa64' }
    'investigate'   = @{ Label = 'INVESTIGATE'; Fill = '#ffd166'; Ink = '#06101e'; Accent = '#ffd166' }
    'unknown'       = @{ Label = 'UNKNOWN';     Fill = '#82b4ff'; Ink = '#06101e'; Accent = '#82b4ff' }
    'informational' = @{ Label = 'INFO';        Fill = '#56d4e8'; Ink = '#06101e'; Accent = '#56d4e8' }
    'benign'        = @{ Label = 'HARMLESS';    Fill = '#5dd39e'; Ink = '#06101e'; Accent = '#5dd39e' }
}

# Chip order in the sidebar, worst first, matching the report's ordering.
$script:LVVerdictDisplayOrder = @('critical', 'actionable', 'investigate', 'unknown', 'informational', 'benign')

# Every brush the XAML treats as semantic rather than decorative. DynamicResource
# references point at these keys, so replacing the resource objects repaints the
# existing visual tree without rebuilding the window.
$script:LVGuiThemeBrushKey = @(
    'Base', 'Mantle', 'Crust',
    'Surface0', 'Surface1', 'Surface2', 'Overlay0', 'Overlay1',
    'Text', 'Subtext1', 'Subtext0', 'TextMuted',
    'Blue', 'Lavender', 'Mauve', 'Red', 'Peach', 'Yellow', 'Green', 'Sky',
    'AccentInk', 'AccentPressed', 'RowDivider', 'RowHover', 'NavBorder',
    'SoftPanel', 'BluePanel', 'NavIconActive', 'SuccessPanel', 'ElevationPanel',
    'StatusIcon', 'WarningBorder', 'WarningCard', 'WarningIcon', 'InfoPanel',
    'CoveragePanel', 'SuccessLine', 'SuccessIcon', 'LogBackground'
)

function Test-LVGuiHighContrast {
    <#
        .SYNOPSIS
        Return the current Windows High Contrast state.

        .DESCRIPTION
        The environment override exists only so visual verification can exercise the
        same theme path on the isolated display without changing the user's global
        desktop theme. Production launches leave it unset and follow SystemParameters.
    #>
    # Get-LVVerdictStyle is also used by non-GUI tests and row projection, before the
    # window entry point has loaded WPF. Load the one assembly that owns SystemParameters
    # here so those otherwise headless callers keep working.
    if (-not ('System.Windows.SystemParameters' -as [type])) {
        Add-Type -AssemblyName PresentationFramework
    }

    if ($env:LOGVERDICT_TEST_HIGH_CONTRAST -eq '1') { return $true }
    if ($env:LOGVERDICT_TEST_HIGH_CONTRAST -eq '0') { return $false }
    return [bool][System.Windows.SystemParameters]::HighContrast
}

function Get-LVGuiThemeSnapshot {
    <#
        .SYNOPSIS
        Capture the original window resources so a theme change can be reversed.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Window)

    $snapshot = @{}
    foreach ($key in @($script:LVGuiThemeBrushKey) + @('LVFocusVisual')) {
        if (-not $Window.Resources.Contains($key)) {
            throw ("LogVerdict markup is missing the theme resource '{0}'." -f $key)
        }
        $snapshot[$key] = $Window.Resources[$key]
    }
    return $snapshot
}

function Sync-LVGuiTheme {
    <#
        .SYNOPSIS
        Apply or remove the Windows High Contrast resource palette.

        .DESCRIPTION
        High Contrast uses only SystemColors brushes. Leaving High Contrast restores
        the exact resource objects captured from XAML, including the custom focus ring.
        While it is active, LVFocusVisual resolves to WPF's framework focus style so
        the user's configured focus treatment wins over the application's template.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Window,
        [Parameter(Mandatory)][hashtable]$Snapshot,
        [bool]$HighContrast = (Test-LVGuiHighContrast)
    )

    if (-not $HighContrast) {
        foreach ($key in @($script:LVGuiThemeBrushKey) + @('LVFocusVisual')) {
            $Window.Resources[$key] = $Snapshot[$key]
        }
        return $false
    }

    $systemBrush = @{
        Base           = [System.Windows.SystemColors]::WindowBrush
        Mantle         = [System.Windows.SystemColors]::WindowBrush
        Crust          = [System.Windows.SystemColors]::WindowBrush
        Surface0       = [System.Windows.SystemColors]::ControlBrush
        Surface1       = [System.Windows.SystemColors]::ControlDarkBrush
        Surface2       = [System.Windows.SystemColors]::ControlTextBrush
        Overlay0       = [System.Windows.SystemColors]::ControlTextBrush
        Overlay1       = [System.Windows.SystemColors]::ControlTextBrush
        Text           = [System.Windows.SystemColors]::WindowTextBrush
        Subtext1       = [System.Windows.SystemColors]::WindowTextBrush
        Subtext0       = [System.Windows.SystemColors]::WindowTextBrush
        TextMuted      = [System.Windows.SystemColors]::WindowTextBrush
        Blue           = [System.Windows.SystemColors]::HighlightBrush
        Lavender       = [System.Windows.SystemColors]::HighlightBrush
        Mauve          = [System.Windows.SystemColors]::HighlightBrush
        Red            = [System.Windows.SystemColors]::HighlightBrush
        Peach          = [System.Windows.SystemColors]::HighlightBrush
        Yellow         = [System.Windows.SystemColors]::HighlightBrush
        Green          = [System.Windows.SystemColors]::HighlightBrush
        Sky            = [System.Windows.SystemColors]::HighlightBrush
        AccentInk      = [System.Windows.SystemColors]::HighlightTextBrush
        AccentPressed  = [System.Windows.SystemColors]::HighlightBrush
        RowDivider     = [System.Windows.SystemColors]::ControlTextBrush
        RowHover       = [System.Windows.SystemColors]::ControlBrush
        NavBorder      = [System.Windows.SystemColors]::ControlTextBrush
        SoftPanel      = [System.Windows.SystemColors]::ControlBrush
        BluePanel      = [System.Windows.SystemColors]::ControlBrush
        NavIconActive  = [System.Windows.SystemColors]::ControlBrush
        SuccessPanel   = [System.Windows.SystemColors]::ControlBrush
        ElevationPanel = [System.Windows.SystemColors]::ControlBrush
        StatusIcon     = [System.Windows.SystemColors]::ControlBrush
        WarningBorder  = [System.Windows.SystemColors]::ControlTextBrush
        WarningCard    = [System.Windows.SystemColors]::WindowBrush
        WarningIcon    = [System.Windows.SystemColors]::ControlBrush
        InfoPanel      = [System.Windows.SystemColors]::ControlBrush
        CoveragePanel  = [System.Windows.SystemColors]::ControlBrush
        SuccessLine    = [System.Windows.SystemColors]::ControlTextBrush
        SuccessIcon    = [System.Windows.SystemColors]::ControlBrush
        LogBackground  = [System.Windows.SystemColors]::WindowBrush
    }

    foreach ($key in $script:LVGuiThemeBrushKey) {
        $Window.Resources[$key] = $systemBrush[$key]
    }

    $frameworkFocus = $Window.TryFindResource([System.Windows.SystemParameters]::FocusVisualStyleKey)
    if ($null -eq $frameworkFocus) {
        throw 'Windows did not provide its High Contrast focus visual style.'
    }
    $Window.Resources['LVFocusVisual'] = $frameworkFocus
    return $true
}

# Every named element the window code reaches for. Show-LogVerdictGui resolves all of
# them up front and fails loudly on the first missing one, and the test suite checks
# this list against the markup - so a renamed x:Name is caught before a build rather
# than by a null reference somewhere deep in an event handler.
$script:LVGuiElement = @(
    'NavOverview', 'NavFindings', 'NavCoverage', 'NavActivity',
    'PageOverview', 'PageFindings', 'PageCoverage', 'PageActivity',
    'TxtSideMachine', 'TxtSideElevation', 'BtnSideElevate',
    'TxtSideDbTitle', 'TxtSideDbMeta', 'TxtSideDbUpdated',
    'TxtOverviewDays', 'ChkOverviewAllChannels', 'ChkOverviewIncludeText',
    'ChkOverviewIncludeBenign', 'BtnOverviewScan', 'BtnOverviewCancel',
    'TxtOverviewLastVerdict', 'TxtOverviewFindingCount', 'TxtOverviewScanTime',
    'PnlOverviewSummary', 'TxtOverviewRecords', 'TxtOverviewSignatures',
    'TxtOverviewReduction', 'TxtOverviewRules',
    'TxtOverviewCritical', 'TxtOverviewActionable', 'TxtOverviewInvestigate',
    'TxtOverviewUnknown', 'TxtOverviewInfo', 'TxtOverviewBenign',
    'BtnViewFindings', 'LvPriority', 'TxtOverviewCoverage', 'BtnViewCoverage',
    'BtnFindingsSave', 'BtnFindingsOpen',
    'FltCritical', 'FltActionable', 'FltInvestigate', 'FltUnknown',
    'FltInformational', 'FltBenign',
    'BtnCoverageElevate', 'TxtCoverageState', 'TxtCoverageSummary',
    'TxtCoverageRatio', 'PbCoverage', 'TxtCoverageReadable', 'TxtCoverageGaps',
    'TxtCoverageWindow', 'LstChannelCoverage', 'LstCoveragePage', 'TxtCoverageNone',
    'TxtHorizonPage', 'LstCrashPage', 'TxtCrashNone',
    'LstCorrelationPage', 'TxtCorrelationNone',
    'TxtActivitySubtitle', 'TxtActivityState', 'BtnActivityClear',
    'TxtActivityHeadline', 'BtnActivityRunAgain', 'TxtActivityLastLine',
    'TxtActivityLog', 'TxtActivitySearch', 'TxtActivitySearchHint', 'TxtActivityDuration',
    'TxtActivityRecords', 'TxtActivitySignatures', 'TxtActivityRules',
    'TxtActivityReportState', 'BtnActivitySave', 'BtnActivityOpen',
    'TxtVersion', 'TxtMachine', 'ChipElevation', 'TxtElevation', 'PnlElevate', 'BtnElevate',
    'TxtDays', 'ChkAllChannels', 'ChkSkipText', 'ChkIncludeBenign', 'BtnScan', 'BtnCancel',
    'PnlSummary', 'ChipCritical', 'ChipActionable', 'ChipInvestigate', 'ChipUnknown',
    'ChipInformational', 'ChipBenign',
    'TxtRecords', 'TxtSignatures', 'TxtReduction', 'TxtRules',
    'PnlCoverage', 'LstCoverage', 'PnlCrash', 'LstCrash',
    'PnlCorrelation', 'LstCorrelation',
    'TxtSearch', 'TxtSearchHint', 'TxtShown', 'LvFindings',
    'PnlEmpty', 'TxtEmptyTitle', 'TxtEmptyBody',
    'TxtNoSelection', 'ScrDetail', 'PillDetail', 'TxtDetailVerdict', 'TxtDetailTitle',
    'TxtDetailMeta', 'TxtPlain', 'TxtWhy', 'TxtAction',
    'PnlFalsePositives', 'LstFalsePositives', 'PnlRefs', 'LstRefs',
    'TxtSample', 'TxtProvenance',
    'BtnCopy', 'BtnSaveReport', 'BtnOpenReport',
    'RowLog', 'BtnToggleLog', 'TxtLastLine', 'TxtLog',
    'PbScan', 'TxtStatus', 'TxtFooter'
)

# Column header text -> the row property that column actually sorts on. The display
# string is never the sort key: "3 days ago" and "CRITICAL" both sort alphabetically
# into nonsense.
$script:LVGuiSortKey = @{
    'VERDICT'        = 'VerdictRank'
    'WHAT HAPPENED'  = 'Title'
    'TIMES'          = 'Count'
    'PER DAY'        = 'PerDay'
    'LAST SEEN'      = 'LastSeenSort'
    'WHERE FROM'     = 'Origin'
}

function Get-LVVerdictStyle {
    <#
        .SYNOPSIS
        Palette entry for a verdict, falling back to the 'unknown' styling.
    #>
    param([AllowNull()][string]$Verdict)

    $key = $Verdict
    if (-not $key -or -not $script:LVVerdictPalette.ContainsKey($key)) { $key = 'unknown' }
    if (Test-LVGuiHighContrast) {
        return @{
            Label  = $script:LVVerdictPalette[$key].Label
            Fill   = [System.Windows.SystemColors]::HighlightBrush
            Ink    = [System.Windows.SystemColors]::HighlightTextBrush
            Accent = [System.Windows.SystemColors]::HighlightBrush
        }
    }
    return $script:LVVerdictPalette[$key]
}

function Format-LVGuiWhen {
    <#
        .SYNOPSIS
        A timestamp as a person would say it out loud.

        .DESCRIPTION
        "3 days ago" answers the question a reader is actually asking - is this still
        happening - which an absolute timestamp makes them compute. Anything older than
        a week falls back to the date, where the exact day starts mattering again.
        Undated text-log lines say so rather than borrowing the current time.
    #>
    param([AllowNull()]$When)

    if ($null -eq $When) { return 'undated' }

    $span = (Get-Date) - $When
    if ($span.TotalSeconds -lt 0)    { return ('{0:yyyy-MM-dd}' -f $When) }
    if ($span.TotalMinutes -lt 2)    { return 'just now' }
    if ($span.TotalMinutes -lt 60)   { return ('{0} min ago' -f [int]$span.TotalMinutes) }
    if ($span.TotalHours -lt 24)     { return ('{0} hr ago' -f [int]$span.TotalHours) }
    if ($span.TotalDays -lt 7)       { return ('{0} days ago' -f [int]$span.TotalDays) }
    return ('{0:yyyy-MM-dd}' -f $When)
}

function ConvertTo-LVGuiRow {
    <#
        .SYNOPSIS
        Flatten findings into bindable rows for the list view.

        .DESCRIPTION
        WPF bindings resolve against plain properties, so everything the grid shows is
        precomputed here rather than converted per cell. The original finding travels
        along on .Finding so the detail pane never has to look it up again, and
        .Haystack is the lowercased text the search box matches against - built once,
        not rebuilt on every keystroke.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding)

    $rows = foreach ($f in $Finding) {
        $style = Get-LVVerdictStyle -Verdict $f.Verdict

        if ($f.Source -eq 'event') {
            $origin = '{0} {1}' -f $f.Provider, $f.Id
        } else {
            $origin = [string]$f.Channel
        }

        $haystack = (@($f.Title, $f.Provider, $f.Channel, $f.Id, $f.SampleMessage, $f.RuleId, $f.Key) -join ' ').ToLowerInvariant()

        # Sorting keys are separate from display strings on purpose. Sorting the grid
        # on "3 days ago" or on "CRITICAL" would order it alphabetically, which is
        # exactly wrong for both columns.
        $lastSeenSort = [datetime]::MinValue
        if ($null -ne $f.LastSeen) { $lastSeenSort = $f.LastSeen }

        # What a screen reader says for this row. Without it WPF falls back to the
        # object's own ToString, which reads out every property including hex colour
        # codes and the whole search haystack. Colour carries meaning in the verdict
        # column, so the verdict is spoken rather than merely shown.
        $spokenWhen = Format-LVGuiWhen -When $f.LastSeen
        $automationName = '{0}. {1}. Seen {2} time(s), {3:0.00} per day, last {4}. Source {5}.' -f `
            $style.Label, $f.Title, $f.Count, $f.PerDay, $spokenWhen, $origin

        [pscustomobject]@{
            Verdict      = $f.Verdict
            VerdictLabel = $style.Label
            VerdictFill  = $style.Fill
            VerdictInk   = $style.Ink
            VerdictRank  = (Get-LVVerdictRank -Verdict $f.Verdict)
            Title        = $f.Title
            Count        = $f.Count
            PerDay       = $f.PerDay
            # Fixed two places so the column reads as a column. The raw value rounds to
            # 2dp, which renders as "0.7", "1" and "10" beside "0.55" - a ragged edge
            # that makes rates hard to compare at a glance.
            PerDayText   = '{0:0.00}' -f $f.PerDay
            LastSeenText = Format-LVGuiWhen -When $f.LastSeen
            LastSeenSort = $lastSeenSort
            Origin         = $origin
            Haystack       = $haystack
            AutomationName = $automationName
            Finding        = $f
        }
    }

    return ConvertTo-LVArrayOutput -Value @($rows)
}

function Get-LVStaleRuleCount {
    <#
        .SYNOPSIS
        How many findings were ruled on by guidance that has not been re-checked recently.

        .DESCRIPTION
        A curated database is only as good as the day each rule was last verified, and
        Windows ships new noise every patch cycle. A confidently wrong ruling is worse
        than no ruling, so the age of the guidance behind a finding is reported rather
        than left implicit.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding)

    $cutoff = (Get-Date).AddMonths(-1 * $script:LVVerificationMaxAgeMonths)
    $stale = 0
    foreach ($f in $Finding) {
        if (-not $f.Verified) { continue }
        $parsed = [datetime]::MinValue
        if (-not [datetime]::TryParseExact([string]$f.Verified, 'yyyy-MM-dd',
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) { continue }
        if ($parsed -lt $cutoff) { $stale++ }
    }
    return $stale
}

function Format-LVCrashArtifact {
    <#
        .SYNOPSIS
        One crash artifact as a single readable line for the window's sidebar.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Artifact)

    $lines = foreach ($a in $Artifact) {
        if ($null -eq $a) { continue }
        $detail = [string]$a.DecodeStatus
        if ($a.Kind -eq 'minidump' -and $a.BugCheckCode) {
            $detail = 'bug check {0} ({1})' -f $a.BugCheckCode, $a.Architecture
        } elseif ($a.Kind -eq 'wer' -and $a.Decoded) {
            $detail = '{0} in {1}' -f $a.App, $a.Module
            if ($a.ExceptionCode) { $detail += ' - exception ' + $a.ExceptionCode }
        }
        '{0}  {1:yyyy-MM-dd HH:mm}  {2}  {3}' -f $a.Kind, $a.When, (Split-Path -Leaf ([string]$a.Path)), $detail
    }
    return ConvertTo-LVArrayOutput -Value @($lines)
}

function Format-LVCorrelation {
    <#
        .SYNOPSIS
        One correlated finding as a readable block for the window's sidebar.

        .DESCRIPTION
        The window has no place to render a second full findings list, but leaving
        correlations out entirely would mean the same scan told you different things
        depending on how you ran it - the exact asymmetry that hid crash evidence from
        the window until 0.5.0.

        The verdict leads, then the title, then the windows of time to look at, so the
        line is a sentence when a screen reader announces it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Correlation)

    $lines = foreach ($c in $Correlation) {
        if ($null -eq $c) { continue }
        $windows = @($c.Windows | Where-Object { $_ })
        $when = (@($windows | Select-Object -First 3 | ForEach-Object { '{0:yyyy-MM-dd HH:mm}' -f $_.Start }) -join ', ')
        if ($windows.Count -gt 3) { $when += (' and {0} more' -f ($windows.Count - 3)) }
        '{0}. {1}. {2} time(s), within {3}: {4}.' -f `
            ([string]$c.Verdict).ToUpper(), $c.Title, $windows.Count, $c.Timespan, $when
    }
    return ConvertTo-LVArrayOutput -Value @($lines)
}

function Get-LVGuiScanScript {
    <#
        .SYNOPSIS
        The scriptblock text run inside the background scan runspace.

        .DESCRIPTION
        A fresh runspace starts empty, so LogVerdict has to be reconstituted inside it.
        There are two ways in and the caller says which: 'module' imports the manifest
        by path; 'flat' dot-sources the source text the single-file build embedded,
        because a compiled executable has no .psd1 to import.

        Kept as text rather than a scriptblock literal so it crosses the runspace
        boundary without dragging the calling session state with it.
    #>
    return @'
param($Mode, $Payload, $DataDir, $Version, $VerdictsJson, $Sink, $ScanArgs)

if ($Mode -eq 'module') {
    $m = Import-Module -Name $Payload -Force -PassThru -ErrorAction Stop

    # Reach into the module's own scope. Write-LVLog reads $script:LVLogSink from
    # inside the module, and a variable of that name set out here is a different
    # variable entirely - the log panel would stay empty for the whole scan.
    & $m { param($q) $script:LVLogSink = $q } $Sink
} else {
    $script:LVVersion              = $Version
    $script:LVModuleRoot           = $null
    $script:LVDataDir              = $DataDir
    $script:LVEmbeddedVerdictsJson = $VerdictsJson

    . ([ScriptBlock]::Create($Payload))

    # Dot-sourcing defined the functions in this scope, so $script: here is the same
    # scope Write-LVLog closes over.
    $script:LVLogSink = $Sink
}

Invoke-LogVerdictScan @ScanArgs
'@
}

function Start-LVScanJob {
    <#
        .SYNOPSIS
        Begin a scan on a worker thread and return a handle to poll.

        .DESCRIPTION
        A scan takes seconds to minutes. Running it on the UI thread freezes the window
        for its whole duration, which reads as a crash. The work goes to its own
        runspace and the window polls this handle on a DispatcherTimer.

        Log lines come back through a concurrent queue rather than a callback: the scan
        is on a worker thread, and touching a WPF control from there throws.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory)][hashtable]$ScanArgs,
        [Parameter(Mandatory)]$LogSink
    )

    if (-not $PSCmdlet.ShouldProcess('this machine', 'Read event channels and text logs')) { return }

    $mode = 'flat'
    $payload = $null

    if ($script:LVModuleRoot) {
        $manifest = Join-Path $script:LVModuleRoot 'LogVerdict.psd1'
        if (Test-Path -LiteralPath $manifest) {
            $mode = 'module'
            $payload = $manifest
        }
    }

    if ($mode -eq 'flat') {
        if (-not $script:LVEmbeddedSource) {
            throw 'This build cannot run a background scan: there is no module to import and no embedded source to load. Rebuild with Tools\Build-LogVerdictExe.ps1.'
        }
        $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($script:LVEmbeddedSource))
    }

    $rs = [runspacefactory]::CreateRunspace()
    try {
        # The worker touches no COM UI, and MTA keeps it off the single-threaded
        # apartment the window lives on. Not fatal if the host refuses it.
        $rs.ApartmentState = 'MTA'
        $rs.ThreadOptions = 'ReuseThread'
    } catch {
        Write-Verbose ("Could not set runspace threading options: {0}" -f $_.Exception.Message)
    }
    $rs.Open()

    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $null = $ps.AddScript((Get-LVGuiScanScript)).AddParameters(@{
        Mode         = $mode
        Payload      = $payload
        DataDir      = $script:LVDataDir
        Version      = $script:LVVersion
        VerdictsJson = $script:LVEmbeddedVerdictsJson
        Sink         = $LogSink
        ScanArgs     = $ScanArgs
    })

    return [pscustomobject]@{
        Mode       = $mode
        PowerShell = $ps
        Runspace   = $rs
        Async      = $ps.BeginInvoke()
    }
}

function Stop-LVScanJob {
    <#
        .SYNOPSIS
        Tear a scan job down. Safe to call twice, and safe to call on a running scan.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    param([AllowNull()]$Job)

    if ($null -eq $Job) { return }
    if (-not $PSCmdlet.ShouldProcess('background scan', 'Stop')) { return }

    foreach ($step in @('stop', 'dispose', 'close')) {
        try {
            switch ($step) {
                'stop'    { if ($Job.PowerShell) { $Job.PowerShell.Stop() } }
                'dispose' { if ($Job.PowerShell) { $Job.PowerShell.Dispose() } }
                'close'   { if ($Job.Runspace)   { $Job.Runspace.Dispose() } }
            }
        } catch {
            # Teardown races with a worker that may already have finished and released
            # its own handles. Nothing here is worth surfacing to a user.
            Write-Verbose ("Scan job teardown ({0}): {1}" -f $step, $_.Exception.Message)
        }
    }
}

function Complete-LVScanJob {
    <#
        .SYNOPSIS
        Harvest a finished scan job's result, or throw with the worker's own error.

        .DESCRIPTION
        The output stream is filtered for the scan result rather than trusted to hold
        exactly one object: anything in the pipeline that escaped into the output stream
        would otherwise be handed back as if it were a result.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Job)

    try {
        $output = @($Job.PowerShell.EndInvoke($Job.Async))
        $errors = @($Job.PowerShell.Streams.Error)

        $result = $null
        foreach ($o in $output) {
            if ($null -ne $o -and $o.PSObject.Properties['ExitCode']) { $result = $o }
        }

        if ($null -eq $result) {
            if ($errors.Count -gt 0) { throw ([string]$errors[0]) }
            throw 'The scan finished but produced no result.'
        }
        return $result
    } finally {
        Stop-LVScanJob -Job $Job -Confirm:$false
    }
}

function Enable-LVDarkTitleBar {
    <#
        .SYNOPSIS
        Ask the desktop window manager for a dark caption bar.

        .DESCRIPTION
        A dark application under a white title bar looks broken. The attribute id moved
        between Windows 10 builds - 19 on 1809-1903, 20 from 2004 onwards - so both are
        tried and the first that succeeds wins. Purely cosmetic: every failure is
        swallowed, because a light title bar is not a reason to fail to open a window.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Window)

    try {
        if (-not ('LVNative.Dwm' -as [type])) {
            Add-Type -Namespace 'LVNative' -Name 'Dwm' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll", PreserveSig = true)]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int value, int size);
'@
        }

        $hwnd = (New-Object System.Windows.Interop.WindowInteropHelper($Window)).Handle
        if ($hwnd -eq [IntPtr]::Zero) { return }

        $highContrast = Test-LVGuiHighContrast
        $enabled = $(if ($highContrast) { 0 } else { 1 })
        foreach ($attr in @(20, 19)) {
            if ([LVNative.Dwm]::DwmSetWindowAttribute($hwnd, $attr, [ref]$enabled, 4) -eq 0) { break }
        }

        if ($highContrast) {
            # -1 is DWMWA_COLOR_DEFAULT. Undo any application colour that was applied
            # before High Contrast switched on and let Windows own the caption again.
            $defaultColour = -1
            $null = [LVNative.Dwm]::DwmSetWindowAttribute($hwnd, 35, [ref]$defaultColour, 4)
            $null = [LVNative.Dwm]::DwmSetWindowAttribute($hwnd, 36, [ref]$defaultColour, 4)
            return
        }

        # Windows 11 otherwise honours the user's bright accent colour for an active
        # caption, which cuts a blue slab across an otherwise restrained dark window.
        # These newer attributes are best-effort and are ignored by older builds.
        $captionColour = 0x001e1006 # COLORREF for RGB #06101e
        $textColour = 0x00fbf7f5    # COLORREF for RGB #f5f7fb
        $null = [LVNative.Dwm]::DwmSetWindowAttribute($hwnd, 35, [ref]$captionColour, 4)
        $null = [LVNative.Dwm]::DwmSetWindowAttribute($hwnd, 36, [ref]$textColour, 4)
    } catch {
        Write-Verbose ("Dark title bar unavailable: {0}" -f $_.Exception.Message)
    }
}

function Get-LVGuiRelaunchTarget {
    <#
        .SYNOPSIS
        How to start this same GUI again, for the elevation restart.

        .DESCRIPTION
        Two shapes to relaunch: a compiled executable re-runs itself, while a module
        checkout re-runs its entry script under powershell.exe. -STA is explicit because
        WPF cannot start on a multi-threaded apartment and pwsh defaults to one.
    #>
    [CmdletBinding()]
    param()

    if ($script:LVModuleRoot) {
        $entry = Join-Path $script:LVModuleRoot 'LogVerdict-GUI.ps1'
        if (Test-Path -LiteralPath $entry) {
            return @{
                FilePath  = 'powershell.exe'
                Arguments = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $entry))
            }
        }
    }

    try {
        $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        if ($exe) { return @{ FilePath = $exe; Arguments = @() } }
    } catch {
        Write-Verbose ("Could not resolve the host executable path: {0}" -f $_.Exception.Message)
    }

    return $null
}
