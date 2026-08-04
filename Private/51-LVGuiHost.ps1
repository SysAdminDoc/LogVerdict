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

function Get-LVGuiScanTimingHint {
    <#
        Return honest, look-back-specific scan guidance for the Overview page.
        Collection is bounded and read-only, but all-channel sweeps can still take
        longer than a focused one-day run; the copy should set that expectation before
        the operator presses Run scan.
    #>
    [CmdletBinding()]
    param([ValidateRange(1, 3650)][int]$DaysBack = 30)

    $range = if ($DaysBack -le 1) {
        'under 30 seconds'
    } elseif ($DaysBack -le 7) {
        '30-90 seconds'
    } elseif ($DaysBack -le 30) {
        '1-3 minutes'
    } else {
        '2-5 minutes'
    }
    return ('Typical {0}-day scan: {1}. All-channel sweeps can take longer.' -f $DaysBack, $range)
}

function Get-LVGuiSettingsPath {
    <#
        .SYNOPSIS
        Per-user location for GUI preferences.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$LocalAppData = $env:LOCALAPPDATA)

    if ([string]::IsNullOrWhiteSpace($LocalAppData)) { return $null }
    return Join-Path (Join-Path $LocalAppData 'LogVerdict') 'settings.json'
}

function Get-LVGuiSetting {
    <#
        .SYNOPSIS
        Read and validate GUI preferences, returning null for any unusable file.

        .DESCRIPTION
        Settings are convenience, never a launch dependency. A partial, future,
        malformed, or unreadable file is ignored as a unit so no unvalidated value
        reaches WPF.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Path = (Get-LVGuiSettingsPath))

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    try {
        $data = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($data.schemaVersion -ne 1) { return $null }

        $days = 0
        if (-not [int]::TryParse([string]$data.daysBack, [ref]$days) -or $days -lt 1 -or $days -gt 3650) {
            return $null
        }
        foreach ($name in @('allChannels', 'skipTextLogs', 'includeBenign')) {
            if ($null -eq $data.PSObject.Properties[$name] -or $data.$name -isnot [bool]) { return $null }
        }
        foreach ($name in @('diagnosticChannels', 'skipReliability', 'redact', 'includeEvidence')) {
            if ($null -ne $data.PSObject.Properties[$name] -and $data.$name -isnot [bool]) { return $null }
        }
        foreach ($name in @('namedChannels', 'databasePath', 'outputDirectory')) {
            if ($null -ne $data.PSObject.Properties[$name] -and
                $null -ne $data.$name -and $data.$name -isnot [string]) { return $null }
        }
        foreach ($name in @('windowWidth', 'windowHeight')) {
            if ($null -eq $data.PSObject.Properties[$name] -or $data.$name -is [string]) { return $null }
        }

        $width = [double]$data.windowWidth
        $height = [double]$data.windowHeight
        if ([double]::IsNaN($width) -or [double]::IsInfinity($width) -or $width -lt 1120 -or $width -gt 10000) {
            return $null
        }
        if ([double]::IsNaN($height) -or [double]::IsInfinity($height) -or $height -lt 650 -or $height -gt 10000) {
            return $null
        }

        return [pscustomobject]@{
            DaysBack      = $days
            AllChannels   = [bool]$data.allChannels
            DiagnosticChannels = if ($data.PSObject.Properties['diagnosticChannels']) { [bool]$data.diagnosticChannels } else { $false }
            SkipTextLogs  = [bool]$data.skipTextLogs
            SkipReliability = if ($data.PSObject.Properties['skipReliability']) { [bool]$data.skipReliability } else { $false }
            IncludeBenign = [bool]$data.includeBenign
            NamedChannels = if ($data.PSObject.Properties['namedChannels']) { [string]$data.namedChannels } else { '' }
            DatabasePath = if ($data.PSObject.Properties['databasePath']) { [string]$data.databasePath } else { '' }
            OutputDirectory = if ($data.PSObject.Properties['outputDirectory']) { [string]$data.outputDirectory } else { '' }
            Redact = if ($data.PSObject.Properties['redact']) { [bool]$data.redact } else { $false }
            IncludeEvidence = if ($data.PSObject.Properties['includeEvidence']) { [bool]$data.includeEvidence } else { $false }
            WindowWidth   = $width
            WindowHeight  = $height
        }
    } catch {
        Write-Verbose ("Ignoring unreadable GUI settings at {0}: {1}" -f $Path, $_.Exception.Message)
        return $null
    }
}

function Save-LVGuiSetting {
    <#
        .SYNOPSIS
        Atomically save normalized per-user GUI preferences.

        .OUTPUTS
        Boolean. False means persistence was unavailable; the GUI must still close.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Settings,
        [AllowEmptyString()][string]$Path = (Get-LVGuiSettingsPath)
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }

    $days = 0
    if (-not [int]::TryParse([string]$Settings.DaysBack, [ref]$days) -or $days -lt 1 -or $days -gt 3650) {
        $days = 30
    }
    $width = [Math]::Max(1120, [Math]::Min(10000, [double]$Settings.WindowWidth))
    $height = [Math]::Max(650, [Math]::Min(10000, [double]$Settings.WindowHeight))
    $document = [ordered]@{
        schemaVersion = 1
        daysBack      = $days
        allChannels   = [bool]$Settings.AllChannels
        diagnosticChannels = [bool]$Settings.DiagnosticChannels
        skipTextLogs  = [bool]$Settings.SkipTextLogs
        skipReliability = [bool]$Settings.SkipReliability
        includeBenign = [bool]$Settings.IncludeBenign
        namedChannels = ([string]$Settings.NamedChannels).Trim()
        databasePath = ([string]$Settings.DatabasePath).Trim()
        outputDirectory = ([string]$Settings.OutputDirectory).Trim()
        redact = [bool]$Settings.Redact
        includeEvidence = [bool]$Settings.IncludeEvidence
        windowWidth   = [Math]::Round($width, 0)
        windowHeight  = [Math]::Round($height, 0)
    }

    $directory = Split-Path -Parent $Path
    $temp = '{0}.{1}.tmp' -f $Path, ([guid]::NewGuid().ToString('N'))
    $backup = '{0}.{1}.bak' -f $Path, ([guid]::NewGuid().ToString('N'))
    try {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            $null = New-Item -ItemType Directory -Path $directory -Force
        }
        Write-LVTextFile -Path $temp -Content (($document | ConvertTo-Json) + [Environment]::NewLine)
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [IO.File]::Replace($temp, $Path, $backup)
        } else {
            [IO.File]::Move($temp, $Path)
        }
        return $true
    } catch {
        Write-Verbose ("Could not save GUI settings at {0}: {1}" -f $Path, $_.Exception.Message)
        return $false
    } finally {
        if (Test-Path -LiteralPath $temp -PathType Leaf) { Remove-Item -LiteralPath $temp -Force }
        if (Test-Path -LiteralPath $backup -PathType Leaf) { Remove-Item -LiteralPath $backup -Force }
    }
}

function Reset-LVGuiSetting {
    <#
        .SYNOPSIS
        Persist the safe first-launch GUI preferences.

        .DESCRIPTION
        Reset is intentionally implemented as an atomic write of validated defaults,
        rather than deleting the settings file. A failed write therefore leaves the
        previous preferences recoverable while the caller can report that only the
        current session was reset.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([AllowEmptyString()][string]$Path = (Get-LVGuiSettingsPath))

    if (-not $PSCmdlet.ShouldProcess($Path, 'Reset LogVerdict GUI settings')) { return $false }
    return Save-LVGuiSetting -Settings ([pscustomobject]@{
        DaysBack      = 30
        AllChannels   = $false
        DiagnosticChannels = $false
        SkipTextLogs  = $false
        SkipReliability = $false
        IncludeBenign = $false
        NamedChannels = ''
        DatabasePath = ''
        OutputDirectory = ''
        Redact = $false
        IncludeEvidence = $false
        WindowWidth   = 1440
        WindowHeight  = 800
    }) -Path $Path
}

function Get-LVGuiNamedChannel {
    <#
        .SYNOPSIS
        Normalize the named-channel text box into a stable, duplicate-free array.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$Text)

    $channel = @($Text -split '[,;\r\n]+' |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ } |
        Select-Object -Unique)
    return ConvertTo-LVArrayOutput -Value $channel
}

function Select-LVGuiFolder {
    <#
        .SYNOPSIS
        Show an owned folder picker so the dialog stays with the LogVerdict window.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Window,
        [AllowEmptyString()][string]$InitialDirectory
    )

    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $owner = New-Object System.Windows.Forms.NativeWindow
    try {
        $dialog.Description = 'Choose where LogVerdict should save reports'
        $dialog.ShowNewFolderButton = $true
        if ($InitialDirectory -and (Test-Path -LiteralPath $InitialDirectory -PathType Container)) {
            $dialog.SelectedPath = $InitialDirectory
        }

        $handle = (New-Object System.Windows.Interop.WindowInteropHelper($Window)).Handle
        $owner.AssignHandle($handle)
        if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {
            return $dialog.SelectedPath
        }
    } finally {
        $owner.ReleaseHandle()
        $dialog.Dispose()
    }
    return $null
}

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
    'TxtOverviewDays', 'ChkOverviewAllChannels', 'ChkOverviewDiagnosticChannels',
    'ChkOverviewIncludeText', 'ChkOverviewIncludeBenign', 'TxtOverviewChannels',
    'TxtOverviewDatabase', 'BtnOverviewBrowseDatabase', 'ChkOverviewSkipReliability',
    'TxtOverviewOutputDir', 'BtnOverviewBrowseOutput', 'ChkOverviewRedact',
    'ChkOverviewEvidence', 'BtnResetSettings', 'TxtSettingsStatus',
    'BtnOverviewScan', 'BtnOverviewCancel',
    'TxtOverviewLastVerdict', 'TxtOverviewFindingCount', 'TxtOverviewScanTime', 'TxtOverviewTimingHint',
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
    'TxtCoverageStaleSummary', 'LstStaleRulesPage', 'TxtStaleNone',
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
    'TxtSearch', 'TxtSearchHint', 'TxtShown', 'FltSource', 'FltChannel', 'FltProvider',
    'FltEventId', 'FltCorrelation', 'FltRuleStatus', 'LvFindings',
    'PnlEmpty', 'TxtEmptyTitle', 'TxtEmptyBody',
    'TxtNoSelection', 'ScrDetail', 'PillDetail', 'TxtDetailVerdict', 'TxtDetailTitle',
    'TxtDetailMeta', 'TxtPlain', 'TxtWhy', 'TxtAction',
    'PnlFalsePositives', 'LstFalsePositives', 'PnlRefs', 'LstRefs', 'LstUnsafeRefs',
    'TxtSample', 'TxtProvenance',
    'BtnCopy', 'BtnCopySummary', 'BtnSaveReport', 'BtnOpenReport',
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
    $label = Get-LVText -Key ('gui.verdict.{0}' -f $key) -Default $script:LVVerdictPalette[$key].Label
    if (Test-LVGuiHighContrast) {
        return @{
            Label  = $label
            Fill   = [System.Windows.SystemColors]::HighlightBrush
            Ink    = [System.Windows.SystemColors]::HighlightTextBrush
            Accent = [System.Windows.SystemColors]::HighlightBrush
        }
    }
    $style = $script:LVVerdictPalette[$key].Clone()
    $style.Label = $label
    return $style
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

    if ($null -eq $When) { return Get-LVText -Key 'gui.time.undated' -Default 'undated' }

    $span = (Get-Date) - $When
    if ($span.TotalSeconds -lt 0)    { return ('{0:yyyy-MM-dd}' -f $When) }
    if ($span.TotalMinutes -lt 2)    { return Get-LVText -Key 'gui.time.justNow' -Default 'just now' }
    if ($span.TotalMinutes -lt 60)   { return ((Get-LVText -Key 'gui.time.minAgo' -Default '{0} min ago') -f [int]$span.TotalMinutes) }
    if ($span.TotalHours -lt 24)     { return ((Get-LVText -Key 'gui.time.hrAgo' -Default '{0} hr ago') -f [int]$span.TotalHours) }
    if ($span.TotalDays -lt 7)       { return ((Get-LVText -Key 'gui.time.daysAgo' -Default '{0} days ago') -f [int]$span.TotalDays) }
    return ('{0:yyyy-MM-dd}' -f $When)
}

function ConvertTo-LVGuiRow {
    <#
        .SYNOPSIS
        Flatten findings into bindable rows for the list view.

        .DESCRIPTION
        WPF bindings resolve against plain properties, so everything the grid shows is
        precomputed here rather than converted per cell. Rows carry only a FindingIndex;
        the selected finding is resolved when the detail pane opens, so a large list does
        not retain a second object graph for every finding. Haystack is built once, not
        rebuilt on every keystroke.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding,
        [int]$StartIndex = 0,
        [AllowNull()][hashtable]$CorrelationIdsByKey
    )

    $index = 0
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

        $correlationIds = @()
        if ($CorrelationIdsByKey -and $f.Key -and $CorrelationIdsByKey.ContainsKey([string]$f.Key)) {
            $correlationIds = @($CorrelationIdsByKey[[string]$f.Key] | Select-Object -Unique)
        }
        $ruleStatus = 'unruled'
        if ($f.RuleId) {
            $ruleStatus = if ($f.Status) { [string]$f.Status } else { 'unknown' }
        }

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
            Source       = [string]$f.Source
            Channel      = [string]$f.Channel
            Provider     = [string]$f.Provider
            EventId      = if ($f.Source -eq 'event') { [string]$f.Id } else { '' }
            RuleId       = [string]$f.RuleId
            RuleStatus   = $ruleStatus
            CorrelationIds = $correlationIds
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
            FindingIndex   = $StartIndex + $index
        }
        $index++
    }

    return ConvertTo-LVArrayOutput -Value @($rows)
}

function Get-LVGuiFilterOption {
    <#
        .SYNOPSIS
        Build the lightweight option lists for the structured findings filters.

        .DESCRIPTION
        Options are projected from rows, not from the full finding or correlation
        graphs. Each option carries only a display label and a scalar filter value,
        so opening a dropdown never creates a second evidence graph.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Row,
        [Parameter(Mandatory)][ValidateSet('Source', 'Channel', 'Provider', 'EventId', 'Correlation', 'RuleStatus')][string]$Kind
    )

    $options = New-Object System.Collections.Generic.List[object]
    switch ($Kind) {
        'Source'      { $options.Add([pscustomobject]@{ Label=(Get-LVText -Key 'gui.filter.allSources' -Default 'All sources'); Value='' }) | Out-Null }
        'Channel'     { $options.Add([pscustomobject]@{ Label=(Get-LVText -Key 'gui.filter.allChannels' -Default 'All channels'); Value='' }) | Out-Null }
        'Provider'    { $options.Add([pscustomobject]@{ Label=(Get-LVText -Key 'gui.filter.allProviders' -Default 'All providers'); Value='' }) | Out-Null }
        'EventId'     { $options.Add([pscustomobject]@{ Label=(Get-LVText -Key 'gui.filter.allEventIds' -Default 'All event IDs'); Value='' }) | Out-Null }
        'Correlation' {
            $options.Add([pscustomobject]@{ Label=(Get-LVText -Key 'gui.filter.allCorrelations' -Default 'All correlations'); Value='' }) | Out-Null
            $options.Add([pscustomobject]@{ Label=(Get-LVText -Key 'gui.filter.correlated' -Default 'Correlated'); Value='__correlated__' }) | Out-Null
            $options.Add([pscustomobject]@{ Label=(Get-LVText -Key 'gui.filter.notCorrelated' -Default 'Not correlated'); Value='__uncorrelated__' }) | Out-Null
        }
        'RuleStatus' { $options.Add([pscustomobject]@{ Label=(Get-LVText -Key 'gui.filter.allRuleStates' -Default 'All rule states'); Value='' }) | Out-Null }
    }

    $values = New-Object System.Collections.Generic.List[string]
    foreach ($rowItem in $Row) {
        if ($Kind -eq 'Correlation') {
            foreach ($id in @($rowItem.CorrelationIds)) {
                if ($id -and -not $values.Contains([string]$id)) { $values.Add([string]$id) | Out-Null }
            }
            continue
        }
        $value = [string]$rowItem.$Kind
        if ($Kind -eq 'RuleStatus' -and -not $value) { $value = 'unruled' }
        if ($value -and -not $values.Contains($value)) { $values.Add($value) | Out-Null }
    }
    foreach ($value in @($values.ToArray() | Sort-Object)) {
        $options.Add([pscustomobject]@{ Label=$value; Value=$value }) | Out-Null
    }
    return ConvertTo-LVArrayOutput -Value @($options.ToArray())
}

function Test-LVGuiFindingVisible {
    <#
        .SYNOPSIS
        Pure predicate for the findings collection view.

        .DESCRIPTION
        Search is a literal substring, not a PowerShell wildcard. Event messages often
        contain brackets and question marks; treating those as wildcard syntax makes a
        search appear to match text the user did not type.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Row,
        [Parameter(Mandatory)][hashtable]$EnabledVerdict,
        [AllowEmptyString()][AllowNull()][string]$Search,
        [AllowNull()][hashtable]$StructuredFilter = @{}
    )

    $verdict = [string]$Row.Verdict
    if (-not $EnabledVerdict.ContainsKey($verdict) -or -not [bool]$EnabledVerdict[$verdict]) {
        return $false
    }

    foreach ($filterName in @('Source', 'Channel', 'Provider', 'EventId', 'RuleStatus', 'Correlation')) {
        if (-not $StructuredFilter.ContainsKey($filterName)) { continue }
        $selected = [string]$StructuredFilter[$filterName]
        if (-not $selected) { continue }
        if ($filterName -eq 'Correlation') {
            $correlations = @($Row.CorrelationIds)
            if ($selected -eq '__correlated__' -and $correlations.Count -eq 0) { return $false }
            if ($selected -eq '__uncorrelated__' -and $correlations.Count -gt 0) { return $false }
            if ($selected -notin @('__correlated__', '__uncorrelated__') -and $correlations -notcontains $selected) { return $false }
            continue
        }
        $rowValue = [string]$Row.$filterName
        if ($rowValue -ine $selected) { return $false }
    }

    $needle = [string]$Search
    if (-not $needle) { return $true }
    return ([string]$Row.Haystack).IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Get-LVGuiVerdictCount {
    <#
        .SYNOPSIS
        Count findings into the six display categories.

        .DESCRIPTION
        An unrecognized verdict value is counted as unknown rather than disappearing
        from the overview. This function knows no WPF types and is directly testable.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding)

    $count = @{}
    foreach ($verdict in $script:LVVerdictDisplayOrder) { $count[$verdict] = 0 }
    foreach ($item in @($Finding)) {
        $key = [string]$item.Verdict
        if (-not $count.ContainsKey($key)) { $key = 'unknown' }
        $count[$key]++
    }
    return $count
}

function ConvertTo-LVGuiClipboardText {
    <#
        Build the detail-pane clipboard payload without touching WPF or the system
        clipboard. Redaction is applied to the complete payload, including rule and
        reference text, so this helper is safe to exercise in a headless test.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Finding,
        [switch]$Redact,
        [AllowNull()][string]$MachineName = $env:COMPUTERNAME,
        [AllowNull()][string]$UserName = $env:USERNAME
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('[{0}] {1}' -f ([string]$Finding.Verdict).ToUpperInvariant(), $Finding.Title))
    $lines.Add(('Signature : {0}' -f $Finding.Key))
    $lines.Add(('Seen      : {0} time(s), {1}/day, last {2}' -f $Finding.Count, $Finding.PerDay, (Format-LVGuiWhen -When $Finding.LastSeen)))
    if ($Finding.RuleId) { $lines.Add(('Rule      : {0}' -f $Finding.RuleId)) }
    $lines.Add('')
    $lines.Add(('Plain English : {0}' -f $Finding.Plain))
    $lines.Add(('Why           : {0}' -f $Finding.Why))
    $lines.Add(('What to do    : {0}' -f $Finding.Action))
    foreach ($reference in @($Finding.References | Where-Object { $_ })) {
        $lines.Add(('Source        : {0}' -f $reference))
    }
    $lines.Add('')
    $lines.Add('Raw evidence:')
    $lines.Add([string]$Finding.SampleMessage)

    $text = $lines -join [Environment]::NewLine
    if ($Redact) {
        $text = ConvertTo-LVRedactedText -Text $text -MachineName $MachineName -UserName $UserName
    }
    return [pscustomobject][ordered]@{
        Text = $text
        Redacted = [bool]$Redact
        Status = if ($Redact) {
            'Finding copied to the clipboard with identifiers redacted.'
        } else {
            'Finding copied to the clipboard with unredacted evidence.'
        }
    }
}

function ConvertTo-LVGuiDetail {
    <#
        .SYNOPSIS
        Project one finding into the text and collections the detail pane displays.

        .DESCRIPTION
        Attribution, reference merging, sample fallback, timestamp wording, and the
        unknown-rule explanation are presentation decisions, not event-handler work.
        The returned object contains no WPF controls and can be tested headlessly.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Finding)

    $style = Get-LVVerdictStyle -Verdict $Finding.Verdict
    $meta = New-Object System.Collections.Generic.List[string]
    $meta.Add(('{0} occurrence(s)' -f $Finding.Count))
    $meta.Add(('{0}/day' -f $Finding.PerDay))
    if ($Finding.Source -eq 'event') {
        $meta.Add(('{0} event {1}' -f $Finding.Provider, $Finding.Id))
        $meta.Add(('{0} channel' -f $Finding.Channel))
    } else {
        $meta.Add(('{0} log' -f $Finding.Channel))
    }
    $meta.Add(('last seen {0}' -f (Format-LVGuiWhen -When $Finding.LastSeen)))
    if ($Finding.UndatedCount -gt 0) {
        $meta.Add(('{0} line(s) carried no timestamp' -f $Finding.UndatedCount))
    }
    foreach ($context in @(
        @{ Name='result'; Value=$Finding.ResultCode },
        @{ Name='extend'; Value=$Finding.ExtendCode },
        @{ Name='phase'; Value=$Finding.Phase },
        @{ Name='operation'; Value=$Finding.Operation },
        @{ Name='provider locale'; Value=$Finding.ProviderLocale }
    )) {
        if ($context.Value) { $meta.Add(('{0} {1}' -f $context.Name, $context.Value)) }
    }

    $falsePositive = @($Finding.FalsePositives | Where-Object { $_ })
    $reference = @(@(@($Finding.References) + @($Finding.Sources | ForEach-Object { $_.uri })) |
        Where-Object { $_ } | Select-Object -Unique)
    $sample = @($Finding.Samples | Where-Object { $_ })
    if ($sample.Count -eq 0) { $sample = @([string]$Finding.SampleMessage) }
    if ($Finding.FallbackMessage -and $sample -notcontains [string]$Finding.FallbackMessage) {
        $sample += [string]$Finding.FallbackMessage
    }

    if ($Finding.RuleId) {
        $provenancePart = New-Object System.Collections.Generic.List[string]
        $provenancePart.Add(('Rule {0}' -f $Finding.RuleId))
        if ($Finding.Status)     { $provenancePart.Add([string]$Finding.Status) }
        if ($Finding.Confidence) { $provenancePart.Add(('{0} confidence' -f $Finding.Confidence)) }
        if ($Finding.Verified)   { $provenancePart.Add(('last verified {0}' -f $Finding.Verified)) }
        $provenance = ($provenancePart -join ' - ') + '.'

        $credit = New-Object System.Collections.Generic.List[string]
        foreach ($source in @($Finding.Sources)) {
            $part = @($source.author, $source.licence) | Where-Object { $_ }
            if ($part.Count -eq 0) { continue }
            $line = $part -join ', '
            if ($source.modified) { $line += ', adapted' }
            if (-not $credit.Contains($line)) { $credit.Add($line) }
        }
        if ($credit.Count -gt 0) { $provenance += ' Derived from ' + ($credit -join '; ') + '.' }
    } else {
        $provenance = 'No rule in the verdict database covers this signature. LogVerdict reports it as unrecognized rather than guessing at a cause.'
    }

    return [pscustomobject]@{
        VerdictLabel  = $style.Label
        VerdictFill   = $style.Fill
        VerdictInk    = $style.Ink
        Title         = [string]$Finding.Title
        Meta          = $meta -join '  |  '
        Plain         = [string]$Finding.Plain
        Why           = [string]$Finding.Why
        Action        = [string]$Finding.Action
        FalsePositive = [string[]]$falsePositive
        Reference     = [string[]]$reference
        SampleText    = (@($sample | Select-Object -Unique) -join ([Environment]::NewLine * 2))
        Provenance    = $provenance
    }
}

function Get-LVGuiReferenceBucket {
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Reference)

    $allowed = New-Object System.Collections.Generic.List[string]
    $blocked = New-Object System.Collections.Generic.List[string]
    foreach ($value in @($Reference)) {
        if ($null -eq $value) { continue }
        $text = [string]$value
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        if (Test-LVAllowedUri -Uri $text) {
            if (-not $allowed.Contains($text)) { $allowed.Add($text) }
        } else {
            $blocked.Add(('Blocked as text (only http/https links are allowed): {0}' -f $text))
        }
    }

    return [pscustomobject]@{
        Allowed = [string[]]$allowed.ToArray()
        Blocked = [string[]]$blocked.ToArray()
    }
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
        if ($f.PSObject.Properties['RuleStale']) {
            if ([bool]$f.RuleStale) { $stale++ }
            continue
        }
        if ($f.PSObject.Properties['RuleFreshness'] -and $f.RuleFreshness) {
            if ([bool]$f.RuleFreshness.IsStale) { $stale++ }
            continue
        }
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
param($Mode, $Payload, $DataDir, $Version, $VerdictsJson, $LocalizationJson, $Sink, $ScanArgs)

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
    $script:LVEmbeddedLocalizationJson = $LocalizationJson

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
        LocalizationJson = $script:LVEmbeddedLocalizationJson
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
