function Resolve-LVGuiScreenshotPath {
    [CmdletBinding()]
    param([string]$ScreenshotPath, [string]$ScreenshotDirectory)

    if ($ScreenshotPath) {
        if (-not $ScreenshotDirectory) {
            throw 'ScreenshotPath requires ScreenshotDirectory so capture cannot write outside the caller-owned output directory.'
        }
        $screenshotRoot = [IO.Path]::GetFullPath($ScreenshotDirectory).TrimEnd('\')
        if (-not (Test-Path -LiteralPath $screenshotRoot -PathType Container)) {
            throw ("ScreenshotDirectory does not exist: {0}" -f $screenshotRoot)
        }
        $documentationScreenshotPath = [IO.Path]::GetFullPath($ScreenshotPath)
        $screenshotPrefix = $screenshotRoot + [IO.Path]::DirectorySeparatorChar
        if (-not $documentationScreenshotPath.StartsWith($screenshotPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw ("ScreenshotPath must remain inside ScreenshotDirectory: {0}" -f $screenshotRoot)
        }
        Write-LVLog -Level info -Message ("Explicit GUI screenshot capture requested in {0}" -f $screenshotRoot)
        return $documentationScreenshotPath
    }
    if ($ScreenshotDirectory) { throw 'ScreenshotDirectory requires ScreenshotPath.' }
    return $null
}

function New-LVGuiSession {
    [CmdletBinding()]
    param(
        [int]$DaysBack,
        [bool]$DaysBackExplicit,
        [AllowNull()][string]$DocumentationScreenshotPath
    )

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml
    $settingsStatus = $null
    $savedSettings = Get-LVGuiSetting -Status ([ref]$settingsStatus)
    $initialDays = $DaysBack
    if (-not $DaysBackExplicit -and $savedSettings) {
        $initialDays = $savedSettings.DaysBack
    }
    $initialAllChannels = $(if ($savedSettings) { $savedSettings.AllChannels } else { $false })
    $initialDiagnosticChannels = $(if ($savedSettings) { $savedSettings.DiagnosticChannels } else { $false })
    $initialSkipText = $(if ($savedSettings) { $savedSettings.SkipTextLogs } else { $false })
    $initialSkipReliability = $(if ($savedSettings) { $savedSettings.SkipReliability } else { $false })
    $initialIncludeBenign = $(if ($savedSettings) { $savedSettings.IncludeBenign } else { $false })
    $initialIncludeLowConfidence = $(if ($savedSettings) { $savedSettings.IncludeLowConfidence } else { $false })
    $initialNamedChannels = $(if ($savedSettings) { [string]$savedSettings.NamedChannels } else { '' })
    $initialDatabasePath = $(if ($savedSettings) { [string]$savedSettings.DatabasePath } else { '' })
    $initialSuppressionPath = $(if ($savedSettings) { [string]$savedSettings.SuppressionPath } else { '' })
    $initialOutputDirectory = $(if ($savedSettings) { [string]$savedSettings.OutputDirectory } else { '' })
    $initialRedact = $(if ($savedSettings) { $savedSettings.Redact } else { $false })
    $initialIncludeEvidence = $(if ($savedSettings) { $savedSettings.IncludeEvidence } else { $false })

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
    if ($settingsStatus -and $settingsStatus.State -notin @('loaded', 'missing')) {
        $ui.TxtSettingsStatus.Text = $settingsStatus.Reason
        $ui.TxtSettingsStatus.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Yellow')
    }

    $themeSnapshot = Get-LVGuiThemeSnapshot -Window $window
    $null = Sync-LVGuiTheme -Window $window -Snapshot $themeSnapshot

    # All mutable state lives on one object. Assigning to a plain variable inside an
    # event handler would create a handler-local copy and silently lose the write;
    # mutating a hashtable's keys does not have that problem.
    $activityMaxLines = $script:LVMaxGuiActivityLines
    $activityMaxCharacters = 524288
    $state = @{
        Result     = $null
        FindingStore = @()
        Rows       = $null
        View       = $null
        Job        = $null
        Timer      = $null
        Sink       = $null
        SmokeHoldUntil = $null
        ScanStartedAt = $null
        Search     = ''
        ReportDir  = $null
        HtmlPath   = $null
        SortKey    = $null
        SortAsc    = $false
        Chips      = @{}
        StructuredFilters = @{
            Source = ''; Channel = ''; Provider = ''; EventId = ''
            Correlation = ''; RuleStatus = ''
        }
        Scanning   = $false
        CurrentPage = 'Overview'
        ActivityLines = (New-Object System.Collections.Generic.List[string])
        ActivityCharacters = 0
        ActivityDropped = 0
    }
    foreach ($v in $script:LVVerdictDisplayOrder) { $state.Chips[$v] = $true }

    $structuredFilterControl = @{
        Source = $ui.FltSource
        Channel = $ui.FltChannel
        Provider = $ui.FltProvider
        EventId = $ui.FltEventId
        Correlation = $ui.FltCorrelation
        RuleStatus = $ui.FltRuleStatus
    }

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

    return [pscustomobject][ordered]@{
        Window = $window
        Ui = $ui
        State = $state
        ThemeSnapshot = $themeSnapshot
        ActivityMaxLines = $activityMaxLines
        ActivityMaxCharacters = $activityMaxCharacters
        StructuredFilterControl = $structuredFilterControl
        ChipControl = $chipControl
        PageControl = $pageControl
        NavControl = $navControl
        DocumentationScreenshotPath = $DocumentationScreenshotPath
        SettingsStatus = $settingsStatus
        SystemThemeChanged = $null
        Actions = [ordered]@{}
        InitialDays = $initialDays
        InitialAllChannels = $initialAllChannels
        InitialDiagnosticChannels = $initialDiagnosticChannels
        InitialSkipText = $initialSkipText
        InitialSkipReliability = $initialSkipReliability
        InitialIncludeBenign = $initialIncludeBenign
        InitialIncludeLowConfidence = $initialIncludeLowConfidence
        InitialNamedChannels = $initialNamedChannels
        InitialDatabasePath = $initialDatabasePath
        InitialSuppressionPath = $initialSuppressionPath
        InitialOutputDirectory = $initialOutputDirectory
        InitialRedact = $initialRedact
        InitialIncludeEvidence = $initialIncludeEvidence
    }
}
