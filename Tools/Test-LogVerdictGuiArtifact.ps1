#requires -Version 5.1

<#!
.SYNOPSIS
Launch the packaged GUI and verify its real window through Windows UI Automation.

.DESCRIPTION
This is a launch-level smoke test for LogVerdict-GUI.exe. It starts one fresh process,
checks placement and the four navigation pages, drives the invalid-database, empty,
and cancellation states, and records only bounds and UI contract evidence. The test
uses a bounded GUI-only hold when cancellation needs to be observed; it never changes
the system theme, display mode, or the user's existing processes.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$GuiPath,
    [string]$EvidencePath = (Join-Path ([IO.Path]::GetTempPath()) ('LogVerdict-gui-smoke-{0}.json' -f $PID)),
    [string]$ScreenshotPath,
    [string]$ScreenshotMetadataPath,
    [ValidateSet('Normal', 'HighContrast')][string]$Theme = 'Normal',
    [ValidateRange(15, 180)][int]$TimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
$resolvedGui = (Resolve-Path -LiteralPath $GuiPath -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $resolvedGui -PathType Leaf)) { throw "GUI artifact not found: $GuiPath" }
if ($ScreenshotMetadataPath -and -not $ScreenshotPath) {
    throw 'ScreenshotMetadataPath requires ScreenshotPath.'
}

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms
if (-not ('LogVerdict.GuiSmoke.Native' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
namespace LogVerdict.GuiSmoke {
    public struct Rect { public int Left; public int Top; public int Right; public int Bottom; }
    public static class Native {
        [DllImport("user32.dll", SetLastError=true)]
        public static extern bool GetWindowRect(IntPtr hWnd, out Rect rect);
    }
}
'@
}

$evidence = [ordered]@{
    schemaVersion = 1
    tool = 'LogVerdict'
    artifact = $resolvedGui
    theme = $Theme
    startedAt = (Get-Date).ToUniversalTime().ToString('o')
    processId = $null
    placement = $null
    checks = New-Object System.Collections.Generic.List[object]
    passed = $false
}
$process = $null
$oldHighContrast = $env:LOGVERDICT_TEST_HIGH_CONTRAST
$oldHold = $env:LOGVERDICT_GUI_SMOKE_HOLD_MS
$oldScreenshotPath = $env:LOGVERDICT_GUI_SCREENSHOT_PATH

function Add-SmokeCheck {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][string]$Details
    )
    $evidence.checks.Add([pscustomobject][ordered]@{ id = $Id; passed = $Passed; details = $Details }) | Out-Null
    if (-not $Passed) { throw ("GUI smoke check failed: {0} - {1}" -f $Id, $Details) }
}

function Find-SmokeElement {
    param(
        [Parameter(Mandatory)]$Root,
        [Parameter(Mandatory)][string]$Name,
        [System.Windows.Automation.ControlType]$ControlType
    )

    $nameCondition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::NameProperty, $Name)
    $condition = $nameCondition
    if ($ControlType) {
        $typeCondition = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty, $ControlType)
        $condition = New-Object System.Windows.Automation.AndCondition($nameCondition, $typeCondition)
    }
    $all = @($Root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition))
    return @($all | Where-Object { -not $_.Current.IsOffscreen -and $_.Current.IsEnabled } | Select-Object -First 1)
}

function Wait-SmokeElement {
    param(
        [Parameter(Mandatory)][scriptblock]$Getter,
        [Parameter(Mandatory)][string]$Description,
        [int]$Seconds = $TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $item = & $Getter
        if ($item) { return $item }
        Start-Sleep -Milliseconds 150
    } while ((Get-Date) -lt $deadline)
    throw "Timed out waiting for $Description."
}

function Invoke-SmokeButton {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = 'Root is captured by the UI Automation getter scriptblock.')]
    param([Parameter(Mandatory)]$Root, [Parameter(Mandatory)][string]$Name)
    $button = Wait-SmokeElement -Description "button '$Name'" -Getter {
        Find-SmokeElement -Root $Root -Name $Name -ControlType ([System.Windows.Automation.ControlType]::Button)
    }
    try {
        $invoke = $button.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
        $invoke.Invoke()
    } catch {
        $toggle = $button.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
        $toggle.Toggle()
    }
    return $button
}

function Set-SmokeText {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = 'Root is captured by the UI Automation getter scriptblock.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'This changes only the test process UI through UI Automation.')]
    param([Parameter(Mandatory)]$Root, [Parameter(Mandatory)][string]$Name, [AllowEmptyString()][string]$Value)
    $box = Wait-SmokeElement -Description "text box '$Name'" -Getter {
        Find-SmokeElement -Root $Root -Name $Name -ControlType ([System.Windows.Automation.ControlType]::Edit)
    }
    $pattern = $box.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    $pattern.SetValue($Value)
}

function Set-SmokeToggle {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = 'Root is captured by the UI Automation getter scriptblock.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'This changes only the test process UI through UI Automation.')]
    param([Parameter(Mandatory)]$Root, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][bool]$On)
    $box = Wait-SmokeElement -Description "toggle '$Name'" -Getter {
        Find-SmokeElement -Root $Root -Name $Name -ControlType ([System.Windows.Automation.ControlType]::CheckBox)
    }
    $pattern = $box.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
    $current = $pattern.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::On
    if ($current -ne $On) { $pattern.Toggle() }
}

function Find-SmokeText {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = 'Root is captured by the UI Automation query scriptblock.')]
    param([Parameter(Mandatory)]$Root, [Parameter(Mandatory)][string]$Text)
    $all = @($Root.FindAll([System.Windows.Automation.TreeScope]::Descendants,
        [System.Windows.Automation.Condition]::TrueCondition))
    return @($all | Where-Object { $_.Current.Name -like ('*{0}*' -f $Text) -and -not $_.Current.IsOffscreen } | Select-Object -First 1)
}

function Save-SmokeScreenshot {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'The screenshot is an explicitly requested test artifact.')]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$MetadataPath
    )

    Add-Type -AssemblyName System.Drawing
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "WPF did not generate the requested GUI screenshot: $Path"
    }
    $image = [System.Drawing.Image]::FromFile($Path)
    try {
        $width = $image.Width
        $height = $image.Height
    } finally {
        $image.Dispose()
    }

    if ($MetadataPath) {
        $metadataParent = Split-Path -Parent $MetadataPath
        if ($metadataParent -and -not (Test-Path -LiteralPath $metadataParent)) {
            New-Item -ItemType Directory -Path $metadataParent -Force | Out-Null
        }
        $version = (& (Join-Path $PSScriptRoot 'Get-LogVerdictVersion.ps1')).Trim()
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $hash = ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '').ToLowerInvariant()
        } finally {
            $sha.Dispose()
        }
        [ordered]@{
            schemaVersion = 1
            artifact = [IO.Path]::GetFileName($resolvedGui)
            artifactVersion = $version
            theme = $Theme
            screenshot = [IO.Path]::GetFileName($Path)
            screenshotSha256 = $hash
            width = $width
            height = $height
            generatedAt = (Get-Date).ToUniversalTime().ToString('o')
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $MetadataPath -Encoding UTF8
    }
}

try {
    if ($Theme -eq 'HighContrast') { $env:LOGVERDICT_TEST_HIGH_CONTRAST = '1' }
    else { $env:LOGVERDICT_TEST_HIGH_CONTRAST = '0' }
    $env:LOGVERDICT_GUI_SMOKE_HOLD_MS = '5000'
    if ($ScreenshotPath) { $env:LOGVERDICT_GUI_SCREENSHOT_PATH = [IO.Path]::GetFullPath($ScreenshotPath) }

    $process = Start-Process -FilePath $resolvedGui -ArgumentList @('-DaysBack', '1') -PassThru
    $evidence.processId = $process.Id
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $handle = [IntPtr]::Zero
    while ((Get-Date) -lt $deadline) {
        $process.Refresh()
        $handle = $process.MainWindowHandle
        if ($handle -ne [IntPtr]::Zero) { break }
        if ($process.HasExited) { throw "GUI process exited before creating a window (exit $($process.ExitCode))." }
        Start-Sleep -Milliseconds 200
    }
    if ($handle -eq [IntPtr]::Zero) { throw 'Timed out waiting for the packaged GUI window.' }
    $rootElement = [System.Windows.Automation.AutomationElement]::FromHandle($handle)
    if ($null -eq $rootElement) { throw 'Windows UI Automation could not attach to the packaged GUI window.' }

    $nativeRect = New-Object LogVerdict.GuiSmoke.Rect
    if (-not [LogVerdict.GuiSmoke.Native]::GetWindowRect($handle, [ref]$nativeRect)) { throw 'GetWindowRect failed.' }
    $screen = [System.Windows.Forms.Screen]::FromHandle($handle)
    $bounds = [pscustomobject][ordered]@{
        left = $nativeRect.Left; top = $nativeRect.Top
        right = $nativeRect.Right; bottom = $nativeRect.Bottom
        width = $nativeRect.Right - $nativeRect.Left; height = $nativeRect.Bottom - $nativeRect.Top
    }
    $work = $screen.WorkingArea
    $evidence.placement = [pscustomobject][ordered]@{
        screen = $screen.DeviceName
        screenBounds = [pscustomobject][ordered]@{ left=$screen.Bounds.Left; top=$screen.Bounds.Top; right=$screen.Bounds.Right; bottom=$screen.Bounds.Bottom }
        workingArea = [pscustomobject][ordered]@{ left=$work.Left; top=$work.Top; right=$work.Right; bottom=$work.Bottom }
        window = $bounds
        fullyInsideWorkingArea = ($bounds.left -ge $work.Left -and $bounds.top -ge $work.Top -and
            $bounds.right -le $work.Right -and $bounds.bottom -le $work.Bottom)
    }
    Add-SmokeCheck -Id 'window-created' -Passed $true -Details ('PID {0}, HWND {1}' -f $process.Id, $handle)
    Add-SmokeCheck -Id 'window-placement' -Passed ([bool]$evidence.placement.fullyInsideWorkingArea) `
        -Details ('{0}x{1} at ({2},{3}) on {4}' -f $bounds.width, $bounds.height, $bounds.left, $bounds.top, $screen.DeviceName)

    foreach ($page in @('Overview', 'Findings', 'Coverage', 'Activity')) {
        Invoke-SmokeButton -Root $rootElement -Name $page | Out-Null
        $target = switch ($page) {
            'Overview' { 'Look back this many days' }
            'Findings' { 'Findings, worst first' }
            'Coverage' { 'No coverage baseline' }
            'Activity' { 'Scan activity log' }
        }
        Wait-SmokeElement -Description "$page page" -Getter { Find-SmokeText -Root $rootElement -Text $target } | Out-Null
        Add-SmokeCheck -Id (('page-' + $page).ToLowerInvariant()) -Passed $true -Details ("$page page is visible through UI Automation")
    }

    Invoke-SmokeButton -Root $rootElement -Name 'Overview' | Out-Null
    Wait-SmokeElement -Description 'rendered overview for documentation screenshot' -Getter {
        Find-SmokeText -Root $rootElement -Text 'Look back this many days'
    } | Out-Null
    Wait-SmokeElement -Description 'visible settings reset control' -Getter {
        Find-SmokeElement -Root $rootElement -Name 'Reset saved settings' -ControlType ([System.Windows.Automation.ControlType]::Button)
    } | Out-Null
    Add-SmokeCheck -Id 'settings-reset' -Passed $true -Details 'The GUI exposes a keyboard-accessible saved-settings reset'
    if ($ScreenshotPath) {
        Save-SmokeScreenshot -Path $ScreenshotPath -MetadataPath $ScreenshotMetadataPath
        Add-SmokeCheck -Id 'documentation-screenshot' -Passed $true `
            -Details ('Captured the rendered normal GUI window at {0}x{1}' -f $bounds.width, $bounds.height)
    }
    Set-SmokeText -Root $rootElement -Name 'Alternate verdict database' -Value (Join-Path ([IO.Path]::GetTempPath()) 'LogVerdict-missing-smoke.json')
    Invoke-SmokeButton -Root $rootElement -Name 'Run scan' | Out-Null
    Wait-SmokeElement -Description 'invalid database error state' -Getter { Find-SmokeText -Root $rootElement -Text 'Rule database not found' } | Out-Null
    Add-SmokeCheck -Id 'error-state' -Passed $true -Details 'Invalid database is reported in the visible status state'

    Set-SmokeText -Root $rootElement -Name 'Alternate verdict database' -Value ''
    Set-SmokeText -Root $rootElement -Name 'Named event channels' -Value 'LogVerdict-Smoke-Missing'
    Set-SmokeToggle -Root $rootElement -Name 'Include setup logs' -On $false
    Set-SmokeToggle -Root $rootElement -Name 'Skip Reliability Monitor' -On $true
    Invoke-SmokeButton -Root $rootElement -Name 'Run scan' | Out-Null
    Wait-SmokeElement -Description 'empty scan completion' -Getter { Find-SmokeText -Root $rootElement -Text 'Scan complete' } | Out-Null
    Invoke-SmokeButton -Root $rootElement -Name 'Findings' | Out-Null
    Wait-SmokeElement -Description 'empty result state' -Getter { Find-SmokeText -Root $rootElement -Text 'Nothing to report' } | Out-Null
    Add-SmokeCheck -Id 'empty-state' -Passed $true -Details 'A source with no matching records reaches the visible empty state'

    foreach ($filterName in @(
        'Filter findings by source', 'Filter findings by channel',
        'Filter findings by provider', 'Filter findings by event ID',
        'Filter findings by correlation', 'Filter findings by rule status'
    )) {
        Wait-SmokeElement -Description "structured filter '$filterName'" -Getter {
            Find-SmokeElement -Root $rootElement -Name $filterName -ControlType ([System.Windows.Automation.ControlType]::ComboBox)
        } | Out-Null
        Add-SmokeCheck -Id ('filter-' + $filterName.ToLowerInvariant().Replace(' ', '-')) -Passed $true `
            -Details ("$filterName is keyboard-accessible through UI Automation")
    }

    Invoke-SmokeButton -Root $rootElement -Name 'Overview' | Out-Null
    Set-SmokeText -Root $rootElement -Name 'Named event channels' -Value 'System'
    Invoke-SmokeButton -Root $rootElement -Name 'Run scan' | Out-Null
    # The scan opens Activity automatically; the Overview page owns the visible
    # cancellation button, so return there while the worker is still running.
    Invoke-SmokeButton -Root $rootElement -Name 'Overview' | Out-Null
    Wait-SmokeElement -Description 'visible cancellation control' -Getter { Find-SmokeElement -Root $rootElement -Name 'Cancel' -ControlType ([System.Windows.Automation.ControlType]::Button) } | Out-Null
    Invoke-SmokeButton -Root $rootElement -Name 'Cancel' | Out-Null
    Wait-SmokeElement -Description 'cancelled result state' -Getter { Find-SmokeText -Root $rootElement -Text 'Scan cancelled' } | Out-Null
    Add-SmokeCheck -Id 'cancelled-state' -Passed $true -Details 'The packaged scan can be cancelled and reports that nothing changed'

    $evidence.passed = $true
} finally {
    if ($process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        $process.WaitForExit(5000)
    }
    if ($null -eq $oldHighContrast) { Remove-Item Env:LOGVERDICT_TEST_HIGH_CONTRAST -ErrorAction SilentlyContinue }
    else { $env:LOGVERDICT_TEST_HIGH_CONTRAST = $oldHighContrast }
    if ($null -eq $oldHold) { Remove-Item Env:LOGVERDICT_GUI_SMOKE_HOLD_MS -ErrorAction SilentlyContinue }
    else { $env:LOGVERDICT_GUI_SMOKE_HOLD_MS = $oldHold }
    if ($null -eq $oldScreenshotPath) { Remove-Item Env:LOGVERDICT_GUI_SCREENSHOT_PATH -ErrorAction SilentlyContinue }
    else { $env:LOGVERDICT_GUI_SCREENSHOT_PATH = $oldScreenshotPath }
    $evidence.finishedAt = (Get-Date).ToUniversalTime().ToString('o')
    $parent = Split-Path -Parent $EvidencePath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $evidence | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $EvidencePath -Encoding UTF8
}

Write-Output ('GUI artifact smoke: {0}; evidence {1}' -f $(if ($evidence.passed) { 'passed' } else { 'failed' }), $EvidencePath)
if (-not $evidence.passed) { exit 1 }
