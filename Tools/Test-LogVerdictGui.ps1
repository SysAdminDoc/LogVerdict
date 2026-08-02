#requires -Version 5.1

<#
.SYNOPSIS
Run the LogVerdict GUI smoke tests in a real STA PowerShell process.

.DESCRIPTION
PowerShell 7 normally starts on an MTA thread, while WPF automation peers and
keyboard focus require STA. This runner relaunches itself with the matching
PowerShell host when needed, then executes the GUI-focused Pester tests. The
theme and scale values are process-local test inputs; they never change the
user's Windows display or accessibility settings.
#>
[CmdletBinding()]
param(
    [ValidateSet('Normal', 'HighContrast')]
    [string]$Theme = 'Normal',

    [ValidateRange(100, 200)]
    [int]$ScalePercent = 125
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent

if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $hostPath = (Get-Process -Id $PID -ErrorAction SilentlyContinue).Path
    if (-not $hostPath) {
        $hostPath = (Get-Command $(if ($PSVersionTable.PSEdition -eq 'Desktop') {
            'powershell.exe'
        } else {
            'pwsh.exe'
        }) -ErrorAction Stop).Source
    }

    $childArgs = @(
        '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass',
        '-File', $PSCommandPath,
        '-Theme', $Theme,
        '-ScalePercent', $ScalePercent
    )
    $child = Start-Process -FilePath $hostPath -ArgumentList $childArgs -Wait -PassThru
    exit $child.ExitCode
}

$env:LOGVERDICT_TEST_HIGH_CONTRAST = $(if ($Theme -eq 'HighContrast') { '1' } else { '0' })
$env:LOGVERDICT_TEST_DPI_SCALE = ([double]$ScalePercent / 100).ToString(
    '0.##', [Globalization.CultureInfo]::InvariantCulture)

Import-Module Pester -RequiredVersion 5.9.0 -Force
$testPath = Join-Path $repoRoot 'Tests\LogVerdict.Tests.ps1'
$result = Invoke-Pester -Path $testPath -FullNameFilter 'GUI*' -Output Normal -PassThru
if ($result.FailedCount -gt 0) {
    exit 1
}

Write-Output ('GUI {0} theme and {1}% DPI smoke checks passed in STA.' -f $Theme, $ScalePercent)
