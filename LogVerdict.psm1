# LogVerdict module loader.
# Dot-sources Private/ then Public/, exports only the Public function names.

$ErrorActionPreference = 'Stop'

$script:LVModuleRoot = $PSScriptRoot
$versionPath = Join-Path $PSScriptRoot 'VERSION'
if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) {
    throw ("LogVerdict version source not found at '{0}'." -f $versionPath)
}
$script:LVVersion = (Get-Content -LiteralPath $versionPath -Raw -Encoding UTF8).Trim()
if ($script:LVVersion -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$') {
    throw ("LogVerdict version source contains invalid SemVer '{0}'." -f $script:LVVersion)
}
$script:LVDataDir    = Join-Path $PSScriptRoot 'Data'

foreach ($scope in @('Private', 'Public')) {
    $dir = Join-Path $PSScriptRoot $scope
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    Get-ChildItem -LiteralPath $dir -Filter '*.ps1' | Sort-Object Name | ForEach-Object {
        try {
            . $_.FullName
        } catch {
            throw ("LogVerdict: failed to load {0}: {1}" -f $_.FullName, $_.Exception.Message)
        }
    }
}

Export-ModuleMember -Function @(
    'Compare-LogVerdictScan',
    'Invoke-LogVerdictScan',
    'Get-LogVerdictDatabase',
    'Get-LogVerdictSuppression',
    'Get-LogVerdictAdvisory',
    'Get-LogVerdictAdvisoryStatus',
    'Get-LogVerdictErrorCatalog',
    'Get-LogVerdictProvider',
    'Get-LogVerdictIntuneDigest',
    'Test-LogVerdictProvider',
    'Invoke-LogVerdictProvider',
    'New-LogVerdictCaseProfile',
    'Test-LogVerdictCaseProfile',
    'Export-LogVerdictHandoff',
    'Test-LogVerdictAdvisoryDatabase',
    'Update-LogVerdictDatabase',
    'Update-LogVerdictAdvisoryDatabase',
    'Test-LogVerdictDatabase',
    'Export-LogVerdictReport',
    'Export-LogVerdictStandard',
    'Watch-LogVerdict',
    'Show-LogVerdictReport',
    'Show-LogVerdictGui'
)
