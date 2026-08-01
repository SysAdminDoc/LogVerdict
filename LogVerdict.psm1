# LogVerdict module loader.
# Dot-sources Private/ then Public/, exports only the Public function names.

$ErrorActionPreference = 'Stop'

$script:LVModuleRoot = $PSScriptRoot
$script:LVVersion    = '0.5.0'
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
    'Invoke-LogVerdictScan',
    'Get-LogVerdictDatabase',
    'Test-LogVerdictDatabase',
    'Export-LogVerdictReport',
    'Show-LogVerdictReport',
    'Show-LogVerdictGui'
)
