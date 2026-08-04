#requires -Version 5.1

<#!
.SYNOPSIS
Run the PowerShell-version-independent release integrity checks.

.DESCRIPTION
The full release gate validates JSON Schema documents with PowerShell's Test-Json
on the Core 7.6 leg. This entry point runs the remaining version, provenance,
database, catalog, localization, and package checks on both supported runtimes.
#>
[CmdletBinding()]
param(
    [string]$ManifestDirectory,
    [string]$AssetDirectory,
    [string]$SupplyChainDirectory,
    [string]$AdvisoryPath,
    [switch]$ReleaseValidation
)

$ErrorActionPreference = 'Stop'
$releaseGate = Join-Path $PSScriptRoot 'Test-LogVerdictRelease.ps1'
$arguments = @{}
foreach ($name in @('ManifestDirectory', 'AssetDirectory', 'SupplyChainDirectory', 'ModuleZipPath', 'AdvisoryPath', 'ReleaseValidation', 'RequireModuleZip')) {
    if ($PSBoundParameters.ContainsKey($name)) { $arguments[$name] = $PSBoundParameters[$name] }
}
$arguments.SkipSchemaValidation = $true
& $releaseGate @arguments
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
